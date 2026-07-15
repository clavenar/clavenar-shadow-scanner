//! Slack source. Auth via `SLACK_BOT_TOKEN` (`xoxb-…`). Required scopes:
//!
//! * `channels:read` (and `groups:read` for private channels the bot is in),
//! * `channels:history` (+ `groups:history`, `mpim:history`, `im:history`),
//! * `users:read` (optional — only used to attribute findings to a user).
//!
//! Threads, archived channels, and external shared channels are
//! intentionally out of scope for the MVP — covering them adds API
//! surface without much marginal lift over "did anyone paste a key into
//! a public channel."

use super::{ScanOutcome, SourceError, SourceErrorKind, USER_AGENT_VALUE};
use crate::detector::{Finding, scan_text};
use anyhow::{Context, Result, bail};
use chrono::{Duration as CDuration, Utc};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use serde::Deserialize;

/// How far back to look by default. 14 days covers "did someone paste
/// a key in the last sprint" without burning rate limit on ancient
/// noise. CLI exposes a `--days` knob to override.
pub const DEFAULT_LOOKBACK_DAYS: i64 = 14;

#[derive(Debug, Clone)]
pub struct SlackClient {
    http: reqwest::Client,
    token: String,
    base_url: String,
}

impl SlackClient {
    pub fn from_env() -> Result<Self> {
        let token = std::env::var("SLACK_BOT_TOKEN")
            .context("SLACK_BOT_TOKEN must be set for the slack source")?;
        Ok(Self {
            http: reqwest::Client::new(),
            token,
            base_url: "https://slack.com/api".into(),
        })
    }

    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    fn headers(&self) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", self.token)).expect("valid token"),
        );
        h.insert(
            reqwest::header::USER_AGENT,
            HeaderValue::from_static(USER_AGENT_VALUE),
        );
        h
    }

    /// List conversations the bot is a member of. Cursors through
    /// pages until exhausted.
    pub async fn list_conversations(&self) -> Result<Vec<Conversation>> {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let mut url = format!(
                "{}/users.conversations?limit=200&types=public_channel,private_channel",
                self.base_url
            );
            if let Some(c) = &cursor {
                url.push_str(&format!("&cursor={}", urlencoding(c)));
            }
            let resp: ListConversationsResponse = self.get_json(&url).await?;
            if !resp.ok {
                bail!(
                    "slack list_conversations: {}",
                    resp.error.unwrap_or_default()
                );
            }
            out.extend(resp.channels);
            match resp.response_metadata.and_then(|m| m.next_cursor) {
                Some(c) if !c.is_empty() => cursor = Some(c),
                _ => break,
            }
        }
        Ok(out)
    }

    /// Pull message history for `channel_id` since `since_ts` (seconds
    /// since epoch). Returns messages newest-first, as Slack does.
    pub async fn fetch_history(
        &self,
        channel_id: &str,
        since_ts: f64,
    ) -> Result<Vec<SlackMessage>> {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let mut url = format!(
                "{}/conversations.history?channel={}&oldest={}&limit=200",
                self.base_url, channel_id, since_ts
            );
            if let Some(c) = &cursor {
                url.push_str(&format!("&cursor={}", urlencoding(c)));
            }
            let resp: HistoryResponse = self.get_json(&url).await?;
            if !resp.ok {
                bail!(
                    "slack history {}: {}",
                    channel_id,
                    resp.error.unwrap_or_default()
                );
            }
            out.extend(resp.messages);
            match resp.response_metadata.and_then(|m| m.next_cursor) {
                Some(c) if !c.is_empty() => cursor = Some(c),
                _ => break,
            }
        }
        Ok(out)
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(&self, url: &str) -> Result<T> {
        let resp = self
            .http
            .get(url)
            .headers(self.headers())
            .send()
            .await
            .with_context(|| format!("GET {}", url))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!("GET {} -> {}: {}", url, status, body);
        }
        // Slack returns `{ ok: false, error: "..." }` with a 200 status,
        // so we need to deserialize first and then check the `ok` field
        // upstream. The inner type carries that boolean.
        resp.json().await.with_context(|| format!("decode {}", url))
    }
}

/// Minimal URL-encoder for Slack cursor values. Cursors are opaque
/// base64-ish strings; we only need to escape `+`, `/`, `=`, and the
/// occasional `&`.
fn urlencoding(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            other => out.push_str(&format!("%{:02X}", other)),
        }
    }
    out
}

#[derive(Debug, Clone, Deserialize)]
pub struct Conversation {
    pub id: String,
    pub name: Option<String>,
    #[serde(default)]
    pub is_archived: bool,
    #[serde(default)]
    pub is_member: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SlackMessage {
    #[serde(default)]
    pub text: String,
    pub ts: String,
    #[serde(default)]
    pub user: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ListConversationsResponse {
    ok: bool,
    #[serde(default)]
    channels: Vec<Conversation>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    response_metadata: Option<ResponseMetadata>,
}

#[derive(Debug, Deserialize)]
struct HistoryResponse {
    ok: bool,
    #[serde(default)]
    messages: Vec<SlackMessage>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    response_metadata: Option<ResponseMetadata>,
}

#[derive(Debug, Deserialize)]
struct ResponseMetadata {
    #[serde(default)]
    next_cursor: Option<String>,
}

/// Top-level driver: scan every conversation the bot is a member of,
/// looking back `lookback_days` days. Skips archived channels.
pub async fn scan_workspace(
    client: &SlackClient,
    lookback_days: i64,
) -> Result<ScanOutcome<Finding>> {
    let mut outcome = ScanOutcome::default();
    let conversations = match client.list_conversations().await {
        Ok(conversations) => conversations,
        Err(error) => {
            outcome.record_error(SourceError::new(
                SourceErrorKind::ConversationList,
                "slack://workspace",
                error.to_string(),
            ));
            return Ok(outcome);
        }
    };
    let since = (Utc::now() - CDuration::days(lookback_days)).timestamp() as f64;

    for conv in conversations {
        if conv.is_archived || !conv.is_member {
            outcome.record_skipped();
            continue;
        }
        let label = conv.name.clone().unwrap_or_else(|| conv.id.clone());
        match client.fetch_history(&conv.id, since).await {
            Ok(messages) => {
                for msg in messages {
                    if msg.text.is_empty() {
                        outcome.record_skipped();
                        continue;
                    }
                    let location = format!("slack://{}/{}", label, msg.ts);
                    outcome.record_scanned(msg.text.len());
                    outcome.findings.extend(scan_text(&msg.text, &location));
                }
                tracing::info!("scanned slack channel {}", label);
            }
            Err(error) => {
                tracing::warn!("skip slack channel {}: {}", label, error);
                outcome.record_error(SourceError::new(
                    SourceErrorKind::ChannelHistory,
                    format!("slack://{label}"),
                    error.to_string(),
                ));
            }
        }
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sources::{CoverageEvaluation, CoverageStatus};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    struct MockResponse {
        path_prefix: &'static str,
        body: &'static str,
    }

    fn mock_slack(responses: Vec<MockResponse>) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0_u8; 8192];
                let length = stream.read(&mut request).unwrap();
                let request = std::str::from_utf8(&request[..length]).unwrap();
                let request_path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap();
                assert!(request_path.starts_with(response.path_prefix));
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response.body.len(),
                    response.body
                )
                .unwrap();
            }
        });
        (format!("http://{address}"), handle)
    }

    #[test]
    fn urlencoding_preserves_unreserved() {
        assert_eq!(urlencoding("abcXYZ012-_.~"), "abcXYZ012-_.~");
    }

    #[test]
    fn urlencoding_escapes_special() {
        assert_eq!(urlencoding("a/b+c=d"), "a%2Fb%2Bc%3Dd");
    }

    #[tokio::test]
    async fn conversation_failure_is_a_typed_partial_error() {
        let client = SlackClient {
            http: reqwest::Client::new(),
            token: "synthetic-test-token".into(),
            base_url: "http://127.0.0.1:9".into(),
        };
        let outcome = scan_workspace(&client, 1).await.unwrap();
        assert!(outcome.findings.is_empty());
        assert_eq!(outcome.coverage().objects_scanned(), 0);
        assert_eq!(outcome.coverage().source_errors().len(), 1);
        assert_eq!(
            outcome.coverage().source_errors()[0].kind,
            SourceErrorKind::ConversationList
        );
        assert!(outcome.coverage().partial());
        let evaluation = CoverageEvaluation::evaluate(outcome.coverage(), 100.0);
        assert_eq!(evaluation.status, CoverageStatus::TotalFailure);
        assert!(evaluation.requires_failure());
    }

    #[tokio::test]
    async fn mixed_channel_failure_exceeds_default_partial_threshold() {
        let (base_url, server) = mock_slack(vec![
            MockResponse {
                path_prefix: "/users.conversations?",
                body: r#"{"ok":true,"channels":[{"id":"C1","name":"one","is_archived":false,"is_member":true},{"id":"C2","name":"two","is_archived":false,"is_member":true}],"response_metadata":{"next_cursor":""}}"#,
            },
            MockResponse {
                path_prefix: "/conversations.history?channel=C1&",
                body: r#"{"ok":true,"messages":[{"text":"clean","ts":"1","user":"U1"}],"response_metadata":{"next_cursor":""}}"#,
            },
            MockResponse {
                path_prefix: "/conversations.history?channel=C2&",
                body: r#"{"ok":false,"error":"synthetic_failure","messages":[]}"#,
            },
        ]);
        let client = SlackClient {
            http: reqwest::Client::new(),
            token: "synthetic-test-token".into(),
            base_url,
        };
        let outcome = scan_workspace(&client, 1).await.unwrap();
        server.join().unwrap();

        assert_eq!(outcome.coverage().objects_scanned(), 1);
        assert_eq!(outcome.coverage().bytes_scanned(), 5);
        assert_eq!(outcome.coverage().source_errors().len(), 1);
        assert_eq!(
            outcome.coverage().source_errors()[0].kind,
            SourceErrorKind::ChannelHistory
        );
        let evaluation = CoverageEvaluation::evaluate(outcome.coverage(), 10.0);
        assert_eq!(evaluation.status, CoverageStatus::ThresholdExceeded);
        assert!(evaluation.requires_failure());
    }
}
