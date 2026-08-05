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

use super::{
    MAX_FILE_BYTES, MAX_REMOTE_BODY_BYTES, MAX_SOURCE_OBJECTS, ScanOutcome, SourceError,
    SourceErrorKind, USER_AGENT_VALUE,
};
use crate::detector::{Finding, scan_text_with_status};
use anyhow::{Context, Result, anyhow, bail};
use chrono::{Duration as CDuration, Utc};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use serde::Deserialize;
use std::net::IpAddr;
use std::time::Duration;

/// How far back to look by default. 14 days covers "did someone paste
/// a key in the last sprint" without burning rate limit on ancient
/// noise. CLI exposes a `--days` knob to override.
pub const DEFAULT_LOOKBACK_DAYS: i64 = 14;
pub const MAX_LOOKBACK_DAYS: i64 = 3_650;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REMOTE_RETRIES: usize = 5;
const MAX_PAGES: usize = 1_000;
const MAX_CURSOR_BYTES: usize = 4_096;

#[derive(Clone)]
pub struct SlackClient {
    http: reqwest::Client,
    authorization: HeaderValue,
    base_url: reqwest::Url,
}

impl SlackClient {
    pub fn from_env() -> Result<Self> {
        let token = std::env::var("SLACK_BOT_TOKEN")
            .context("SLACK_BOT_TOKEN must be set for the slack source")?;
        if token.trim().is_empty() {
            bail!("SLACK_BOT_TOKEN cannot be empty");
        }
        let mut authorization = HeaderValue::from_str(&format!("Bearer {}", token.trim()))
            .context("SLACK_BOT_TOKEN is not a valid HTTP credential")?;
        authorization.set_sensitive(true);
        Ok(Self {
            http: build_http_client()?,
            authorization,
            base_url: reqwest::Url::parse("https://slack.com/api")
                .expect("static Slack API URL is valid"),
        })
    }

    pub fn with_base_url(mut self, base_url: impl AsRef<str>) -> Result<Self> {
        self.base_url = validate_base_url(base_url.as_ref(), false)?;
        Ok(self)
    }

    pub fn with_insecure_loopback_base_url(mut self, base_url: impl AsRef<str>) -> Result<Self> {
        self.base_url = validate_base_url(base_url.as_ref(), true)?;
        Ok(self)
    }

    #[cfg(test)]
    fn for_test_base_url(base_url: &str) -> Self {
        let mut authorization = HeaderValue::from_static("Bearer synthetic-test-token");
        authorization.set_sensitive(true);
        Self {
            http: build_http_client().expect("test HTTP client"),
            authorization,
            base_url: validate_base_url(base_url, true).expect("loopback test URL"),
        }
    }

    fn headers(&self) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(AUTHORIZATION, self.authorization.clone());
        h.insert(
            reqwest::header::USER_AGENT,
            HeaderValue::from_static(USER_AGENT_VALUE),
        );
        h
    }

    fn endpoint(&self, method: &str) -> Result<reqwest::Url> {
        let mut url = self.base_url.clone();
        url.set_query(None);
        url.set_fragment(None);
        url.path_segments_mut()
            .map_err(|_| anyhow!("Slack base URL cannot be a base"))?
            .pop_if_empty()
            .push(method);
        Ok(url)
    }

    /// List conversations the bot is a member of. Cursors through
    /// pages until exhausted.
    pub async fn list_conversations(&self) -> Result<Vec<Conversation>> {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let mut url = self.endpoint("users.conversations")?;
            url.query_pairs_mut()
                .append_pair("limit", "200")
                .append_pair("types", "public_channel,private_channel");
            if let Some(c) = &cursor {
                validate_cursor(c)?;
                url.query_pairs_mut().append_pair("cursor", c);
            }
            let resp: ListConversationsResponse = self.get_json(url).await?;
            if !resp.ok {
                bail!("slack list_conversations: {}", safe_slack_error(resp.error));
            }
            if out.len().saturating_add(resp.channels.len()) > MAX_SOURCE_OBJECTS {
                bail!("Slack conversation listing exceeded safety limit");
            }
            out.extend(resp.channels);
            match resp.response_metadata.and_then(|m| m.next_cursor) {
                Some(c) if !c.is_empty() => cursor = Some(c),
                _ => return Ok(out),
            }
        }
        bail!("Slack conversation pagination exceeded safety limit")
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
        for _ in 0..MAX_PAGES {
            let mut url = self.endpoint("conversations.history")?;
            url.query_pairs_mut()
                .append_pair("channel", channel_id)
                .append_pair("oldest", &since_ts.to_string())
                .append_pair("limit", "200");
            if let Some(c) = &cursor {
                validate_cursor(c)?;
                url.query_pairs_mut().append_pair("cursor", c);
            }
            let resp: HistoryResponse = self.get_json(url).await?;
            if !resp.ok {
                bail!(
                    "slack history {}: {}",
                    channel_id,
                    safe_slack_error(resp.error)
                );
            }
            if out.len().saturating_add(resp.messages.len()) > MAX_SOURCE_OBJECTS {
                bail!("Slack channel history exceeded safety limit");
            }
            out.extend(resp.messages);
            match resp.response_metadata.and_then(|m| m.next_cursor) {
                Some(c) if !c.is_empty() => cursor = Some(c),
                _ => return Ok(out),
            }
        }
        bail!("Slack history pagination exceeded safety limit")
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(&self, url: reqwest::Url) -> Result<T> {
        self.validate_request_url(&url)?;
        let request_label = request_label(&url);
        for attempt in 0..=MAX_REMOTE_RETRIES {
            let response = self
                .http
                .get(url.clone())
                .headers(self.headers())
                .send()
                .await
                .with_context(|| format!("GET {request_label}"))?;
            if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
                if attempt == MAX_REMOTE_RETRIES {
                    bail!("GET {request_label} remained rate-limited after bounded retries");
                }
                let wait = retry_after(&response);
                tokio::time::sleep(wait).await;
                continue;
            }
            let status = response.status();
            let body = read_bounded_body(response, MAX_REMOTE_BODY_BYTES).await?;
            if !status.is_success() {
                bail!(
                    "GET {} -> {} (response body omitted)",
                    request_label,
                    status
                );
            }
            return serde_json::from_slice(&body)
                .with_context(|| format!("decode {request_label}"));
        }
        unreachable!("bounded retry loop always returns or errors")
    }

    fn validate_request_url(&self, url: &reqwest::Url) -> Result<()> {
        if url.scheme() != self.base_url.scheme()
            || url.host_str() != self.base_url.host_str()
            || url.port_or_known_default() != self.base_url.port_or_known_default()
        {
            bail!("refuse Slack request outside configured API origin");
        }
        Ok(())
    }
}

fn build_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("build Slack HTTP client")
}

fn validate_base_url(value: &str, allow_insecure_loopback: bool) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(value).context("invalid Slack API base URL")?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("Slack API base URL cannot contain credentials, query, or fragment");
    }
    match url.scheme() {
        "https" => {}
        "http"
            if allow_insecure_loopback
                && url
                    .host_str()
                    .and_then(|host| host.parse::<IpAddr>().ok())
                    .is_some_and(|address| address.is_loopback()) => {}
        "http" => bail!("plaintext Slack API transport is restricted to explicit loopback use"),
        _ => bail!("Slack API base URL must use HTTPS"),
    }
    Ok(url)
}

fn request_label(url: &reqwest::Url) -> String {
    let mut label = url.clone();
    label.set_query(None);
    label.set_fragment(None);
    label.to_string()
}

async fn read_bounded_body(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        bail!("Slack response exceeded {limit}-byte safety limit");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.context("read Slack response body")? {
        if body.len().saturating_add(chunk.len()) > limit {
            bail!("Slack response exceeded {limit}-byte safety limit");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn retry_after(response: &reqwest::Response) -> Duration {
    let seconds = response
        .headers()
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(30)
        .clamp(1, 600);
    Duration::from_secs(seconds)
}

fn validate_cursor(cursor: &str) -> Result<()> {
    if cursor.len() > MAX_CURSOR_BYTES {
        bail!("Slack pagination cursor exceeded safety limit");
    }
    Ok(())
}

fn safe_slack_error(error: Option<String>) -> String {
    error
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 128
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        })
        .unwrap_or_else(|| "unclassified_api_error".to_string())
}

#[derive(Debug, Clone, Deserialize)]
pub struct Conversation {
    pub id: String,
    pub name: Option<String>,
    #[serde(default)]
    pub is_archived: bool,
    #[serde(default)]
    pub is_member: bool,
    #[serde(default)]
    pub is_ext_shared: bool,
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
    if !(1..=MAX_LOOKBACK_DAYS).contains(&lookback_days) {
        bail!("Slack --days must be between 1 and {MAX_LOOKBACK_DAYS}");
    }
    let mut outcome = ScanOutcome::default();
    outcome.record_scope("slack:member_channels;no_archived;no_external_shared;no_threads");
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
        if conv.is_archived {
            outcome.record_excluded("archived_conversation");
            continue;
        }
        if !conv.is_member {
            outcome.record_excluded("non_member_conversation");
            continue;
        }
        if conv.is_ext_shared {
            outcome.record_excluded("external_shared_conversation");
            continue;
        }
        let label = bounded_label(conv.name.as_deref().unwrap_or(&conv.id), 256);
        match client.fetch_history(&conv.id, since).await {
            Ok(messages) => {
                for msg in messages {
                    if msg.text.is_empty() {
                        outcome.record_excluded("empty_message");
                        continue;
                    }
                    if msg.text.len() as u64 > MAX_FILE_BYTES {
                        outcome.record_excluded("oversized_message");
                        continue;
                    }
                    let timestamp = bounded_label(&msg.ts, 64);
                    let location = format!("slack://{label}/{timestamp}");
                    outcome.record_scanned(msg.text.len());
                    let (mut findings, truncated) = scan_text_with_status(&msg.text, &location);
                    outcome.append_findings(&mut findings);
                    if truncated {
                        outcome.mark_truncated();
                    }
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

fn bounded_label(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes.saturating_sub('…'.len_utf8());
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &value[..end])
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
    fn base_url_policy_requires_https_or_explicit_ip_loopback() {
        assert!(validate_base_url("https://slack.example/api", false).is_ok());
        assert!(validate_base_url("http://slack.example/api", true).is_err());
        assert!(validate_base_url("http://localhost:8080", true).is_err());
        assert!(validate_base_url("http://127.0.0.1:8080", true).is_ok());
        assert!(validate_base_url("https://user:pass@slack.example", false).is_err());
    }

    #[tokio::test]
    async fn conversation_failure_is_a_typed_partial_error() {
        let client = SlackClient::for_test_base_url("http://127.0.0.1:9");
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
        let client = SlackClient::for_test_base_url(&base_url);
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

    #[tokio::test]
    async fn pagination_cursor_is_percent_encoded_by_url_builder() {
        let (base_url, server) = mock_slack(vec![
            MockResponse {
                path_prefix: "/users.conversations?",
                body: r#"{"ok":true,"channels":[],"response_metadata":{"next_cursor":"a/b+c=d&x"}}"#,
            },
            MockResponse {
                path_prefix: "/users.conversations?limit=200&types=public_channel%2Cprivate_channel&cursor=a%2Fb%2Bc%3Dd%26x",
                body: r#"{"ok":true,"channels":[],"response_metadata":{"next_cursor":""}}"#,
            },
        ]);
        let conversations = SlackClient::for_test_base_url(&base_url)
            .list_conversations()
            .await
            .unwrap();
        server.join().unwrap();
        assert!(conversations.is_empty());
    }

    #[tokio::test]
    async fn invalid_lookback_is_rejected_before_network_access() {
        let client = SlackClient::for_test_base_url("http://127.0.0.1:9");
        assert!(scan_workspace(&client, 0).await.is_err());
        assert!(
            scan_workspace(&client, MAX_LOOKBACK_DAYS + 1)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn archived_channels_are_visible_exclusions_not_partial_failures() {
        let (base_url, server) = mock_slack(vec![MockResponse {
            path_prefix: "/users.conversations?",
            body: r#"{"ok":true,"channels":[{"id":"C1","name":"old","is_archived":true,"is_member":true}],"response_metadata":{"next_cursor":""}}"#,
        }]);
        let outcome = scan_workspace(&SlackClient::for_test_base_url(&base_url), 1)
            .await
            .unwrap();
        server.join().unwrap();
        assert_eq!(outcome.coverage().objects_excluded(), 1);
        assert_eq!(
            outcome.coverage().exclusion_reasons()["archived_conversation"],
            1
        );
        assert!(!outcome.coverage().partial());
    }
}
