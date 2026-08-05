//! GitHub source. Calls the REST API directly via `reqwest` — no SDK dep.
//!
//! Auth comes from the `GITHUB_TOKEN` env var (PAT or GitHub App token).
//! Without a token we still hit the public API — useful for "scan a
//! public repo" demos — but rate-limit drops to 60 req/hour.
//!
//! Rate-limit handling: 403 with `X-RateLimit-Remaining: 0` sleeps until
//! `X-RateLimit-Reset`; 429 backs off 30s; anything else surfaces.

use super::{
    MAX_FILE_BYTES, MAX_REMOTE_BODY_BYTES, MAX_SOURCE_OBJECTS, ScanOutcome, SourceError,
    SourceErrorKind, USER_AGENT_VALUE, looks_binary,
};
use crate::detector::{Finding, scan_text_with_status};
use anyhow::{Context, Result, anyhow, bail};
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderValue, USER_AGENT};
use serde::Deserialize;
use std::net::IpAddr;
use std::time::Duration;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REMOTE_RETRIES: usize = 5;
const MAX_PAGES: usize = 1_000;

#[derive(Clone)]
pub struct GitHubClient {
    http: reqwest::Client,
    authorization: Option<HeaderValue>,
    base_url: reqwest::Url,
}

impl GitHubClient {
    pub fn from_env() -> Result<Self> {
        let authorization = std::env::var("GITHUB_TOKEN")
            .ok()
            .filter(|token| !token.trim().is_empty())
            .map(|token| {
                let mut value = HeaderValue::from_str(&format!("Bearer {}", token.trim()))
                    .context("GITHUB_TOKEN is not a valid HTTP credential")?;
                value.set_sensitive(true);
                Ok::<_, anyhow::Error>(value)
            })
            .transpose()?;
        Ok(Self {
            http: reqwest::Client::builder()
                .connect_timeout(CONNECT_TIMEOUT)
                .timeout(REQUEST_TIMEOUT)
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .context("build GitHub HTTP client")?,
            authorization,
            base_url: reqwest::Url::parse("https://api.github.com")
                .expect("static GitHub API URL is valid"),
        })
    }

    /// Override the API origin for GitHub Enterprise. Credentialed endpoints
    /// must use HTTPS and redirects are never followed.
    pub fn with_base_url(mut self, base_url: impl AsRef<str>) -> Result<Self> {
        self.base_url = validate_base_url(base_url.as_ref(), false)?;
        Ok(self)
    }

    /// Explicit local-test/development escape hatch. Plaintext transport is
    /// accepted only for an actual loopback host.
    pub fn with_insecure_loopback_base_url(mut self, base_url: impl AsRef<str>) -> Result<Self> {
        self.base_url = validate_base_url(base_url.as_ref(), true)?;
        Ok(self)
    }

    #[cfg(test)]
    fn for_test_base_url(base_url: &str) -> Self {
        Self {
            http: reqwest::Client::builder()
                .connect_timeout(CONNECT_TIMEOUT)
                .timeout(REQUEST_TIMEOUT)
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("test HTTP client"),
            authorization: None,
            base_url: validate_base_url(base_url, true).expect("loopback test URL"),
        }
    }

    fn headers(&self) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(USER_AGENT, HeaderValue::from_static(USER_AGENT_VALUE));
        h.insert(
            ACCEPT,
            HeaderValue::from_static("application/vnd.github+json"),
        );
        if let Some(value) = &self.authorization {
            h.insert(AUTHORIZATION, value.clone());
        }
        h
    }

    fn endpoint(&self, segments: &[&str]) -> Result<reqwest::Url> {
        let mut url = self.base_url.clone();
        url.set_query(None);
        url.set_fragment(None);
        url.path_segments_mut()
            .map_err(|_| anyhow!("GitHub base URL cannot be a base"))?
            .pop_if_empty()
            .extend(segments);
        Ok(url)
    }

    fn validate_request_url(&self, url: &reqwest::Url) -> Result<()> {
        if url.scheme() != self.base_url.scheme()
            || url.host_str() != self.base_url.host_str()
            || url.port_or_known_default() != self.base_url.port_or_known_default()
        {
            bail!("refuse GitHub request outside configured API origin");
        }
        Ok(())
    }

    async fn send_get(
        &self,
        url: &reqwest::Url,
        headers: HeaderMap,
        operation: &str,
    ) -> Result<reqwest::Response> {
        self.validate_request_url(url)?;
        let request_label = request_label(url);
        for attempt in 0..=MAX_REMOTE_RETRIES {
            let response = self
                .http
                .get(url.clone())
                .headers(headers.clone())
                .send()
                .await
                .with_context(|| format!("{operation} {request_label}"))?;
            let Some(wait) = rate_limit_backoff(&response) else {
                return Ok(response);
            };
            if attempt == MAX_REMOTE_RETRIES {
                bail!("{operation} {request_label} remained rate-limited after bounded retries");
            }
            tokio::time::sleep(wait).await;
        }
        unreachable!("bounded retry loop always returns or errors")
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(&self, url: reqwest::Url) -> Result<T> {
        let response = self.send_get(&url, self.headers(), "GET").await?;
        let status = response.status();
        let body = read_bounded_body(response, MAX_REMOTE_BODY_BYTES).await?;
        if !status.is_success() {
            bail!(
                "GET {} -> {} (response body omitted)",
                request_label(&url),
                status
            );
        }
        serde_json::from_slice(&body).with_context(|| format!("decode {}", request_label(&url)))
    }

    async fn get_raw(&self, url: reqwest::Url) -> Result<Vec<u8>> {
        let mut headers = self.headers();
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/vnd.github.raw"),
        );
        let response = self.send_get(&url, headers, "GET raw").await?;
        let status = response.status();
        let body = read_bounded_body(response, MAX_FILE_BYTES as usize + 1).await?;
        if !status.is_success() {
            bail!(
                "GET raw {} -> {} (response body omitted)",
                request_label(&url),
                status
            );
        }
        Ok(body)
    }

    /// List every repo under `owner` (org or user). Walks paginated
    /// `/orgs/{owner}/repos` first; if that 404s, falls back to
    /// `/users/{owner}/repos`. If both endpoints error out (e.g. a
    /// 401 on bad auth), surface the last error rather than returning
    /// an empty list — silent-empty on auth failure was masking the
    /// real cause behind a misleading "no findings" exit 0.
    pub async fn list_repos(&self, owner: &str) -> Result<Vec<RepoSummary>> {
        let mut org_url = self.endpoint(&["orgs", owner, "repos"])?;
        org_url
            .query_pairs_mut()
            .append_pair("per_page", "100")
            .append_pair("type", "all");
        if let Some(repos) = self.paginate_repos(org_url).await? {
            return Ok(repos);
        }

        let mut user_url = self.endpoint(&["users", owner, "repos"])?;
        user_url
            .query_pairs_mut()
            .append_pair("per_page", "100")
            .append_pair("type", "all");
        match self.paginate_repos(user_url).await? {
            Some(repos) => Ok(repos),
            None => bail!("GitHub owner not found: {owner}"),
        }
    }

    async fn paginate_repos(&self, mut url: reqwest::Url) -> Result<Option<Vec<RepoSummary>>> {
        let mut all = Vec::new();
        for page_index in 0..MAX_PAGES {
            let resp = self.send_get(&url, self.headers(), "GET").await?;
            let status = resp.status();
            let next = next_link(&resp, &self.base_url)?;
            let body = read_bounded_body(resp, MAX_REMOTE_BODY_BYTES).await?;
            if status == reqwest::StatusCode::NOT_FOUND && page_index == 0 {
                return Ok(None);
            }
            if !status.is_success() {
                bail!(
                    "GET {} -> {} (response body omitted)",
                    request_label(&url),
                    status
                );
            }
            let page: Vec<RepoSummary> = serde_json::from_slice(&body)
                .with_context(|| format!("decode repository page {}", request_label(&url)))?;
            if all.len().saturating_add(page.len()) > MAX_SOURCE_OBJECTS {
                bail!("GitHub repository listing exceeded safety limit");
            }
            all.extend(page);
            match next {
                Some(n) => url = n,
                None => return Ok(Some(all)),
            }
        }
        bail!("GitHub repository pagination exceeded safety limit")
    }

    /// Recursive tree listing for a repo at a given branch. Preserves GitHub's
    /// truncation signal and returns every blob path in the response.
    pub async fn list_tree(&self, owner: &str, repo: &str, branch: &str) -> Result<TreeListing> {
        let mut url = self.endpoint(&["repos", owner, repo, "git", "trees", branch])?;
        url.query_pairs_mut().append_pair("recursive", "1");
        let tree: TreeResponse = self.get_json(url).await?;
        let too_many_entries = tree.tree.len() > MAX_SOURCE_OBJECTS;
        Ok(TreeListing {
            entries: tree
                .tree
                .into_iter()
                .filter(|entry| entry.kind == "blob")
                .take(MAX_SOURCE_OBJECTS)
                .collect(),
            truncated: tree.truncated || too_many_entries,
        })
    }

    pub async fn get_repo(&self, owner: &str, repo: &str) -> Result<RepoSummary> {
        let url = self.endpoint(&["repos", owner, repo])?;
        self.get_json(url).await
    }

    pub async fn fetch_blob(
        &self,
        owner: &str,
        repo: &str,
        path: &str,
        branch: &str,
    ) -> Result<Vec<u8>> {
        if path
            .split('/')
            .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
        {
            bail!("GitHub tree returned an invalid blob path");
        }
        let mut segments = vec!["repos", owner, repo, "contents"];
        segments.extend(path.split('/'));
        let mut url = self.endpoint(&segments)?;
        url.query_pairs_mut().append_pair("ref", branch);
        self.get_raw(url).await
    }
}

fn validate_base_url(value: &str, allow_insecure_loopback: bool) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(value).context("invalid GitHub API base URL")?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("GitHub API base URL cannot contain credentials, query, or fragment");
    }
    match url.scheme() {
        "https" => {}
        "http"
            if allow_insecure_loopback
                && url
                    .host_str()
                    .and_then(|host| host.parse::<IpAddr>().ok())
                    .is_some_and(|address| address.is_loopback()) => {}
        "http" => bail!("plaintext GitHub API transport is restricted to explicit loopback use"),
        _ => bail!("GitHub API base URL must use HTTPS"),
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
        bail!("GitHub response exceeded {limit}-byte safety limit");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("read GitHub response body")?
    {
        if body.len().saturating_add(chunk.len()) > limit {
            bail!("GitHub response exceeded {limit}-byte safety limit");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[derive(Debug, Clone, Deserialize)]
pub struct RepoSummary {
    pub name: String,
    pub full_name: String,
    pub default_branch: String,
    #[serde(default)]
    pub fork: bool,
    #[serde(default)]
    pub archived: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TreeResponse {
    pub tree: Vec<TreeEntry>,
    #[serde(default)]
    pub truncated: bool,
}

#[derive(Debug, Clone)]
pub struct TreeListing {
    pub entries: Vec<TreeEntry>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TreeEntry {
    pub path: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub size: Option<u64>,
}

/// Inspect a response for rate-limit / retry signals. Returns `Some(d)`
/// if the caller should sleep for `d` and retry; `None` to proceed.
fn rate_limit_backoff(resp: &reqwest::Response) -> Option<Duration> {
    let status = resp.status();
    if status == reqwest::StatusCode::FORBIDDEN
        && resp
            .headers()
            .get("x-ratelimit-remaining")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u32>().ok())
            == Some(0)
    {
        let reset = resp
            .headers()
            .get("x-ratelimit-reset")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);
        let now = chrono::Utc::now().timestamp();
        let wait = (reset - now).clamp(1, 600);
        tracing::warn!("github rate-limited; sleeping {}s", wait);
        return Some(Duration::from_secs(wait as u64));
    }
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        let wait = resp
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(30)
            .clamp(1, 600);
        tracing::warn!("github 429; backing off {}s", wait);
        return Some(Duration::from_secs(wait));
    }
    None
}

/// Parse the next-page URL out of a paginated response's `Link` header.
fn next_link(resp: &reqwest::Response, base_url: &reqwest::Url) -> Result<Option<reqwest::Url>> {
    let Some(value) = resp.headers().get("link") else {
        return Ok(None);
    };
    let link = value.to_str().context("invalid GitHub Link header")?;
    // Header looks like: <url1>; rel="next", <url2>; rel="last"
    for part in link.split(',') {
        let part = part.trim();
        if part.contains(r#"rel="next""#)
            && let Some(start) = part.find('<')
            && let Some(end) = part.find('>')
        {
            let url = reqwest::Url::parse(&part[start + 1..end])
                .context("invalid GitHub next-page URL")?;
            if url.scheme() != base_url.scheme()
                || url.host_str() != base_url.host_str()
                || url.port_or_known_default() != base_url.port_or_known_default()
            {
                bail!("refuse GitHub pagination outside configured API origin");
            }
            return Ok(Some(url));
        }
    }
    Ok(None)
}

/// Top-level driver: scan every text file in every (non-archived,
/// non-fork by default) repo under `owner`. If `repo_filter` is `Some`,
/// scan only that one repo.
pub async fn scan_owner(
    client: &GitHubClient,
    owner: &str,
    repo_filter: Option<&str>,
    include_forks: bool,
    include_archived: bool,
) -> Result<ScanOutcome<Finding>> {
    let mut outcome = ScanOutcome::default();
    outcome.record_scope(format!(
        "github:default_branch;forks={};archived={}",
        if include_forks {
            "included"
        } else {
            "excluded"
        },
        if include_archived {
            "included"
        } else {
            "excluded"
        }
    ));
    let repos_result = match repo_filter {
        Some(name) => client.get_repo(owner, name).await.map(|repo| vec![repo]),
        None => client.list_repos(owner).await,
    };
    let repos = match repos_result {
        Ok(repos) => repos,
        Err(error) => {
            outcome.record_error(SourceError::new(
                SourceErrorKind::Repository,
                repo_filter
                    .map(|repo| format!("{owner}/{repo}"))
                    .unwrap_or_else(|| owner.to_string()),
                error.to_string(),
            ));
            return Ok(outcome);
        }
    };
    for repo in repos {
        if !include_forks && repo.fork {
            outcome.record_excluded("fork_repository");
            continue;
        }
        if !include_archived && repo.archived {
            outcome.record_excluded("archived_repository");
            continue;
        }
        let repo_outcome = scan_repo(client, owner, &repo).await;
        tracing::info!(
            "scanned {}: {} findings",
            repo.full_name,
            repo_outcome.findings.len()
        );
        outcome.merge(repo_outcome);
    }
    Ok(outcome)
}

async fn scan_repo(client: &GitHubClient, owner: &str, repo: &RepoSummary) -> ScanOutcome<Finding> {
    let mut outcome = ScanOutcome::default();
    let tree = match client
        .list_tree(owner, &repo.name, &repo.default_branch)
        .await
    {
        Ok(tree) => tree,
        Err(error) => {
            tracing::warn!("skip repo {}: {}", repo.full_name, error);
            outcome.record_error(SourceError::new(
                SourceErrorKind::Tree,
                repo.full_name.clone(),
                error.to_string(),
            ));
            return outcome;
        }
    };
    if tree.truncated {
        outcome.mark_truncated();
    }
    for entry in tree.entries {
        // Skip oversized blobs and obviously-binary paths.
        if entry.size.unwrap_or(0) > MAX_FILE_BYTES {
            outcome.record_excluded("oversized_blob");
            continue;
        }
        if has_binary_extension(&entry.path) {
            outcome.record_excluded("binary_extension");
            continue;
        }
        let bytes = match client
            .fetch_blob(owner, &repo.name, &entry.path, &repo.default_branch)
            .await
        {
            Ok(b) => b,
            Err(e) => {
                tracing::debug!("blob fetch {}/{}: {}", repo.full_name, entry.path, e);
                outcome.record_error(SourceError::new(
                    SourceErrorKind::Blob,
                    format!("{}:{}", repo.full_name, entry.path),
                    e.to_string(),
                ));
                continue;
            }
        };
        if bytes.len() as u64 > MAX_FILE_BYTES {
            outcome.record_excluded("oversized_blob");
            continue;
        }
        if looks_binary(&bytes) {
            outcome.record_excluded("binary_blob");
            continue;
        }
        let Ok(text) = std::str::from_utf8(&bytes) else {
            outcome.record_excluded("non_utf8_blob");
            continue;
        };
        let location = format!("{}:{}@{}", repo.full_name, entry.path, repo.default_branch);
        outcome.record_scanned(bytes.len());
        let (mut findings, truncated) = scan_text_with_status(text, &location);
        outcome.append_findings(&mut findings);
        if truncated {
            outcome.mark_truncated();
        }
    }
    outcome
}

fn has_binary_extension(path: &str) -> bool {
    // Lower-case extension suffix match. Cheap; covers >95% of binary
    // file types you'd find in a typical repo.
    let lc = path.to_ascii_lowercase();
    const BIN_EXTS: &[&str] = &[
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".tif", ".tiff", ".pdf", ".zip",
        ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar", ".so", ".dll", ".dylib", ".exe", ".bin", ".o",
        ".a", ".lib", ".class", ".jar", ".war", ".ear", ".woff", ".woff2", ".ttf", ".otf", ".eot",
        ".mp3", ".mp4", ".wav", ".flac", ".ogg", ".mov", ".avi", ".mkv", ".pyc", ".pyo", ".node",
    ];
    BIN_EXTS.iter().any(|ext| lc.ends_with(ext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sources::{CoverageEvaluation, CoverageStatus};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    struct MockResponse {
        path: &'static str,
        status: &'static str,
        body: &'static str,
    }

    fn mock_github(responses: Vec<MockResponse>) -> (String, thread::JoinHandle<()>) {
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
                assert_eq!(request_path, response.path);
                write!(
                    stream,
                    "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response.status,
                    response.body.len(),
                    response.body
                )
                .unwrap();
            }
        });
        (format!("http://{address}"), handle)
    }

    const REPO_RESPONSE: &str = r#"{
        "name":"repo",
        "full_name":"owner/repo",
        "default_branch":"main",
        "fork":false,
        "archived":false
    }"#;

    #[test]
    fn binary_extensions_recognised() {
        assert!(has_binary_extension("logo.png"));
        assert!(has_binary_extension("icon.ICO"));
        assert!(has_binary_extension("path/to/lib.so"));
        assert!(!has_binary_extension("README.md"));
        assert!(!has_binary_extension("src/main.rs"));
    }

    #[test]
    fn base_url_policy_requires_https_or_explicit_ip_loopback() {
        assert!(validate_base_url("https://github.example/api/v3", false).is_ok());
        assert!(validate_base_url("http://github.example", true).is_err());
        assert!(validate_base_url("http://localhost:8080", true).is_err());
        assert!(validate_base_url("http://127.0.0.1:8080", true).is_ok());
        assert!(validate_base_url("https://user:pass@github.example", false).is_err());
    }

    #[tokio::test]
    async fn blob_url_percent_encodes_every_untrusted_component() {
        let (base_url, server) = mock_github(vec![MockResponse {
            path: "/repos/owner%20name/repo%231/contents/dir/file%20name?ref=feature%2Fone",
            status: "200 OK",
            body: "clean",
        }]);
        let client = GitHubClient::for_test_base_url(&base_url);
        let body = client
            .fetch_blob("owner name", "repo#1", "dir/file name", "feature/one")
            .await
            .unwrap();
        server.join().unwrap();
        assert_eq!(body, b"clean");
    }

    #[tokio::test]
    async fn empty_organization_is_not_misclassified_as_a_user() {
        let (base_url, server) = mock_github(vec![MockResponse {
            path: "/orgs/owner/repos?per_page=100&type=all",
            status: "200 OK",
            body: "[]",
        }]);
        let repos = GitHubClient::for_test_base_url(&base_url)
            .list_repos("owner")
            .await
            .unwrap();
        server.join().unwrap();
        assert!(repos.is_empty());
    }

    #[tokio::test]
    async fn owner_fallback_occurs_only_when_org_endpoint_is_not_found() {
        let (base_url, server) = mock_github(vec![
            MockResponse {
                path: "/orgs/owner/repos?per_page=100&type=all",
                status: "404 Not Found",
                body: r#"{"message":"not found"}"#,
            },
            MockResponse {
                path: "/users/owner/repos?per_page=100&type=all",
                status: "200 OK",
                body: "[]",
            },
        ]);
        let repos = GitHubClient::for_test_base_url(&base_url)
            .list_repos("owner")
            .await
            .unwrap();
        server.join().unwrap();
        assert!(repos.is_empty());
    }

    #[tokio::test]
    async fn truncated_tree_sets_typed_partial_coverage_and_keeps_results() {
        let (base_url, server) = mock_github(vec![
            MockResponse {
                path: "/repos/owner/repo",
                status: "200 OK",
                body: REPO_RESPONSE,
            },
            MockResponse {
                path: "/repos/owner/repo/git/trees/main?recursive=1",
                status: "200 OK",
                body: r#"{"tree":[{"path":"README.md","type":"blob","size":8}],"truncated":true}"#,
            },
            MockResponse {
                path: "/repos/owner/repo/contents/README.md?ref=main",
                status: "200 OK",
                body: "# clean\n",
            },
        ]);
        let client = GitHubClient::for_test_base_url(&base_url);
        let outcome = scan_owner(&client, "owner", Some("repo"), false, false)
            .await
            .unwrap();
        server.join().unwrap();

        assert!(outcome.findings.is_empty());
        assert_eq!(outcome.coverage().objects_scanned(), 1);
        assert_eq!(outcome.coverage().bytes_scanned(), 8);
        assert!(outcome.coverage().truncated());
        assert!(outcome.coverage().partial());
        let evaluation = CoverageEvaluation::evaluate(outcome.coverage(), 100.0);
        assert_eq!(evaluation.status, CoverageStatus::Truncated);
        assert!(evaluation.requires_failure());
    }

    #[tokio::test]
    async fn mixed_blob_failure_retains_success_and_structured_error() {
        let (base_url, server) = mock_github(vec![
            MockResponse {
                path: "/repos/owner/repo",
                status: "200 OK",
                body: REPO_RESPONSE,
            },
            MockResponse {
                path: "/repos/owner/repo/git/trees/main?recursive=1",
                status: "200 OK",
                body: r#"{"tree":[{"path":"good.txt","type":"blob","size":6},{"path":"bad.txt","type":"blob","size":5}],"truncated":false}"#,
            },
            MockResponse {
                path: "/repos/owner/repo/contents/good.txt?ref=main",
                status: "200 OK",
                body: "clean\n",
            },
            MockResponse {
                path: "/repos/owner/repo/contents/bad.txt?ref=main",
                status: "500 Internal Server Error",
                body: r#"{"message":"synthetic failure"}"#,
            },
        ]);
        let client = GitHubClient::for_test_base_url(&base_url);
        let outcome = scan_owner(&client, "owner", Some("repo"), false, false)
            .await
            .unwrap();
        server.join().unwrap();

        assert_eq!(outcome.coverage().objects_scanned(), 1);
        assert_eq!(outcome.coverage().bytes_scanned(), 6);
        assert_eq!(outcome.coverage().source_errors().len(), 1);
        assert_eq!(
            outcome.coverage().source_errors()[0].kind,
            SourceErrorKind::Blob
        );
        assert!(outcome.coverage().partial());
        assert!(!outcome.coverage().truncated());
        let evaluation = CoverageEvaluation::evaluate(outcome.coverage(), 10.0);
        assert_eq!(evaluation.status, CoverageStatus::ThresholdExceeded);
        assert!(evaluation.requires_failure());
    }

    #[tokio::test]
    async fn repository_failure_is_a_typed_partial_error() {
        let client = GitHubClient::for_test_base_url("http://127.0.0.1:9");
        let outcome = scan_owner(&client, "owner", Some("repo"), false, false)
            .await
            .unwrap();
        assert!(outcome.findings.is_empty());
        assert_eq!(outcome.coverage().objects_scanned(), 0);
        assert_eq!(outcome.coverage().source_errors().len(), 1);
        assert_eq!(
            outcome.coverage().source_errors()[0].kind,
            SourceErrorKind::Repository
        );
        assert!(outcome.coverage().partial());
        let evaluation = CoverageEvaluation::evaluate(outcome.coverage(), 100.0);
        assert_eq!(evaluation.status, CoverageStatus::TotalFailure);
        assert!(evaluation.requires_failure());
    }
}
