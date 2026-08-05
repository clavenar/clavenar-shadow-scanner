//! Local filesystem source.
//!
//! Walks a directory using ripgrep's `ignore` crate so `.gitignore` and
//! `.git/` are respected by default — without that, scans of typical
//! repos drown in `node_modules` / `target/` / `.venv`.
//!
//! Each text file under `MAX_FILE_BYTES` is read and scanned. Binaries
//! are skipped via a NUL-byte heuristic (the same trick git uses).
//!
//! `ignore`'s walker is synchronous, so we drive it via
//! [`tokio::task::spawn_blocking`] to avoid stalling the runtime.

use super::{
    MAX_FILE_BYTES, MAX_SOURCE_OBJECTS, ScanOutcome, SourceError, SourceErrorKind, looks_binary,
};
use crate::detector::{
    Finding, UnsafeFinding, scan_text_unredacted_with_status, scan_text_with_status,
};
use anyhow::{Context, Result, bail};
use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LocalScanMode {
    #[default]
    Standard,
    Secrets,
}

/// Scan `root` recursively and return findings with complete coverage
/// accounting. Errors during one item become typed partial-coverage records;
/// they do not erase findings from other readable files.
pub async fn scan_directory(root: &Path) -> Result<ScanOutcome<Finding>> {
    scan_directory_with_mode(root, LocalScanMode::Standard).await
}

pub async fn scan_directory_with_mode(
    root: &Path,
    mode: LocalScanMode,
) -> Result<ScanOutcome<Finding>> {
    let requested_root = root.to_path_buf();
    // The `ignore` walker is synchronous. Push the whole walk onto the
    // blocking pool; we collect a `Vec<PathBuf>` first, then read +
    // scan asynchronously. Trading a small upfront allocation for a
    // simpler async story.
    let gathered = tokio::task::spawn_blocking(move || gather_paths(&requested_root, mode))
        .await
        .context("spawn_blocking gather_paths")?;

    let mut outcome = ScanOutcome::default();
    record_local_scope(&mut outcome, mode);
    if gathered.truncated {
        outcome.mark_truncated();
    }
    for error in gathered.errors {
        outcome.record_error(error);
    }
    let Some(root) = gathered.root else {
        return Ok(outcome);
    };
    for path in gathered.paths {
        match scan_one_file(&root, &path).await {
            Ok(FileScan::Scanned {
                mut findings,
                bytes,
                truncated,
            }) => {
                outcome.record_scanned(bytes);
                outcome.append_findings(&mut findings);
                if truncated {
                    outcome.mark_truncated();
                }
            }
            Ok(FileScan::Excluded(reason)) => outcome.record_excluded(reason),
            Err(error) => {
                tracing::warn!("skip {}: {}", path.display(), error);
                outcome.record_error(SourceError::new(
                    SourceErrorKind::Read,
                    path.display().to_string(),
                    error.to_string(),
                ));
            }
        }
    }
    Ok(outcome)
}

/// Explicit local-only scan that retains raw matches for visibly marked unsafe
/// output. Remote sources do not expose an equivalent entry point.
pub async fn scan_directory_unredacted(root: &Path) -> Result<ScanOutcome<UnsafeFinding>> {
    scan_directory_unredacted_with_mode(root, LocalScanMode::Standard).await
}

pub async fn scan_directory_unredacted_with_mode(
    root: &Path,
    mode: LocalScanMode,
) -> Result<ScanOutcome<UnsafeFinding>> {
    let requested_root = root.to_path_buf();
    let gathered = tokio::task::spawn_blocking(move || gather_paths(&requested_root, mode))
        .await
        .context("spawn_blocking gather_paths")?;

    let mut outcome = ScanOutcome::default();
    record_local_scope(&mut outcome, mode);
    if gathered.truncated {
        outcome.mark_truncated();
    }
    for error in gathered.errors {
        outcome.record_error(error);
    }
    let Some(root) = gathered.root else {
        return Ok(outcome);
    };
    for path in gathered.paths {
        match scan_one_file_unredacted(&root, &path).await {
            Ok(FileScan::Scanned {
                mut findings,
                bytes,
                truncated,
            }) => {
                outcome.record_scanned(bytes);
                outcome.append_findings(&mut findings);
                if truncated {
                    outcome.mark_truncated();
                }
            }
            Ok(FileScan::Excluded(reason)) => outcome.record_excluded(reason),
            Err(error) => {
                tracing::warn!("skip {}: {}", path.display(), error);
                outcome.record_error(SourceError::new(
                    SourceErrorKind::Read,
                    path.display().to_string(),
                    error.to_string(),
                ));
            }
        }
    }
    Ok(outcome)
}

fn record_local_scope<F>(outcome: &mut ScanOutcome<F>, mode: LocalScanMode) {
    outcome.record_scope(match mode {
        LocalScanMode::Standard => "local:gitignore_aware_text_files",
        LocalScanMode::Secrets => "local:gitignore_aware_plus_credential_files",
    });
}

struct GatheredPaths {
    root: Option<PathBuf>,
    paths: Vec<PathBuf>,
    errors: Vec<SourceError>,
    truncated: bool,
}

fn gather_paths(root: &Path, mode: LocalScanMode) -> GatheredPaths {
    let root = match std::fs::canonicalize(root) {
        Ok(root) => root,
        Err(error) => {
            return GatheredPaths {
                root: None,
                paths: Vec::new(),
                errors: vec![SourceError::new(
                    SourceErrorKind::Walk,
                    root.display().to_string(),
                    error.to_string(),
                )],
                truncated: false,
            };
        }
    };

    let mut gathered = walk_paths(&root, true, false);
    if mode == LocalScanMode::Secrets {
        let supplemental = walk_paths(&root, false, true);
        gathered.paths.extend(supplemental.paths);
        gathered.errors.extend(supplemental.errors);
        gathered.truncated |= supplemental.truncated;
    }
    let paths = gathered.paths.into_iter().collect::<BTreeSet<_>>();
    let truncated = gathered.truncated || paths.len() > MAX_SOURCE_OBJECTS;
    GatheredPaths {
        root: Some(root),
        paths: paths.into_iter().take(MAX_SOURCE_OBJECTS).collect(),
        errors: gathered.errors,
        truncated,
    }
}

fn walk_paths(root: &Path, standard_filters: bool, credential_only: bool) -> GatheredPaths {
    let mut builder = ignore::WalkBuilder::new(root);
    builder
        .standard_filters(standard_filters)
        .hidden(false)
        .follow_links(false);
    if credential_only {
        builder.filter_entry(safe_secrets_entry);
    } else {
        builder.filter_entry(safe_standard_entry);
    }
    let walker = builder.build();

    let mut paths = Vec::new();
    let mut errors = Vec::new();
    let mut truncated = false;
    for dent in walker {
        let dent = match dent {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!("walk error: {}", e);
                errors.push(SourceError::new(
                    SourceErrorKind::Walk,
                    root.display().to_string(),
                    e.to_string(),
                ));
                continue;
            }
        };
        let path = dent.path();
        if !path.starts_with(root) {
            errors.push(SourceError::new(
                SourceErrorKind::Walk,
                path.display().to_string(),
                "walker returned a path outside the canonical scan root",
            ));
            continue;
        }
        // Skip symlinks (no recursion into them) and non-files.
        match dent.file_type() {
            Some(ft) if ft.is_file() => {}
            _ => continue,
        }
        if credential_only && !is_credential_path(path) {
            continue;
        }
        // Defer the size + binary heuristics to scan_one_file; here we
        // just collect candidate paths.
        paths.push(path.to_path_buf());
        if paths.len() > MAX_SOURCE_OBJECTS {
            truncated = true;
            break;
        }
    }
    GatheredPaths {
        root: Some(root.to_path_buf()),
        paths,
        errors,
        truncated,
    }
}

fn safe_secrets_entry(entry: &ignore::DirEntry) -> bool {
    if entry.depth() == 0 {
        return true;
    }
    let Some(file_type) = entry.file_type() else {
        return false;
    };
    if file_type.is_symlink() {
        return false;
    }
    if !file_type.is_dir() {
        return true;
    }
    let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
    !matches!(
        name.as_str(),
        ".git"
            | ".hg"
            | ".svn"
            | ".jj"
            | "node_modules"
            | "target"
            | "vendor"
            | ".venv"
            | "venv"
            | "__pycache__"
    )
}

fn safe_standard_entry(entry: &ignore::DirEntry) -> bool {
    if entry.depth() == 0 {
        return true;
    }
    let Some(file_type) = entry.file_type() else {
        return false;
    };
    if file_type.is_symlink() {
        return false;
    }
    if !file_type.is_dir() {
        return true;
    }
    let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
    !matches!(name.as_str(), ".git" | ".hg" | ".svn" | ".jj")
}

fn is_credential_path(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let name = name.to_ascii_lowercase();
    name == ".env"
        || name.starts_with(".env.")
        || name.ends_with(".pem")
        || name.ends_with(".key")
        || name.ends_with(".p12")
        || name.ends_with(".pfx")
        || name == ".npmrc"
        || name == ".pypirc"
        || name == ".netrc"
        || name == "_netrc"
        || name == "credentials"
        || name.starts_with("credentials.")
        || name == "kubeconfig"
        || name == "id_rsa"
        || name == "id_ed25519"
        || name.starts_with("secret.")
        || name.contains(".secret.")
        || name.starts_with("secrets.")
        || name.contains(".secrets.")
}

enum FileScan<F> {
    Scanned {
        findings: Vec<F>,
        bytes: usize,
        truncated: bool,
    },
    Excluded(&'static str),
}

async fn scan_one_file(root: &Path, path: &Path) -> Result<FileScan<Finding>> {
    let text = match read_scannable_file(root, path).await? {
        FileContent::Text(text) => text,
        FileContent::Excluded(reason) => return Ok(FileScan::Excluded(reason)),
    };
    let location = local_location(root, path);
    let (findings, truncated) = scan_text_with_status(&text, &location);
    Ok(FileScan::Scanned {
        bytes: text.len(),
        findings,
        truncated,
    })
}

async fn scan_one_file_unredacted(root: &Path, path: &Path) -> Result<FileScan<UnsafeFinding>> {
    let text = match read_scannable_file(root, path).await? {
        FileContent::Text(text) => text,
        FileContent::Excluded(reason) => return Ok(FileScan::Excluded(reason)),
    };
    let location = local_location(root, path);
    let (findings, truncated) = scan_text_unredacted_with_status(&text, &location);
    Ok(FileScan::Scanned {
        bytes: text.len(),
        findings,
        truncated,
    })
}

fn local_location(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/")
}

enum FileContent {
    Text(String),
    Excluded(&'static str),
}

async fn read_scannable_file(root: &Path, path: &Path) -> Result<FileContent> {
    let root = root.to_path_buf();
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || read_scannable_file_sync(&root, &path))
        .await
        .context("spawn_blocking read_scannable_file")?
}

fn read_scannable_file_sync(root: &Path, path: &Path) -> Result<FileContent> {
    let mut file = open_root_confined(root, path)?;
    let metadata = file
        .metadata()
        .with_context(|| format!("stat open file {}", path.display()))?;
    if !metadata.is_file() {
        bail!("opened path is not a regular file: {}", path.display());
    }
    if metadata.len() > MAX_FILE_BYTES {
        tracing::debug!("exclude oversized {}", path.display());
        return Ok(FileContent::Excluded("oversized_file"));
    }
    let mut bytes = Vec::with_capacity((metadata.len() as usize).min(MAX_FILE_BYTES as usize));
    file.by_ref()
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {}", path.display()))?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Ok(FileContent::Excluded("file_grew_beyond_size_limit"));
    }
    if looks_binary(&bytes) {
        tracing::debug!("exclude binary {}", path.display());
        return Ok(FileContent::Excluded("binary_file"));
    }
    match String::from_utf8(bytes) {
        Ok(text) => Ok(FileContent::Text(text)),
        Err(_) => Ok(FileContent::Excluded("non_utf8_file")),
    }
}

#[cfg(target_os = "linux")]
fn open_root_confined(root: &Path, path: &Path) -> Result<std::fs::File> {
    use rustix::fs::{Mode, OFlags, ResolveFlags, open, openat2};

    let relative = path
        .strip_prefix(root)
        .with_context(|| format!("{} is outside scan root {}", path.display(), root.display()))?;
    if relative.as_os_str().is_empty() {
        bail!("scan root itself is not a candidate file");
    }
    let root_fd = open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("open scan root {}", root.display()))?;
    let file_fd = openat2(
        &root_fd,
        relative,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .with_context(|| format!("open root-confined {}", path.display()))?;
    Ok(std::fs::File::from(file_fd))
}

#[cfg(not(target_os = "linux"))]
fn open_root_confined(root: &Path, path: &Path) -> Result<std::fs::File> {
    let metadata =
        std::fs::symlink_metadata(path).with_context(|| format!("lstat {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("refuse symlink {}", path.display());
    }
    let canonical =
        std::fs::canonicalize(path).with_context(|| format!("canonicalize {}", path.display()))?;
    if !canonical.starts_with(root) {
        bail!(
            "{} resolves outside scan root {}",
            path.display(),
            root.display()
        );
    }
    std::fs::File::open(&canonical).with_context(|| format!("open {}", canonical.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sources::{CoverageEvaluation, CoverageStatus};
    use std::fs;
    use tempfile::tempdir;

    #[tokio::test]
    async fn scans_planted_secret_in_subdir() {
        let dir = tempdir().unwrap();
        let nested = dir.path().join("subdir");
        fs::create_dir_all(&nested).unwrap();
        // Plant a high-confidence vendor key — pattern matches without
        // entropy gating.
        let key = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-aZbYcXdW";
        fs::write(nested.join(".env"), format!("ANTHROPIC_API_KEY={}\n", key)).unwrap();

        let outcome = scan_directory(dir.path()).await.unwrap();
        assert!(
            outcome
                .findings
                .iter()
                .any(|f| f.detector == "anthropic_api_key"),
            "no anthropic finding: {:?}",
            outcome.findings
        );
        assert_eq!(outcome.coverage().objects_scanned(), 1);
        assert!(outcome.coverage().bytes_scanned() > 0);
        assert!(!outcome.coverage().partial());
    }

    #[tokio::test]
    async fn respects_gitignore() {
        let dir = tempdir().unwrap();
        // Stand up a fake repo: .gitignore excludes node_modules.
        fs::write(dir.path().join(".gitignore"), "node_modules/\n").unwrap();
        fs::create_dir_all(dir.path().join("node_modules")).unwrap();
        let key = "sk-ant-api03-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB-cZbYaXdW";
        fs::write(
            dir.path().join("node_modules/leaked.env"),
            format!("ANTHROPIC_API_KEY={}", key),
        )
        .unwrap();

        // For the ignore crate to respect .gitignore, the dir must look
        // like a git repo OR we must ask explicitly. WalkBuilder honours
        // .gitignore even without .git/, so this is enough.
        // BUT we need a `.git` marker dir for some `ignore` defaults to
        // pick up the file — depends on version. Add an empty .git for
        // robustness.
        fs::create_dir_all(dir.path().join(".git")).unwrap();

        let outcome = scan_directory(dir.path()).await.unwrap();
        assert!(
            !outcome
                .findings
                .iter()
                .any(|f| f.location.contains("node_modules")),
            "ignored path leaked into findings: {:?}",
            outcome.findings
        );
    }

    #[tokio::test]
    async fn skips_oversized_file() {
        let dir = tempdir().unwrap();
        // Build a >1MiB file ending with what would otherwise be a hit.
        let mut buf = "x".repeat((MAX_FILE_BYTES + 1024) as usize);
        buf.push_str(
            "\nANTHROPIC_API_KEY=sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-aZbYcXdW\n",
        );
        fs::write(dir.path().join("big.txt"), buf).unwrap();
        let outcome = scan_directory(dir.path()).await.unwrap();
        assert!(
            outcome.findings.is_empty(),
            "scanned an oversized file: {:?}",
            outcome.findings
        );
        assert_eq!(outcome.coverage().objects_excluded(), 1);
        assert_eq!(outcome.coverage().exclusion_reasons()["oversized_file"], 1);
        assert!(!outcome.coverage().partial());
    }

    #[tokio::test]
    async fn skips_binary_file() {
        let dir = tempdir().unwrap();
        // NUL byte + valid-looking key after = binary heuristic should
        // skip the whole file.
        let mut buf: Vec<u8> = b"\x00binary marker\n".to_vec();
        buf.extend_from_slice(
            b"ANTHROPIC_API_KEY=sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-aZbYcXdW\n",
        );
        fs::write(dir.path().join("opaque.bin"), buf).unwrap();
        let outcome = scan_directory(dir.path()).await.unwrap();
        assert!(
            outcome.findings.is_empty(),
            "binary file scanned: {:?}",
            outcome.findings
        );
        assert_eq!(outcome.coverage().objects_excluded(), 1);
        assert_eq!(outcome.coverage().exclusion_reasons()["binary_file"], 1);
        assert!(!outcome.coverage().partial());
    }

    #[tokio::test]
    async fn missing_root_is_a_typed_partial_error() {
        let dir = tempdir().unwrap();
        let outcome = scan_directory(&dir.path().join("missing")).await.unwrap();
        assert!(outcome.findings.is_empty());
        assert_eq!(outcome.coverage().objects_scanned(), 0);
        assert_eq!(outcome.coverage().source_errors().len(), 1);
        assert_eq!(
            outcome.coverage().source_errors()[0].kind,
            SourceErrorKind::Walk
        );
        assert!(outcome.coverage().partial());
        let evaluation = CoverageEvaluation::evaluate(outcome.coverage(), 100.0);
        assert_eq!(evaluation.status, CoverageStatus::TotalFailure);
        assert!(evaluation.requires_failure());
    }

    #[test]
    fn credential_path_filter_covers_common_ignored_secret_files() {
        for path in [
            ".env",
            ".env.production",
            "service.pem",
            "private.key",
            ".npmrc",
            "credentials.json",
            "app.secrets.yaml",
            "id_ed25519",
        ] {
            assert!(is_credential_path(Path::new(path)), "not selected: {path}");
        }
        assert!(!is_credential_path(Path::new("README.md")));
        assert!(!is_credential_path(Path::new("src/main.rs")));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn confined_open_rejects_symlinks_and_paths_outside_root() {
        use std::os::unix::fs::symlink;

        let root = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let outside_file = outside.path().join("outside.env");
        fs::write(
            &outside_file,
            "GITHUB_TOKEN=ghp_LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL",
        )
        .unwrap();
        let link = root.path().join("linked.env");
        symlink(&outside_file, &link).unwrap();

        assert!(read_scannable_file(root.path(), &link).await.is_err());
        assert!(
            read_scannable_file(root.path(), &outside_file)
                .await
                .is_err()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn secrets_mode_adds_ignored_credentials_without_following_unsafe_paths() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let outside = tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".git")).unwrap();
        fs::create_dir_all(dir.path().join("node_modules")).unwrap();
        fs::write(
            dir.path().join(".gitignore"),
            ".env\nlinked.env\nnode_modules/\n",
        )
        .unwrap();
        let included = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-aZbYcXdW";
        let vcs_internal = "sk-ant-api03-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB-bZbYcXdW";
        let dependency = "sk-ant-api03-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC-cZbYcXdW";
        let outside_key = "sk-ant-api03-DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD-dZbYcXdW";
        fs::write(dir.path().join(".env"), format!("KEY={included}\n")).unwrap();
        fs::write(
            dir.path().join(".git/config"),
            format!("KEY={vcs_internal}\n"),
        )
        .unwrap();
        fs::write(
            dir.path().join("node_modules/.env"),
            format!("KEY={dependency}\n"),
        )
        .unwrap();
        let outside_path = outside.path().join("outside.env");
        fs::write(&outside_path, format!("KEY={outside_key}\n")).unwrap();
        symlink(&outside_path, dir.path().join("linked.env")).unwrap();

        let standard = scan_directory(dir.path()).await.unwrap();
        assert!(
            standard.findings.is_empty(),
            "standard locations: {:?}",
            standard
                .findings
                .iter()
                .map(|finding| &finding.location)
                .collect::<Vec<_>>()
        );

        let secrets = scan_directory_with_mode(dir.path(), LocalScanMode::Secrets)
            .await
            .unwrap();
        assert!(
            secrets
                .findings
                .iter()
                .any(|finding| finding.detector == "anthropic_api_key")
        );
        let locations = secrets
            .findings
            .iter()
            .map(|finding| finding.location.as_str())
            .collect::<Vec<_>>();
        assert!(locations.contains(&".env"));
        assert!(!locations.iter().any(|location| location.contains(".git/")));
        assert!(
            !locations
                .iter()
                .any(|location| location.contains("node_modules/"))
        );
        assert!(!locations.iter().any(|location| location == &"linked.env"));
        assert_eq!(secrets.coverage().source_errors().len(), 0);
        assert!(!secrets.coverage().partial());
    }
}
