//! clavenar-shadow-scanner — CLI entry point.
//!
//! Three scan subcommands: `local`, `github`, `slack`. Common output
//! flags are split out into [`OutputArgs`] so each subcommand sees the
//! same surface.

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use clavenar_shadow_scanner::{
    detector::Severity,
    output::{Report, UnsafeReport, filter_by_min_severity, filter_unsafe_by_min_severity},
    sources,
};
use std::io::stdout;
use std::path::PathBuf;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser, Debug)]
#[command(
    name = "clavenar-shadow-scanner",
    version,
    about = "Find unauthorized agent credentials in repos, chat, and on-disk."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Scan a local directory.
    Local {
        path: PathBuf,
        /// Supplement the normal walk with ignored credential-oriented files.
        /// Never follows symlinks or enters VCS/dependency/build internals.
        #[arg(long)]
        secrets_mode: bool,
        #[command(flatten)]
        out: OutputArgs,
    },
    /// Scan one or every repo under a GitHub owner (org or user).
    /// Auth via `GITHUB_TOKEN` env var (optional but strongly recommended;
    /// without it you're capped at 60 req/hour).
    Github {
        /// Owner (org or user). Use `owner/repo` to limit to one repo.
        owner: String,
        #[arg(long)]
        include_forks: bool,
        #[arg(long)]
        include_archived: bool,
        #[command(flatten)]
        out: OutputArgs,
    },
    /// Scan Slack workspace history. Auth via `SLACK_BOT_TOKEN`.
    /// Looks back `--days` days across every conversation the bot is
    /// a member of.
    Slack {
        #[arg(long, default_value_t = sources::slack::DEFAULT_LOOKBACK_DAYS)]
        days: i64,
        #[command(flatten)]
        out: OutputArgs,
    },
}

#[derive(Args, Debug)]
struct OutputArgs {
    /// Emit JSON (machine-readable) instead of the human-readable report.
    #[arg(long, conflicts_with = "sarif")]
    json: bool,
    /// Emit SARIF v2.1.0 (the format GitHub Code Scanning, Sonatype,
    /// etc. consume). Always redacted — SARIF outputs end up as build
    /// artefacts and we never teach this path to leak.
    #[arg(long, conflicts_with = "json")]
    sarif: bool,
    /// Show secrets in plaintext for a local scan. This makes the output a
    /// secrets file. Rejected for remote sources and SARIF.
    #[arg(long, conflicts_with = "sarif")]
    unredacted: bool,
    /// Drop findings below this severity. One of: critical, high,
    /// medium, low.
    #[arg(long, default_value = "low")]
    severity_min: String,
    /// Maximum tolerated incomplete-object percentage. Total failure and
    /// truncation always fail with exit 3 regardless of this value.
    #[arg(
        long,
        default_value_t = sources::DEFAULT_MAX_PARTIAL_PERCENT,
        value_parser = parse_partial_percent
    )]
    max_partial_percent: f64,
}

fn parse_partial_percent(value: &str) -> std::result::Result<f64, String> {
    let value = value
        .parse::<f64>()
        .map_err(|_| "must be a number from 0 through 100".to_string())?;
    if value.is_finite() && (0.0..=100.0).contains(&value) {
        Ok(value)
    } else {
        Err("must be a finite number from 0 through 100".into())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Default-off tracing; opt in via RUST_LOG (e.g. RUST_LOG=info).
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Local {
            path,
            secrets_mode,
            out,
        } => run_local(path, secrets_mode, out).await,
        Command::Github {
            owner,
            include_forks,
            include_archived,
            out,
        } => run_github(owner, include_forks, include_archived, out).await,
        Command::Slack { days, out } => run_slack(days, out).await,
    }
}

async fn run_local(path: PathBuf, secrets_mode: bool, out: OutputArgs) -> Result<()> {
    let source = format!("local:{}", path.display());
    let mode = if secrets_mode {
        sources::local::LocalScanMode::Secrets
    } else {
        sources::local::LocalScanMode::Standard
    };
    if out.unredacted {
        let outcome = sources::local::scan_directory_unredacted_with_mode(&path, mode).await?;
        emit_unredacted(&source, outcome, out)
    } else {
        let outcome = sources::local::scan_directory_with_mode(&path, mode).await?;
        emit(&source, outcome, out)
    }
}

async fn run_github(
    owner_arg: String,
    include_forks: bool,
    include_archived: bool,
    out: OutputArgs,
) -> Result<()> {
    reject_remote_unredacted(&out, "github")?;
    let client = sources::github::GitHubClient::from_env();
    let (owner, repo) = match owner_arg.split_once('/') {
        Some((o, r)) => (o.to_string(), Some(r.to_string())),
        None => (owner_arg.clone(), None),
    };
    let outcome = sources::github::scan_owner(
        &client,
        &owner,
        repo.as_deref(),
        include_forks,
        include_archived,
    )
    .await
    .with_context(|| format!("scan github://{}", owner_arg))?;
    emit(&format!("github://{}", owner_arg), outcome, out)
}

async fn run_slack(days: i64, out: OutputArgs) -> Result<()> {
    reject_remote_unredacted(&out, "slack")?;
    let client = sources::slack::SlackClient::from_env()?;
    let outcome = sources::slack::scan_workspace(&client, days).await?;
    emit(&format!("slack://workspace?days={}", days), outcome, out)
}

fn emit(
    source: &str,
    outcome: sources::ScanOutcome<clavenar_shadow_scanner::Finding>,
    out: OutputArgs,
) -> Result<()> {
    let min = Severity::from_min(&out.severity_min)
        .with_context(|| format!("invalid --severity-min: {}", out.severity_min))?;
    let outcome = outcome.map_findings(|findings| filter_by_min_severity(findings, min));
    let report = Report::from_outcome_with_threshold(source, outcome, out.max_partial_percent);
    let mut stdout = stdout().lock();
    if out.sarif {
        report.write_sarif(&mut stdout)?;
    } else if out.json {
        report.write_json(&mut stdout)?;
    } else {
        report.write_human(&mut stdout)?;
    }
    if report.coverage_evaluation.requires_failure() {
        std::process::exit(sources::COVERAGE_FAILURE_EXIT_CODE);
    }
    // Non-zero exit if any critical/high finding so CI integration is useful.
    // Medium and low are informational. Coverage failure takes precedence.
    let any_high = report
        .aggregates
        .iter()
        .any(|a| matches!(a.severity, Severity::Critical | Severity::High));
    if any_high {
        std::process::exit(2);
    }
    Ok(())
}

fn emit_unredacted(
    source: &str,
    outcome: sources::ScanOutcome<clavenar_shadow_scanner::UnsafeFinding>,
    out: OutputArgs,
) -> Result<()> {
    if out.sarif {
        bail!("--unredacted cannot be combined with --sarif");
    }
    let min = Severity::from_min(&out.severity_min)
        .with_context(|| format!("invalid --severity-min: {}", out.severity_min))?;
    let outcome = outcome.map_findings(|findings| filter_unsafe_by_min_severity(findings, min));
    let report =
        UnsafeReport::from_outcome_with_threshold(source, outcome, out.max_partial_percent);
    let mut stdout = stdout().lock();
    if out.json {
        report.write_json(&mut stdout)?;
    } else {
        report.write_human(&mut stdout)?;
    }
    if report.coverage_evaluation.requires_failure() {
        std::process::exit(sources::COVERAGE_FAILURE_EXIT_CODE);
    }
    let any_high = report
        .aggregates
        .iter()
        .any(|aggregate| matches!(aggregate.severity, Severity::Critical | Severity::High));
    if any_high {
        std::process::exit(2);
    }
    Ok(())
}

fn reject_remote_unredacted(out: &OutputArgs, source: &str) -> Result<()> {
    if out.unredacted {
        bail!("--unredacted is restricted to local scans; {source} output is always redacted");
    }
    Ok(())
}
