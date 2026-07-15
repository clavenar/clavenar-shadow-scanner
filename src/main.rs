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
        Command::Local { path, out } => run_local(path, out).await,
        Command::Github {
            owner,
            include_forks,
            include_archived,
            out,
        } => run_github(owner, include_forks, include_archived, out).await,
        Command::Slack { days, out } => run_slack(days, out).await,
    }
}

async fn run_local(path: PathBuf, out: OutputArgs) -> Result<()> {
    let source = format!("local:{}", path.display());
    if out.unredacted {
        let findings = sources::local::scan_directory_unredacted(&path).await?;
        emit_unredacted(&source, findings, out)
    } else {
        let findings = sources::local::scan_directory(&path).await?;
        emit(&source, findings, out)
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
    let findings = sources::github::scan_owner(
        &client,
        &owner,
        repo.as_deref(),
        include_forks,
        include_archived,
    )
    .await
    .with_context(|| format!("scan github://{}", owner_arg))?;
    emit(&format!("github://{}", owner_arg), findings, out)
}

async fn run_slack(days: i64, out: OutputArgs) -> Result<()> {
    reject_remote_unredacted(&out, "slack")?;
    let client = sources::slack::SlackClient::from_env()?;
    let findings = sources::slack::scan_workspace(&client, days).await?;
    emit(&format!("slack://workspace?days={}", days), findings, out)
}

fn emit(
    source: &str,
    findings: Vec<clavenar_shadow_scanner::Finding>,
    out: OutputArgs,
) -> Result<()> {
    let min = Severity::from_min(&out.severity_min)
        .with_context(|| format!("invalid --severity-min: {}", out.severity_min))?;
    let findings = filter_by_min_severity(findings, min);
    let report = Report::from_findings(source, findings);
    let mut stdout = stdout().lock();
    if out.sarif {
        report.write_sarif(&mut stdout)?;
    } else if out.json {
        report.write_json(&mut stdout)?;
    } else {
        report.write_human(&mut stdout)?;
    }
    // Non-zero exit if any critical/high finding so CI integration is
    // useful. Medium and low are informational.
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
    findings: Vec<clavenar_shadow_scanner::UnsafeFinding>,
    out: OutputArgs,
) -> Result<()> {
    if out.sarif {
        bail!("--unredacted cannot be combined with --sarif");
    }
    let min = Severity::from_min(&out.severity_min)
        .with_context(|| format!("invalid --severity-min: {}", out.severity_min))?;
    let findings = filter_unsafe_by_min_severity(findings, min);
    let report = UnsafeReport::from_findings(source, findings);
    let mut stdout = stdout().lock();
    if out.json {
        report.write_json(&mut stdout)?;
    } else {
        report.write_human(&mut stdout)?;
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
