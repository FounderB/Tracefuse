use crate::config::FailOn;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "tracefuse",
    version,
    about = "Supply-chain / pipeline truth scanner — declared vs real",
    long_about = "Tracefuse compares what a repository claims with what actually ships:\n\
secrets, dangerous scripts, lockfile drift, Dockerfile & CI smells, credential files,\n\
and dependency-risk heuristics. Offline-first. SARIF-ready.\n\n\
Try: tracefuse doctor · tracefuse explain ci/pull-request-target · tracefuse scan ."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Scan a project directory for supply-chain / pipeline risks
    Scan {
        /// Path to scan (defaults to current directory)
        #[arg(default_value = ".")]
        path: Option<PathBuf>,

        /// Emit machine-readable JSON to stdout
        #[arg(long)]
        json: bool,

        /// Write SARIF 2.1.0 report to this path (GitHub Code Scanning)
        #[arg(long, value_name = "FILE")]
        sarif: Option<PathBuf>,

        /// Fail (exit 1) when findings at or above this severity exist
        #[arg(long, value_enum)]
        fail_on: Option<FailOnCli>,

        /// Path to config file (default: .tracefuse.toml in scan root)
        #[arg(long, short = 'c')]
        config: Option<PathBuf>,

        /// Suppress human output (useful with --json / --sarif)
        #[arg(long, short = 'q')]
        quiet: bool,
    },

    /// Write an example `.tracefuse.toml` config
    Init {
        /// Directory to write config into (defaults to cwd)
        #[arg(default_value = ".")]
        path: Option<PathBuf>,

        /// Overwrite existing config
        #[arg(long)]
        force: bool,
    },

    /// Check local environment, config, and Tracefuse health
    Doctor {
        /// Project path to inspect (defaults to cwd)
        #[arg(default_value = ".")]
        path: Option<PathBuf>,
    },

    /// Explain a detector rule id (or fuzzy title match)
    Explain {
        /// Rule id, e.g. `ci/pull-request-target` or `gcp`
        rule_id: String,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum FailOnCli {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl From<FailOnCli> for FailOn {
    fn from(v: FailOnCli) -> Self {
        match v {
            FailOnCli::Info => FailOn::Info,
            FailOnCli::Low => FailOn::Low,
            FailOnCli::Medium => FailOn::Medium,
            FailOnCli::High => FailOn::High,
            FailOnCli::Critical => FailOn::Critical,
        }
    }
}
