use anyhow::{bail, Result};
use clap::Parser;
use owo_colors::OwoColorize;
use std::process::ExitCode;
use tracefuse::cli::{Cli, Commands};
use tracefuse::config::{load_config, write_example_config, DetectorToggles};
use tracefuse::report::{emit_json, emit_sarif, print_human};
use tracefuse::rules::{find_rule, list_rule_ids};
use tracefuse::scan::run_scan;

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { path, force } => {
            let target = path.unwrap_or_else(|| std::env::current_dir().unwrap());
            let written = write_example_config(&target, force)?;
            println!("Wrote {}", written.display());
            Ok(ExitCode::SUCCESS)
        }
        Commands::Doctor { path } => {
            let root = path.unwrap_or_else(|| std::env::current_dir().unwrap());
            run_doctor(&root)?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::Explain { rule_id } => {
            run_explain(&rule_id)?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::Scan {
            path,
            json,
            sarif,
            fail_on,
            config,
            quiet,
            git_diff,
        } => {
            let root = path.unwrap_or_else(|| std::env::current_dir().unwrap());
            let mut cfg = load_config(&root, config.as_deref())?;
            if let Some(level) = fail_on {
                cfg.fail_on = level.into();
            }

            let report = if git_diff {
                tracefuse::scan::run_scan_git_diff(&root, &cfg)?
            } else {
                run_scan(&root, &cfg)?
            };

            if json {
                emit_json(&report, &mut std::io::stdout())?;
            } else if !quiet {
                print_human(&report)?;
            }

            if let Some(sarif_path) = sarif {
                emit_sarif(&report, &sarif_path)?;
                if !json && !quiet {
                    println!("SARIF written to {}", sarif_path.display());
                }
            }

            let exit = exit_for_findings(&report.findings, cfg.fail_on);
            Ok(ExitCode::from(exit))
        }
    }
}

fn run_doctor(root: &std::path::Path) -> Result<()> {
    let cfg_path = root.join(".tracefuse.toml");
    let cfg = load_config(root, None)?;
    let version = env!("CARGO_PKG_VERSION");

    println!();
    println!("  {}", "TRACEFUSE DOCTOR".bold().bright_cyan());
    println!("  {}", "────────────────".dimmed());
    println!("  {}  {}", "version".dimmed(), version);
    println!(
        "  {}  {}",
        "offline".dimmed(),
        "yes — default scan uses no network".bright_green()
    );
    println!("  {}  {}", "root".dimmed(), root.display());
    if cfg_path.exists() {
        println!(
            "  {}  {} {}",
            "config".dimmed(),
            cfg_path.display(),
            "(found)".bright_green()
        );
    } else {
        println!(
            "  {}  {} {}",
            "config".dimmed(),
            "missing".bright_yellow(),
            "— run `tracefuse init`".dimmed()
        );
    }
    println!(
        "  {}  {} (default gate)",
        "fail_on".dimmed(),
        format!("{:?}", cfg.fail_on).to_ascii_lowercase()
    );
    println!(
        "  {}  {} path components",
        "ignore_paths".dimmed(),
        cfg.ignore_paths.len()
    );
    println!(
        "  {}  {} override(s)",
        "severity_overrides".dimmed(),
        cfg.severity_overrides.len()
    );
    println!(
        "  {}  {}",
        "detectors".dimmed(),
        format_detectors(&cfg.detectors)
    );
    println!(
        "  {}  {} rules in catalog",
        "explain".dimmed(),
        list_rule_ids().len()
    );
    println!();
    println!("  {}", "CHECKS".bold().bright_yellow());
    let mut ok = true;
    if !cfg_path.exists() {
        println!(
            "  {}  No `.tracefuse.toml` — defaults are fine; init when you need overrides.",
            "·".dimmed()
        );
    } else {
        println!("  {}  Config parses and loads.", "✓".bright_green());
    }
    let gitignore = root.join(".gitignore");
    if gitignore.exists() {
        let text = std::fs::read_to_string(&gitignore).unwrap_or_default();
        if text
            .lines()
            .any(|l| l.trim() == ".env" || l.trim() == ".env.*")
        {
            println!(
                "  {}  `.gitignore` covers `.env` patterns.",
                "✓".bright_green()
            );
        } else {
            println!(
                "  {}  Consider ignoring `.env` / `.env.*` (keep `.env.example`).",
                "!".bright_yellow()
            );
            ok = false;
        }
    }
    println!(
        "  {}  Redaction enabled for human / JSON / SARIF evidence.",
        "✓".bright_green()
    );
    println!();
    println!("  {}", "NEXT".bold());
    println!("  · tracefuse scan .");
    println!("  · tracefuse explain ci/pull-request-target");
    println!("  · tracefuse scan . --sarif tracefuse.sarif --fail-on high -q");
    println!();
    let _ = ok;
    Ok(())
}

fn format_detectors(d: &DetectorToggles) -> String {
    let mut on = Vec::new();
    let mut off = Vec::new();
    let pairs = [
        ("secrets", d.secrets),
        ("scripts", d.scripts),
        ("lockfile", d.lockfile),
        ("dockerfile", d.dockerfile),
        ("ci", d.ci),
        ("env_files", d.env_files),
        ("deps", d.deps),
    ];
    for (name, enabled) in pairs {
        if enabled {
            on.push(name);
        } else {
            off.push(name);
        }
    }
    if off.is_empty() {
        format!("{} on", on.join(", "))
    } else {
        format!("{} on; {} off", on.join(", "), off.join(", "))
    }
}

fn run_explain(query: &str) -> Result<()> {
    match find_rule(query) {
        Some(rule) => {
            println!();
            println!("  {}  {}", "RULE".dimmed(), rule.id.bold().bright_cyan());
            println!("  {}  {}", "detector".dimmed(), rule.detector);
            println!(
                "  {}  {}",
                "severity".dimmed(),
                rule.default_severity.as_str()
            );
            println!("  {}  {}", "title".dimmed(), rule.title);
            println!();
            println!("  {}", "SUMMARY".bold());
            println!("  {}", rule.summary);
            println!();
            println!("  {}", "WHY IT MATTERS".bold());
            println!("  {}", rule.why);
            println!();
            println!("  {}", "REMEDIATION".bold());
            println!("  {}", rule.remediation);
            if !rule.references.is_empty() {
                println!();
                println!("  {}", "REFERENCES".bold());
                for r in rule.references {
                    println!("  · {r}");
                }
            }
            println!();
            println!("  {}", "Override in .tracefuse.toml:".dimmed());
            println!("  [severity_overrides]\n  \"{}\" = \"low\"", rule.id);
            println!();
            Ok(())
        }
        None => {
            eprintln!("unknown rule: {query}");
            eprintln!("known ids:");
            for id in list_rule_ids() {
                eprintln!("  · {id}");
            }
            bail!("rule not found");
        }
    }
}

fn exit_for_findings(findings: &[tracefuse::Finding], fail_on: tracefuse::config::FailOn) -> u8 {
    let threshold = fail_on.as_severity();
    let should_fail = findings.iter().any(|f| f.severity >= threshold);
    if should_fail {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracefuse::{Finding, FindingSeverity};

    #[test]
    fn exit_clean_when_below_threshold() {
        let findings = vec![Finding {
            id: "t".into(),
            detector: "t".into(),
            severity: FindingSeverity::Low,
            title: "t".into(),
            message: "t".into(),
            file: None,
            line: None,
            evidence: None,
            remediation: None,
        }];
        assert_eq!(
            exit_for_findings(&findings, tracefuse::config::FailOn::High),
            0
        );
    }

    #[test]
    fn exit_fail_when_at_or_above_threshold() {
        let findings = vec![Finding {
            id: "t".into(),
            detector: "t".into(),
            severity: FindingSeverity::High,
            title: "t".into(),
            message: "t".into(),
            file: None,
            line: None,
            evidence: None,
            remediation: None,
        }];
        assert_eq!(
            exit_for_findings(&findings, tracefuse::config::FailOn::High),
            1
        );
    }
}
