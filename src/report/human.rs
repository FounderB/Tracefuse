use anyhow::Result;
use owo_colors::OwoColorize;
use std::io::{self, Write};

use crate::{Finding, FindingSeverity, ScanReport};

pub fn print_human(report: &ScanReport) -> Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out)?;
    writeln!(
        out,
        "{}",
        "╔══════════════════════════════════════════════════════════╗".bright_cyan()
    )?;
    writeln!(
        out,
        "{}{}{}",
        "║".bright_cyan(),
        format!("{:^58}", "TRACEFUSE").bold().bright_white(),
        "║".bright_cyan()
    )?;
    writeln!(
        out,
        "{}{}{}",
        "║".bright_cyan(),
        format!("{:^58}", "declared vs real · supply-chain truth").dimmed(),
        "║".bright_cyan()
    )?;
    writeln!(
        out,
        "{}",
        "╚══════════════════════════════════════════════════════════╝".bright_cyan()
    )?;
    writeln!(out)?;

    writeln!(out, "  {}  {}", "target".dimmed(), report.root.display())?;
    writeln!(
        out,
        "  {}  {}  ·  {} findings  ·  v{}",
        "scanned".dimmed(),
        report.scanned_at,
        report.summary.total,
        report.version
    )?;
    writeln!(out)?;

    print_score_bar(&mut out, report.score)?;
    writeln!(out)?;

    print_summary_badges(&mut out, report)?;
    writeln!(out)?;

    if report.findings.is_empty() {
        writeln!(
            out,
            "  {}  No findings. Pipeline looks clean at current rules.",
            "✓".bright_green().bold()
        )?;
    } else {
        let mut current_det = String::new();
        for f in &report.findings {
            if f.detector != current_det {
                current_det = f.detector.clone();
                writeln!(out)?;
                writeln!(
                    out,
                    "  {}",
                    format!("▸ {}", current_det.to_ascii_uppercase())
                        .bold()
                        .bright_magenta()
                )?;
                writeln!(
                    out,
                    "  {}",
                    "────────────────────────────────────────".dimmed()
                )?;
            }
            print_finding(&mut out, f)?;
        }
    }

    if !report.next_steps.is_empty() {
        writeln!(out)?;
        writeln!(out, "  {}", "NEXT STEPS".bold().bright_yellow())?;
        for (i, step) in report.next_steps.iter().enumerate() {
            writeln!(out, "  {}. {}", i + 1, step)?;
        }
    }

    writeln!(out)?;
    writeln!(
        out,
        "  {}",
        "exit: 0 clean/low · 1 policy fail · 2 tool error".dimmed()
    )?;
    writeln!(out)?;
    Ok(())
}

fn print_score_bar(out: &mut impl Write, score: u8) -> Result<()> {
    let filled = (score as usize) / 5;
    let empty = 20 - filled;
    let bar: String = format!("{}{}", "█".repeat(filled), "░".repeat(empty));
    let colored = if score >= 85 {
        bar.bright_green().to_string()
    } else if score >= 60 {
        bar.bright_yellow().to_string()
    } else {
        bar.bright_red().to_string()
    };
    writeln!(
        out,
        "  {}  {}  {}",
        "score".dimmed(),
        format!("{score:>3}").bold(),
        colored
    )?;
    Ok(())
}

fn print_summary_badges(out: &mut impl Write, report: &ScanReport) -> Result<()> {
    let s = &report.summary;
    write!(out, "  ")?;
    badge(out, "CRIT", s.critical, FindingSeverity::Critical)?;
    write!(out, " ")?;
    badge(out, "HIGH", s.high, FindingSeverity::High)?;
    write!(out, " ")?;
    badge(out, "MED", s.medium, FindingSeverity::Medium)?;
    write!(out, " ")?;
    badge(out, "LOW", s.low, FindingSeverity::Low)?;
    write!(out, " ")?;
    badge(out, "INFO", s.info, FindingSeverity::Info)?;
    writeln!(out)?;
    Ok(())
}

fn badge(out: &mut impl Write, label: &str, count: usize, sev: FindingSeverity) -> Result<()> {
    let text = format!(" {label} {count} ");
    let painted = match sev {
        FindingSeverity::Critical => {
            if count > 0 {
                text.on_bright_red().bright_white().bold().to_string()
            } else {
                text.dimmed().to_string()
            }
        }
        FindingSeverity::High => {
            if count > 0 {
                text.on_red().bright_white().bold().to_string()
            } else {
                text.dimmed().to_string()
            }
        }
        FindingSeverity::Medium => {
            if count > 0 {
                text.on_yellow().black().bold().to_string()
            } else {
                text.dimmed().to_string()
            }
        }
        FindingSeverity::Low => {
            if count > 0 {
                text.on_bright_blue().bright_white().to_string()
            } else {
                text.dimmed().to_string()
            }
        }
        FindingSeverity::Info => {
            if count > 0 {
                text.on_bright_black().bright_white().to_string()
            } else {
                text.dimmed().to_string()
            }
        }
    };
    write!(out, "{painted}")?;
    Ok(())
}

fn print_finding(out: &mut impl Write, f: &Finding) -> Result<()> {
    let sev = severity_badge(f.severity);
    writeln!(out, "  {sev}  {}", f.title.bold())?;
    writeln!(out, "         {}", f.message)?;
    if let Some(file) = &f.file {
        let loc = match f.line {
            Some(n) => format!("{}:{n}", file.display()),
            None => file.display().to_string(),
        };
        writeln!(out, "         {} {}", "at".dimmed(), loc.cyan())?;
    }
    if let Some(ev) = &f.evidence {
        writeln!(out, "         {} {}", "evidence".dimmed(), ev.dimmed())?;
    }
    if let Some(fix) = &f.remediation {
        writeln!(out, "         {} {}", "fix".dimmed(), fix)?;
    }
    Ok(())
}

fn severity_badge(sev: FindingSeverity) -> String {
    let label = format!(" {:<8} ", sev.as_str().to_ascii_uppercase());
    match sev {
        FindingSeverity::Critical => label.on_bright_red().bright_white().bold().to_string(),
        FindingSeverity::High => label.on_red().bright_white().bold().to_string(),
        FindingSeverity::Medium => label.on_yellow().black().bold().to_string(),
        FindingSeverity::Low => label.on_bright_blue().bright_white().to_string(),
        FindingSeverity::Info => label.on_bright_black().bright_white().to_string(),
    }
}
