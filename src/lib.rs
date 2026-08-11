//! Tracefuse — supply-chain / pipeline truth scanner.
//!
//! Compares what a repository *declares* with what it *actually ships*:
//! secrets, risky scripts, lockfile drift, Dockerfile & CI smells, credential files,
//! and light dependency-risk heuristics — offline-first.

pub mod cli;
pub mod config;
pub mod detect;
pub mod report;
pub mod rules;
pub mod scan;

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;
use std::path::PathBuf;

/// Severity levels used across detectors and `--fail-on` policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl FindingSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn rank(self) -> u8 {
        match self {
            Self::Info => 0,
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Critical => 4,
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Some(Self::Info),
            "low" => Some(Self::Low),
            "medium" | "med" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" | "crit" => Some(Self::Critical),
            _ => None,
        }
    }
}

impl PartialOrd for FindingSeverity {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FindingSeverity {
    fn cmp(&self, other: &Self) -> Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A single scanner finding. Sensitive evidence is always redacted before emit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub detector: String,
    pub severity: FindingSeverity,
    pub title: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

/// Aggregate scan result for a project root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub tool: String,
    pub version: String,
    pub root: PathBuf,
    pub scanned_at: String,
    pub score: u8,
    pub summary: ScanSummary,
    pub findings: Vec<Finding>,
    pub next_steps: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl ScanSummary {
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut s = Self {
            total: findings.len(),
            ..Default::default()
        };
        for f in findings {
            match f.severity {
                FindingSeverity::Critical => s.critical += 1,
                FindingSeverity::High => s.high += 1,
                FindingSeverity::Medium => s.medium += 1,
                FindingSeverity::Low => s.low += 1,
                FindingSeverity::Info => s.info += 1,
            }
        }
        s
    }
}

/// Redact a secret-like string for safe display / JSON / SARIF.
///
/// Keeps a short prefix/suffix for triage; never returns the full secret.
pub fn redact_secret(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return "***".to_string();
    }
    // KEY=value — preserve the key name, redact the value.
    if let Some(idx) = trimmed.find('=') {
        let (left, right) = trimmed.split_at(idx + 1);
        let right_trim = right.trim().trim_matches(|c| c == '"' || c == '\'');
        if right_trim.chars().count() >= 8 {
            return format!("{left}{}", redact_body(right_trim));
        }
    }
    redact_body(trimmed)
}

fn redact_body(trimmed: &str) -> String {
    let chars: Vec<char> = trimmed.chars().collect();
    if chars.len() <= 8 {
        return "***".to_string();
    }
    if chars.len() <= 12 {
        return format!("{}…***", chars.iter().take(3).collect::<String>());
    }
    let prefix: String = chars.iter().take(4).collect();
    let suffix: String = chars[chars.len() - 4..].iter().collect();
    format!("{prefix}…{suffix}")
}

/// Scrub known secret shapes anywhere inside free-form evidence / messages.
pub fn redact_in_text(text: &str) -> String {
    use regex::Regex;
    use std::sync::OnceLock;

    static RES: OnceLock<Vec<Regex>> = OnceLock::new();
    let patterns = RES.get_or_init(|| {
        [
            r"(?i)-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
            r"(?i)\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
            r"(?i)\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b",
            r"(?i)\bgithub_pat_[A-Za-z0-9_]{20,}\b",
            r"(?i)\bsk_live_[A-Za-z0-9]{16,}\b",
            r"(?i)\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b",
            r"(?i)\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
            r"(?i)\bAIza[0-9A-Za-z\-_]{35}\b",
            r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
            r#"(?i)(?:aws_?)?secret_?access_?key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{30,}['\"]?"#,
        ]
        .into_iter()
        .map(|p| Regex::new(p).expect("redaction regex"))
        .collect()
    });

    let mut out = text.to_string();
    for re in patterns.iter() {
        out = re
            .replace_all(&out, |caps: &regex::Captures| {
                redact_secret(caps.get(0).unwrap().as_str())
            })
            .into_owned();
    }
    out
}

/// Final safety net before human / JSON / SARIF emit.
pub fn sanitize_findings(findings: &mut [Finding]) {
    for f in findings.iter_mut() {
        if let Some(ev) = f.evidence.take() {
            f.evidence = Some(redact_in_text(&ev));
        }
        let secret_ish = f.detector == "secrets"
            || f.title.to_ascii_lowercase().contains("secret")
            || f.title.to_ascii_lowercase().contains("token")
            || f.title.to_ascii_lowercase().contains("key");
        if secret_ish {
            f.message = redact_in_text(&f.message);
        }
    }
}

/// Compute a 0–100 health score (100 = clean).
pub fn compute_score(summary: &ScanSummary) -> u8 {
    let penalty = summary.critical * 35
        + summary.high * 18
        + summary.medium * 8
        + summary.low * 3
        + summary.info;
    100u32.saturating_sub(penalty as u32).min(100) as u8
}

pub fn build_next_steps(summary: &ScanSummary) -> Vec<String> {
    let mut steps = Vec::new();
    if summary.critical + summary.high > 0 {
        steps.push(
            "Rotate any exposed credentials immediately and purge them from git history.".into(),
        );
        steps.push(
            "Block high/critical findings in CI with `tracefuse scan --fail-on high`.".into(),
        );
    }
    if summary.medium > 0 {
        steps.push(
            "Pin image tags and remove curl|bash installers from package scripts & workflows."
                .into(),
        );
    }
    if summary.total == 0 {
        steps.push("No findings at current threshold — keep scanning on every PR.".into());
    } else {
        steps.push(
            "Re-run with `--json` or `--sarif out.sarif` to feed GitHub Code Scanning.".into(),
        );
        steps.push(
            "Tune ignore / severity_overrides in `.tracefuse.toml` after reviewing false positives."
                .into(),
        );
    }
    steps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_preserves_prefix_suffix() {
        let r = redact_secret("sk_live_abcdefghijklmnopqrstuvwxyz");
        assert!(r.starts_with("sk_l"));
        assert!(r.ends_with("wxyz") || r.contains('…'));
        assert!(!r.contains("abcdefghijklmnopqrstuvwxyz"));
    }

    #[test]
    fn redact_in_text_scrubs_aws() {
        let s = redact_in_text("key=AKIAIOSFODNN7EXAMPLE in log");
        assert!(!s.contains("IOSFODNN7EXAMPLE"));
        assert!(s.contains('…') || s.contains('*'));
    }

    #[test]
    fn score_drops_with_critical() {
        let s = ScanSummary {
            total: 1,
            critical: 1,
            ..Default::default()
        };
        assert!(compute_score(&s) < 70);
    }

    #[test]
    fn severity_ordering() {
        assert!(FindingSeverity::Critical > FindingSeverity::High);
        assert!(FindingSeverity::Medium > FindingSeverity::Low);
    }
}
