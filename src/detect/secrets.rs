use anyhow::Result;
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::config::Config;
use crate::redact_secret;
use crate::scan::rel_display;
use crate::{Finding, FindingSeverity};

fn patterns() -> &'static Vec<(Regex, &'static str, FindingSeverity)> {
    static P: OnceLock<Vec<(Regex, &'static str, FindingSeverity)>> = OnceLock::new();
    P.get_or_init(|| {
        vec![
            (
                Regex::new(r"(?i)-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----").unwrap(),
                "Private key material",
                FindingSeverity::Critical,
            ),
            (
                Regex::new(r"(?i)\b(?:AKIA|ASIA)[0-9A-Z]{16}\b").unwrap(),
                "AWS access key id",
                FindingSeverity::Critical,
            ),
            (
                Regex::new(r"(?i)\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b").unwrap(),
                "GitHub personal access token",
                FindingSeverity::Critical,
            ),
            (
                Regex::new(r"(?i)\bgithub_pat_[A-Za-z0-9_]{20,}\b").unwrap(),
                "GitHub fine-grained PAT",
                FindingSeverity::Critical,
            ),
            (
                Regex::new(r"(?i)\bsk_live_[A-Za-z0-9]{16,}\b").unwrap(),
                "Stripe live secret key",
                FindingSeverity::Critical,
            ),
            (
                Regex::new(r"(?i)\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b").unwrap(),
                "OpenAI-style API key",
                FindingSeverity::High,
            ),
            (
                Regex::new(r"(?i)\bxox[baprs]-[A-Za-z0-9-]{10,}\b").unwrap(),
                "Slack token",
                FindingSeverity::High,
            ),
            (
                Regex::new(
                    r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
                )
                .unwrap(),
                "Slack incoming webhook",
                FindingSeverity::High,
            ),
            (
                // EXAMPLE shape only — 39 chars after AIza
                Regex::new(r"(?i)\bAIza[0-9A-Za-z\-_]{35}\b").unwrap(),
                "GCP API key",
                FindingSeverity::High,
            ),
            (
                Regex::new(
                    r#"(?i)(?:api[_-]?key|secret|token|password)\s*[=:]\s*['\"]([^'\"]{12,})['\"]"#,
                )
                .unwrap(),
                "Hard-coded credential assignment",
                FindingSeverity::High,
            ),
        ]
    })
}

/// High-entropy token heuristic (base64-ish / hex-ish long strings).
fn entropy_suspect(line: &str) -> Option<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:secret|token|password|api[_-]?key|auth)\s*[=:]\s*['\"]?([A-Za-z0-9+/=_\-]{28,})['\"]?"#,
        )
        .expect("entropy regex")
    });
    re.captures(line)
        .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
}

pub fn scan(root: &Path, files: &[PathBuf], _cfg: &Config) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let skip_ext = [
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".woff", ".woff2", ".pdf", ".zip", ".gz",
        ".tgz", ".lock",
    ];

    for path in files {
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let lower = name.to_ascii_lowercase();
        if skip_ext.iter().any(|e| lower.ends_with(e)) {
            continue;
        }
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        if content.chars().take(800).any(|c| c == '\0') {
            continue;
        }

        for (lineno, line) in content.lines().enumerate() {
            let line_no = lineno + 1;
            for (re, title, sev) in patterns().iter() {
                if let Some(m) = re.find(line) {
                    let evidence = redact_secret(m.as_str());
                    findings.push(Finding {
                        id: format!(
                            "secrets/{}/{}:{}",
                            title_slug(title),
                            rel_display(root, path).display(),
                            line_no
                        ),
                        detector: "secrets".into(),
                        severity: *sev,
                        title: (*title).into(),
                        message: format!(
                            "Possible secret detected in {}:{line_no}",
                            rel_display(root, path).display()
                        ),
                        file: Some(rel_display(root, path)),
                        line: Some(line_no),
                        evidence: Some(evidence),
                        remediation: Some(
                            "Remove the secret, rotate credentials, and load secrets from a vault or CI secret store."
                                .into(),
                        ),
                    });
                }
            }

            if let Some(tok) = entropy_suspect(line) {
                let already = findings.iter().any(|f| {
                    f.file.as_deref() == Some(rel_display(root, path).as_path())
                        && f.line == Some(line_no)
                        && f.detector == "secrets"
                });
                if !already && shannon_entropy(&tok) >= 3.5 {
                    findings.push(Finding {
                        id: format!(
                            "secrets/high-entropy/{}:{}",
                            rel_display(root, path).display(),
                            line_no
                        ),
                        detector: "secrets".into(),
                        severity: FindingSeverity::Medium,
                        title: "High-entropy credential-like value".into(),
                        message: format!(
                            "High-entropy token near a credential keyword in {}:{line_no}",
                            rel_display(root, path).display()
                        ),
                        file: Some(rel_display(root, path)),
                        line: Some(line_no),
                        evidence: Some(redact_secret(&tok)),
                        remediation: Some(
                            "Confirm whether this is a real secret; if so, rotate and remove from the repo."
                                .into(),
                        ),
                    });
                }
            }
        }
    }

    Ok(findings)
}

/// Apply `[[custom_rules]]` independently of the secrets detector toggle.
pub fn scan_custom(root: &Path, files: &[PathBuf], cfg: &Config) -> Result<Vec<Finding>> {
    if cfg.custom_rules.is_empty() {
        return Ok(Vec::new());
    }

    let mut findings = Vec::new();
    let skip_ext = [
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".woff", ".woff2", ".pdf", ".zip", ".gz",
        ".tgz", ".lock",
    ];

    for path in files {
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let lower = name.to_ascii_lowercase();
        if skip_ext.iter().any(|e| lower.ends_with(e)) {
            continue;
        }
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        if content.chars().take(800).any(|c| c == '\0') {
            continue;
        }

        for (lineno, line) in content.lines().enumerate() {
            let line_no = lineno + 1;
            for rule in &cfg.custom_rules {
                if let Some(needle) = rule.path_contains.as_deref() {
                    let rel = rel_display(root, path);
                    if !rel.to_string_lossy().contains(needle) {
                        continue;
                    }
                }
                let Ok(re) = Regex::new(&rule.pattern) else {
                    continue;
                };
                if let Some(m) = re.find(line) {
                    findings.push(Finding {
                        id: format!(
                            "custom/{}/{}:{}",
                            rule.id,
                            rel_display(root, path).display(),
                            line_no
                        ),
                        detector: "custom".into(),
                        severity: rule.severity,
                        title: rule.title.clone(),
                        message: format!(
                            "Custom rule `{}` matched in {}:{line_no}",
                            rule.id,
                            rel_display(root, path).display()
                        ),
                        file: Some(rel_display(root, path)),
                        line: Some(line_no),
                        evidence: Some(redact_secret(m.as_str())),
                        remediation: Some(
                            "Review the match; tune or remove the custom rule if it is a false positive."
                                .into(),
                        ),
                    });
                }
            }
        }
    }

    Ok(findings)
}

fn title_slug(s: &str) -> String {
    s.to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

fn shannon_entropy(s: &str) -> f64 {
    let mut freq = [0u32; 256];
    let bytes = s.as_bytes();
    for &b in bytes {
        freq[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    if len == 0.0 {
        return 0.0;
    }
    let mut h = 0.0;
    for &c in &freq {
        if c == 0 {
            continue;
        }
        let p = c as f64 / len;
        h -= p * p.log2();
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use tempfile::tempdir;

    #[test]
    fn detects_aws_key() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("cfg.env");
        // Fake EXAMPLE key shape
        fs::write(&f, "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n").unwrap();
        let files = vec![f];
        let findings = scan(dir.path(), &files, &Config::default()).unwrap();
        assert!(findings.iter().any(|x| x.title.contains("AWS")));
        assert!(findings.iter().all(|x| {
            x.evidence
                .as_ref()
                .map(|e| !e.contains("IOSFODNN7EXAMPLE") || e.contains('…') || e.contains('*'))
                .unwrap_or(true)
        }));
    }

    #[test]
    fn detects_gcp_and_github_pat() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("keys.env");
        // FAKE / EXAMPLE fixtures only
        fs::write(
            &f,
            "GCP_KEY=AIzaSyA-FAKEEXAMPLEKEY00000000000000000\n\
             GH_FINE=github_pat_FAKEEXAMPLE_0000000000000000000000\n\
             SLACK_HOOK=https://hooks.slack.com/services/T00000000/B00000000/FAKEEXAMPLETTOKEN000\n",
        )
        .unwrap();
        let findings = scan(dir.path(), &[f], &Config::default()).unwrap();
        assert!(findings.iter().any(|x| x.title.contains("GCP")));
        assert!(findings.iter().any(|x| x.title.contains("fine-grained")));
        assert!(findings.iter().any(|x| x.title.contains("Slack incoming")));
        assert!(findings.iter().all(|f| {
            f.evidence
                .as_ref()
                .map(|e| !e.contains("FAKEEXAMPLEKEY00000000000000000"))
                .unwrap_or(true)
        }));
    }

    #[test]
    fn entropy_helper() {
        assert!(shannon_entropy("aaaaaaaa") < 1.0);
        assert!(shannon_entropy("aB3$_xY9QmLp2VwZ8") > 3.0);
    }

    #[test]
    fn custom_rules_run_without_builtin_secrets() {
        use crate::config::CustomRule;
        let dir = tempdir().unwrap();
        let f = dir.path().join("app.txt");
        fs::write(&f, "CORP_ABCDEFGHIJKLMNOPQRSTUVWX\n").unwrap();
        let mut cfg = Config::default();
        cfg.custom_rules.push(CustomRule {
            id: "corp-token".into(),
            title: "Corp internal token".into(),
            pattern: r"(?i)\bCORP_[A-Z0-9]{24}\b".into(),
            severity: FindingSeverity::High,
            path_contains: None,
        });
        // Builtin secrets scan would not match CORP_*; custom rules still fire
        let custom = scan_custom(dir.path(), &[f], &cfg).unwrap();
        assert!(custom
            .iter()
            .any(|x| x.detector == "custom" && x.id.contains("corp-token")));
    }
}
