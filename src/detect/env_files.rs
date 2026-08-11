use anyhow::Result;
use std::path::{Path, PathBuf};

use crate::scan::rel_display;
use crate::{Finding, FindingSeverity};

const SENSITIVE_NAMES: &[&str] = &[
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".env.staging",
    "credentials.json",
    "credentials.csv",
    "service-account.json",
    "serviceAccount.json",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    ".npmrc",
    ".pypirc",
    "secrets.yaml",
    "secrets.yml",
    "kubeconfig",
];

pub fn scan(root: &Path, files: &[PathBuf]) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    for path in files {
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let lower = name.to_ascii_lowercase();

        let matched = SENSITIVE_NAMES
            .iter()
            .any(|n| name == *n || lower == n.to_ascii_lowercase());

        let looks_like_env = lower.starts_with(".env")
            && !lower.ends_with(".example")
            && !lower.ends_with(".sample")
            && !lower.ends_with(".template");
        let looks_like_pem = lower.ends_with(".pem")
            || lower.ends_with(".key")
            || lower.ends_with(".p12")
            || lower.ends_with(".pfx");

        if matched || looks_like_env || looks_like_pem {
            let sev = if lower.contains("id_rsa")
                || lower.ends_with(".pem")
                || lower.ends_with(".key")
                || lower.contains("service-account")
                || lower.contains("credentials")
            {
                FindingSeverity::High
            } else {
                FindingSeverity::Medium
            };

            findings.push(Finding {
                id: format!("env-files/{}", rel_display(root, path).display()),
                detector: "env_files".into(),
                severity: sev,
                title: "Credential / env file present".into(),
                message: format!(
                    "Sensitive-looking file committed or present: {}",
                    rel_display(root, path).display()
                ),
                file: Some(rel_display(root, path)),
                line: None,
                evidence: Some(name.to_string()),
                remediation: Some(
                    "Ensure secrets are gitignored, use `.env.example` templates, and load real values from a secret manager."
                        .into(),
                ),
            });
        }
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn finds_dotenv() {
        let dir = tempdir().unwrap();
        let f = dir.path().join(".env");
        fs::write(&f, "FOO=1\n").unwrap();
        let findings = scan(dir.path(), &[f]).unwrap();
        assert_eq!(findings.len(), 1);
    }
}
