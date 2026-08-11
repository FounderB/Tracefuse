use anyhow::Result;
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};

use crate::scan::rel_display;
use crate::{Finding, FindingSeverity};

pub fn scan(root: &Path, files: &[PathBuf]) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let from_latest = Regex::new(r"(?i)^\s*FROM\s+(\S+:latest|\S+)").unwrap();
    let env_secret =
        Regex::new(r"(?i)^\s*ENV\s+.*(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)\s*=").unwrap();
    let add_http = Regex::new(r"(?i)^\s*ADD\s+https?://").unwrap();
    let privileged = Regex::new(r"(?i)--privileged|^\s*USER\s+0\b|^\s*USER\s+root\b").unwrap();
    let curl_pipe = Regex::new(r"(?i)(curl|wget).*\|\s*(ba)?sh").unwrap();

    for path in files {
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let lower = name.to_ascii_lowercase();
        if !(lower == "dockerfile"
            || lower.starts_with("dockerfile.")
            || lower.ends_with(".dockerfile"))
        {
            continue;
        }
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };

        for (lineno, line) in text.lines().enumerate() {
            let line_no = lineno + 1;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if let Some(caps) = from_latest.captures(line) {
                let image = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                if image.ends_with(":latest")
                    || (!image.contains(':') && !image.starts_with("scratch"))
                {
                    // untagged or :latest
                    let sev = if image.ends_with(":latest") {
                        FindingSeverity::Medium
                    } else if image.contains('/')
                        || image == "ubuntu"
                        || image == "node"
                        || image == "python"
                        || image == "alpine"
                        || image == "debian"
                    {
                        FindingSeverity::Low
                    } else {
                        continue;
                    };
                    findings.push(Finding {
                        id: format!(
                            "dockerfile/latest/{}:{}",
                            rel_display(root, path).display(),
                            line_no
                        ),
                        detector: "dockerfile".into(),
                        severity: sev,
                        title: "Unpinned or :latest base image".into(),
                        message: format!(
                            "FROM uses floating tag `{image}` — builds are not reproducible"
                        ),
                        file: Some(rel_display(root, path)),
                        line: Some(line_no),
                        evidence: Some(trimmed.to_string()),
                        remediation: Some(
                            "Pin to a digest (`image@sha256:…`) or immutable version tag.".into(),
                        ),
                    });
                }
            }

            if env_secret.is_match(line) {
                findings.push(Finding {
                    id: format!(
                        "dockerfile/env-secret/{}:{}",
                        rel_display(root, path).display(),
                        line_no
                    ),
                    detector: "dockerfile".into(),
                    severity: FindingSeverity::High,
                    title: "Secret-like value in ENV".into(),
                    message: "Dockerfile ENV appears to embed a credential".into(),
                    file: Some(rel_display(root, path)),
                    line: Some(line_no),
                    evidence: Some(redact_env_line(trimmed)),
                    remediation: Some(
                        "Pass secrets at runtime via orchestrator secrets / BuildKit secret mounts — never bake them into layers."
                            .into(),
                    ),
                });
            }

            if add_http.is_match(line) {
                findings.push(Finding {
                    id: format!(
                        "dockerfile/add-http/{}:{}",
                        rel_display(root, path).display(),
                        line_no
                    ),
                    detector: "dockerfile".into(),
                    severity: FindingSeverity::Medium,
                    title: "ADD from remote HTTP(S)".into(),
                    message: "ADD fetching remote content is opaque and hard to verify".into(),
                    file: Some(rel_display(root, path)),
                    line: Some(line_no),
                    evidence: Some(trimmed.to_string()),
                    remediation: Some(
                        "Prefer COPY of vendored artifacts, or curl with checksum verification in a RUN step."
                            .into(),
                    ),
                });
            }

            if privileged.is_match(line) {
                findings.push(Finding {
                    id: format!(
                        "dockerfile/privileged/{}:{}",
                        rel_display(root, path).display(),
                        line_no
                    ),
                    detector: "dockerfile".into(),
                    severity: FindingSeverity::Medium,
                    title: "Privileged / root container pattern".into(),
                    message: "Dockerfile hints at root or privileged execution".into(),
                    file: Some(rel_display(root, path)),
                    line: Some(line_no),
                    evidence: Some(trimmed.to_string()),
                    remediation: Some(
                        "Run as a non-root USER and avoid --privileged unless absolutely required."
                            .into(),
                    ),
                });
            }

            if curl_pipe.is_match(line) {
                findings.push(Finding {
                    id: format!(
                        "dockerfile/curl-pipe-shell/{}:{}",
                        rel_display(root, path).display(),
                        line_no
                    ),
                    detector: "dockerfile".into(),
                    severity: FindingSeverity::High,
                    title: "curl|sh in Dockerfile RUN".into(),
                    message: "Dockerfile pipes remote content into a shell during build".into(),
                    file: Some(rel_display(root, path)),
                    line: Some(line_no),
                    evidence: Some(trimmed.to_string()),
                    remediation: Some(
                        "Vendor installers and verify checksums/signatures — never curl|sh in image builds."
                            .into(),
                    ),
                });
            }
        }
    }

    Ok(findings)
}

fn redact_env_line(line: &str) -> String {
    if let Some(idx) = line.find('=') {
        let (left, right) = line.split_at(idx + 1);
        format!("{left}***REDACTED*** (len={})", right.len())
    } else {
        line.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn detects_latest_and_env_secret() {
        let dir = tempdir().unwrap();
        let df = dir.path().join("Dockerfile");
        fs::write(
            &df,
            "FROM node:latest\nENV API_SECRET=supersecretvalue\nUSER root\nRUN curl -fsSL https://example.invalid/i.sh | sh\n",
        )
        .unwrap();
        let findings = scan(dir.path(), &[df]).unwrap();
        assert!(findings.iter().any(|f| f.title.contains("latest")));
        assert!(findings.iter().any(|f| f.title.contains("ENV")));
        assert!(findings.iter().any(|f| f.title.contains("curl|sh")));
        assert!(findings
            .iter()
            .filter(|f| f.title.contains("ENV"))
            .all(|f| !f
                .evidence
                .as_deref()
                .unwrap_or("")
                .contains("supersecretvalue")));
    }
}
