use anyhow::Result;
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};

use crate::redact_secret;
use crate::scan::rel_display;
use crate::{Finding, FindingSeverity};

pub fn scan(root: &Path, files: &[PathBuf]) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let curl_bash = Regex::new(r"(?i)(curl|wget).*\|\s*(ba)?sh").unwrap();
    let pr_target = Regex::new(r"(?i)pull_request_target").unwrap();
    let id_token_write = Regex::new(r"(?i)id-token\s*:\s*write").unwrap();
    let write_all = Regex::new(r"(?i)permissions\s*:\s*write-all").unwrap();
    let plaintext_secret = Regex::new(
        r#"(?i)^\s*(?:[A-Z0-9_]*)?(?:SECRET|TOKEN|PASSWORD|API_KEY)\s*:\s*['\"]?[^\s'\"$#\{][^'\"\n]{6,}"#,
    )
    .unwrap();
    let env_secret_assign = Regex::new(
        r#"(?i)^\s*[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|API_KEY)\s*:\s*['\"]([^'\"\n]{8,})['\"]"#,
    )
    .unwrap();

    for path in files {
        if !is_workflow(root, path) {
            continue;
        }
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };

        let has_pr_target = pr_target.is_match(&text);
        let has_id_token = id_token_write.is_match(&text);
        let has_write_all = write_all.is_match(&text);

        // File-level OIDC misuse: id-token: write with dangerous context
        if has_id_token && (has_pr_target || has_write_all) {
            findings.push(Finding {
                id: format!("ci/oidc-misuse/{}", rel_display(root, path).display()),
                detector: "ci".into(),
                severity: FindingSeverity::High,
                title: "OIDC / id-token misuse pattern".into(),
                message: if has_pr_target {
                    "Workflow combines `id-token: write` with `pull_request_target` — untrusted PRs may mint cloud creds"
                        .into()
                } else {
                    "Workflow combines `id-token: write` with `permissions: write-all` — OIDC tokens with over-broad job perms"
                        .into()
                },
                file: Some(rel_display(root, path)),
                line: None,
                evidence: Some("id-token: write + risky trigger/permissions".into()),
                remediation: Some(
                    "Use least-privilege permissions, pin OIDC audiences, and never mint tokens on pull_request_target with untrusted checkout."
                        .into(),
                ),
            });
        } else if has_write_all {
            findings.push(Finding {
                id: format!("ci/write-all/{}", rel_display(root, path).display()),
                detector: "ci".into(),
                severity: FindingSeverity::Medium,
                title: "permissions: write-all".into(),
                message: "Workflow grants write-all permissions — prefer least privilege".into(),
                file: Some(rel_display(root, path)),
                line: None,
                evidence: Some("permissions: write-all".into()),
                remediation: Some(
                    "Enumerate only the permissions the job needs (contents: read, …).".into(),
                ),
            });
        }

        for (lineno, line) in text.lines().enumerate() {
            let line_no = lineno + 1;
            let trimmed = line.trim();

            if pr_target.is_match(line) {
                findings.push(Finding {
                    id: format!(
                        "ci/pull-request-target/{}:{}",
                        rel_display(root, path).display(),
                        line_no
                    ),
                    detector: "ci".into(),
                    severity: FindingSeverity::High,
                    title: "pull_request_target trigger".into(),
                    message: "Workflow uses pull_request_target — fork PRs can access secrets if checkout is misused"
                        .into(),
                    file: Some(rel_display(root, path)),
                    line: Some(line_no),
                    evidence: Some(trimmed.to_string()),
                    remediation: Some(
                        "Prefer `pull_request`. If you must use pull_request_target, never checkout untrusted code with write secrets."
                            .into(),
                    ),
                });
            }

            if curl_bash.is_match(line) {
                findings.push(Finding {
                    id: format!(
                        "ci/curl-bash/{}:{}",
                        rel_display(root, path).display(),
                        line_no
                    ),
                    detector: "ci".into(),
                    severity: FindingSeverity::High,
                    title: "curl|bash in CI workflow".into(),
                    message: "Workflow pipes remote content into a shell".into(),
                    file: Some(rel_display(root, path)),
                    line: Some(line_no),
                    evidence: Some(trimmed.to_string()),
                    remediation: Some(
                        "Pin actions by SHA, verify checksums, avoid piping curl to bash.".into(),
                    ),
                });
            }

            if let Some(caps) = env_secret_assign.captures(line) {
                let val = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                if val.contains("${{") {
                    continue;
                }
                findings.push(Finding {
                    id: format!(
                        "ci/plaintext-secret/{}:{}",
                        rel_display(root, path).display(),
                        line_no
                    ),
                    detector: "ci".into(),
                    severity: FindingSeverity::Critical,
                    title: "Plaintext secret in workflow env".into(),
                    message: "Workflow embeds a secret-like value in plaintext".into(),
                    file: Some(rel_display(root, path)),
                    line: Some(line_no),
                    evidence: Some(format!(
                        "{}:{}",
                        line.split(':').next().unwrap_or("ENV").trim(),
                        redact_secret(val)
                    )),
                    remediation: Some(
                        "Move the value to GitHub Actions secrets / OIDC — never commit plaintext credentials."
                            .into(),
                    ),
                });
            } else if plaintext_secret.is_match(line) && !line.contains("${{") {
                findings.push(Finding {
                    id: format!(
                        "ci/plaintext-secret-soft/{}:{}",
                        rel_display(root, path).display(),
                        line_no
                    ),
                    detector: "ci".into(),
                    severity: FindingSeverity::High,
                    title: "Possible plaintext secret in workflow".into(),
                    message:
                        "Workflow line looks like a secret assignment without ${{ secrets.* }}"
                            .into(),
                    file: Some(rel_display(root, path)),
                    line: Some(line_no),
                    evidence: Some("***REDACTED***".into()),
                    remediation: Some(
                        "Use `${{ secrets.NAME }}` or environment secrets instead of literals."
                            .into(),
                    ),
                });
            }
        }
    }

    Ok(findings)
}

fn is_workflow(root: &Path, path: &Path) -> bool {
    let rel = path.strip_prefix(root).unwrap_or(path);
    let s = rel.to_string_lossy().replace('\\', "/");
    (s.contains(".github/workflows/") || s.contains(".gitlab-ci"))
        && (s.ends_with(".yml") || s.ends_with(".yaml"))
        || path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n == ".gitlab-ci.yml" || n == "azure-pipelines.yml")
            .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn detects_pr_target_and_curl() {
        let dir = tempdir().unwrap();
        let wf_dir = dir.path().join(".github/workflows");
        fs::create_dir_all(&wf_dir).unwrap();
        let wf = wf_dir.join("ci.yml");
        fs::write(
            &wf,
            "on: pull_request_target\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl -fsSL https://x | bash\n",
        )
        .unwrap();
        let findings = scan(dir.path(), &[wf]).unwrap();
        assert!(findings
            .iter()
            .any(|f| f.title.contains("pull_request_target")));
        assert!(findings.iter().any(|f| f.title.contains("curl|bash")));
    }

    #[test]
    fn detects_oidc_with_pr_target() {
        let dir = tempdir().unwrap();
        let wf_dir = dir.path().join(".github/workflows");
        fs::create_dir_all(&wf_dir).unwrap();
        let wf = wf_dir.join("oidc.yml");
        fs::write(
            &wf,
            "on: pull_request_target\npermissions:\n  id-token: write\n  contents: read\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n",
        )
        .unwrap();
        let findings = scan(dir.path(), &[wf]).unwrap();
        assert!(findings.iter().any(|f| f.title.contains("OIDC")));
    }
}
