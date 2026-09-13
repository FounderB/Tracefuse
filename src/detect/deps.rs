use anyhow::Result;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

use crate::scan::rel_display;
use crate::{Finding, FindingSeverity};

/// Light dependency risk heuristics: known dangerous patterns + typosquat-ish names.
pub fn scan(root: &Path, files: &[PathBuf]) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

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

        for section in ["dependencies", "devDependencies", "optionalDependencies"] {
            let Some(obj) = v.get(section).and_then(|x| x.as_object()) else {
                continue;
            };
            for (pkg, ver) in obj {
                let ver_s = ver.as_str().unwrap_or("");
                check_package(root, path, pkg, ver_s, &mut findings);
            }
        }
    }

    Ok(findings)
}

fn check_package(root: &Path, path: &Path, pkg: &str, ver: &str, findings: &mut Vec<Finding>) {
    let lower = pkg.to_ascii_lowercase();

    // ua-parser-js was historically compromised (2021) — flag only known-bad versions, not all uses
    if lower == "ua-parser-js" {
        if is_weird_ua_parser_version(ver) {
            findings.push(Finding {
                id: format!("deps/dangerous/{pkg}"),
                detector: "deps".into(),
                severity: FindingSeverity::High,
                title: format!("Compromised ua-parser-js version: {pkg}@{ver}"),
                message: format!(
                    "Dependency `{pkg}@{ver}` matches a historically compromised ua-parser-js release"
                ),
                file: Some(rel_display(root, path)),
                line: None,
                evidence: Some(format!("{pkg}@{ver}")),
                remediation: Some(
                    "Pin to a patched release (e.g. ≥0.7.30 / ≥0.8.1 / ≥1.0.1) and audit the lockfile."
                        .into(),
                ),
            });
        }
        return;
    }

    // Known dangerous / joke malware-ish patterns often used in demos & real incidents
    const DANGEROUS: &[&str] = &[
        "event-stream",
        "flatmap-stream",
        "crossenv",
        "cross-env.js",
        "electorn",
        "lodahs",
        "reac",
        "expresss",
        "mongose",
        "colour-name", // typosquat-ish of color
    ];

    if DANGEROUS.contains(&lower.as_str())
        || lower.contains("discord-token")
        || lower.starts_with("@malicious/")
        || lower.ends_with("-trojan")
    {
        findings.push(Finding {
            id: format!("deps/dangerous/{pkg}"),
            detector: "deps".into(),
            severity: FindingSeverity::High,
            title: format!("Risky / known-bad dependency pattern: {pkg}"),
            message: format!("Dependency `{pkg}@{ver}` matches a high-risk name heuristic"),
            file: Some(rel_display(root, path)),
            line: None,
            evidence: Some(format!("{pkg}@{ver}")),
            remediation: Some(
                "Remove the package, audit install scripts, and verify the intended package name on the registry."
                    .into(),
            ),
        });
        return;
    }

    // Typosquat-ish: common packages with one-edit lookalikes
    const POPULAR: &[&str] = &[
        "react",
        "lodash",
        "express",
        "axios",
        "webpack",
        "typescript",
        "jquery",
        "moment",
        "request",
        "chalk",
        "commander",
        "debug",
        "fs-extra",
        "uuid",
        "dotenv",
    ];

    for popular in POPULAR {
        if lower == *popular {
            continue;
        }
        if is_typosquatish(&lower, popular) {
            findings.push(Finding {
                id: format!("deps/typosquat/{pkg}"),
                detector: "deps".into(),
                severity: FindingSeverity::Medium,
                title: format!("Possible typosquat of `{popular}`: {pkg}"),
                message: format!(
                    "`{pkg}` is unusually close to popular package `{popular}` — verify intent"
                ),
                file: Some(rel_display(root, path)),
                line: None,
                evidence: Some(format!("{pkg}@{ver}")),
                remediation: Some(
                    "Confirm the package name spelling against the official registry listing."
                        .into(),
                ),
            });
            break;
        }
    }

    // Install from git/http without pin
    if ver.starts_with("git+")
        || ver.starts_with("http://")
        || ver.starts_with("https://")
        || ver.contains("github:")
    {
        findings.push(Finding {
            id: format!("deps/remote/{pkg}"),
            detector: "deps".into(),
            severity: FindingSeverity::Low,
            title: format!("Remote URL dependency: {pkg}"),
            message: format!("`{pkg}` is resolved from a remote URL ({ver})"),
            file: Some(rel_display(root, path)),
            line: None,
            evidence: Some(format!("{pkg}@{ver}")),
            remediation: Some(
                "Prefer registry versions with lockfile pins; if git is required, pin a commit SHA."
                    .into(),
            ),
        });
    }
}

/// Known malicious ua-parser-js releases from the 2021 npm account compromise.
fn is_weird_ua_parser_version(ver: &str) -> bool {
    const BAD: &[&str] = &["0.7.29", "0.8.0", "1.0.0"];
    let base = normalize_npm_version(ver);
    BAD.contains(&base.as_str())
}

fn normalize_npm_version(ver: &str) -> String {
    let mut s = ver.trim().trim_start_matches(['v', 'V']);
    // Strip range / comparator prefixes (^, ~, >=, <=, >, <, =)
    loop {
        let next = s
            .trim_start()
            .trim_start_matches(['^', '~', '=', '>', '<', ' ']);
        if next == s {
            break;
        }
        s = next;
    }
    s.split(|c: char| c.is_whitespace() || c == '|' || c == ',')
        .next()
        .unwrap_or(s)
        .trim()
        .to_string()
}

fn is_typosquatish(candidate: &str, popular: &str) -> bool {
    if candidate.len().abs_diff(popular.len()) > 1 {
        return false;
    }
    let dist = levenshtein(candidate, popular);
    dist == 1
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0; b.len() + 1];
    for i in 1..=a.len() {
        cur[0] = i;
        for j in 1..=b.len() {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn typosquat_lodahs() {
        let dir = tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        fs::write(&pkg, r#"{"name":"x","dependencies":{"lodahs":"1.0.0"}}"#).unwrap();
        let findings = scan(dir.path(), &[pkg]).unwrap();
        assert!(findings.iter().any(|f| f.detector == "deps"));
    }

    #[test]
    fn levenshtein_basic() {
        assert_eq!(levenshtein("react", "reacr"), 1);
        assert_eq!(levenshtein("lodash", "lodahs"), 2);
        assert_eq!(levenshtein("react", "react"), 0);
    }

    #[test]
    fn ua_parser_js_flags_only_compromised_versions() {
        let dir = tempdir().unwrap();
        let bad = dir.path().join("package.json");
        fs::write(
            &bad,
            r#"{"name":"x","dependencies":{"ua-parser-js":"0.7.29"}}"#,
        )
        .unwrap();
        let findings = scan(dir.path(), &[bad]).unwrap();
        assert!(findings.iter().any(|f| f.id.contains("ua-parser-js")));

        let ok_pkg = dir.path().join("pkg");
        fs::create_dir_all(&ok_pkg).unwrap();
        let ok_path = ok_pkg.join("package.json");
        fs::write(
            &ok_path,
            r#"{"name":"x","dependencies":{"ua-parser-js":"^1.0.37"}}"#,
        )
        .unwrap();
        let findings_ok = scan(dir.path(), &[ok_path]).unwrap();
        assert!(!findings_ok
            .iter()
            .any(|f| f.id.contains("ua-parser-js") || f.title.contains("ua-parser-js")));
    }
}
