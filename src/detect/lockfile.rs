use anyhow::Result;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::scan::rel_display;
use crate::{Finding, FindingSeverity};

pub fn scan(root: &Path, files: &[PathBuf]) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    // npm: package.json vs package-lock.json / yarn.lock / pnpm-lock.yaml
    let pkg = files.iter().find(|p| {
        p.file_name().and_then(|s| s.to_str()) == Some("package.json") && p.parent() == Some(root)
    });
    if let Some(pkg) = pkg {
        let has_lock = files.iter().any(|p| {
            matches!(
                p.file_name().and_then(|s| s.to_str()),
                Some("package-lock.json" | "yarn.lock" | "pnpm-lock.yaml" | "npm-shrinkwrap.json")
            ) && p.parent() == Some(root)
        });
        if !has_lock {
            findings.push(Finding {
                id: "lockfile/npm-missing".into(),
                detector: "lockfile".into(),
                severity: FindingSeverity::Medium,
                title: "package.json without a lockfile".into(),
                message: "Manifest present but no package-lock.json / yarn.lock / pnpm-lock.yaml — installs are non-reproducible".into(),
                file: Some(rel_display(root, pkg)),
                line: None,
                evidence: None,
                remediation: Some(
                    "Commit a lockfile and install with `npm ci` / `yarn --frozen-lockfile` / `pnpm i --frozen-lockfile`."
                        .into(),
                ),
            });
        } else if let Some(lock) = files.iter().find(|p| {
            p.file_name().and_then(|s| s.to_str()) == Some("package-lock.json")
                && p.parent() == Some(root)
        }) {
            findings.extend(npm_drift(root, pkg, lock)?);
        }
    }

    // Cargo.toml vs Cargo.lock
    let cargo_toml = files.iter().find(|p| {
        p.file_name().and_then(|s| s.to_str()) == Some("Cargo.toml") && p.parent() == Some(root)
    });
    if let Some(manifest) = cargo_toml {
        let has_lock = files.iter().any(|p| {
            p.file_name().and_then(|s| s.to_str()) == Some("Cargo.lock") && p.parent() == Some(root)
        });
        let is_bin_or_app = fs::read_to_string(manifest)
            .map(|t| t.contains("[[bin]]") || t.contains("[package]"))
            .unwrap_or(false);
        if is_bin_or_app && !has_lock {
            findings.push(Finding {
                id: "lockfile/cargo-missing".into(),
                detector: "lockfile".into(),
                severity: FindingSeverity::Low,
                title: "Cargo.toml without Cargo.lock".into(),
                message: "Application crate should commit Cargo.lock for reproducible builds"
                    .into(),
                file: Some(rel_display(root, manifest)),
                line: None,
                evidence: None,
                remediation: Some("Run `cargo generate-lockfile` and commit Cargo.lock.".into()),
            });
        }
    }

    // go.mod vs go.sum
    let gomod = files.iter().find(|p| {
        p.file_name().and_then(|s| s.to_str()) == Some("go.mod") && p.parent() == Some(root)
    });
    if let Some(gomod) = gomod {
        let has_sum = files.iter().any(|p| {
            p.file_name().and_then(|s| s.to_str()) == Some("go.sum") && p.parent() == Some(root)
        });
        if !has_sum {
            findings.push(Finding {
                id: "lockfile/go-missing-sum".into(),
                detector: "lockfile".into(),
                severity: FindingSeverity::Medium,
                title: "go.mod without go.sum".into(),
                message: "Go module present but go.sum missing — dependency digests are unverified"
                    .into(),
                file: Some(rel_display(root, gomod)),
                line: None,
                evidence: None,
                remediation: Some("Run `go mod tidy` and commit go.sum.".into()),
            });
        }
    }

    Ok(findings)
}

fn npm_drift(root: &Path, pkg: &Path, lock: &Path) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let pkg_text = fs::read_to_string(pkg)?;
    let lock_text = fs::read_to_string(lock)?;
    let Ok(pkg_v) = serde_json::from_str::<Value>(&pkg_text) else {
        return Ok(findings);
    };
    let Ok(lock_v) = serde_json::from_str::<Value>(&lock_text) else {
        return Ok(findings);
    };

    let mut declared = BTreeSet::new();
    for key in ["dependencies", "devDependencies", "optionalDependencies"] {
        if let Some(obj) = pkg_v.get(key).and_then(|v| v.as_object()) {
            for name in obj.keys() {
                declared.insert(name.clone());
            }
        }
    }

    // package-lock v2/v3: packages[""].dependencies + packages entries
    let mut locked = BTreeSet::new();
    if let Some(packages) = lock_v.get("packages").and_then(|p| p.as_object()) {
        if let Some(root_pkg) = packages.get("") {
            for key in ["dependencies", "devDependencies", "optionalDependencies"] {
                if let Some(obj) = root_pkg.get(key).and_then(|v| v.as_object()) {
                    for name in obj.keys() {
                        locked.insert(name.clone());
                    }
                }
            }
        }
    }
    if locked.is_empty() {
        if let Some(deps) = lock_v.get("dependencies").and_then(|d| d.as_object()) {
            for name in deps.keys() {
                locked.insert(name.clone());
            }
        }
    }

    if locked.is_empty() {
        return Ok(findings);
    }

    let missing: Vec<_> = declared.difference(&locked).cloned().collect();
    if !missing.is_empty() {
        let sample: Vec<_> = missing.iter().take(5).cloned().collect();
        findings.push(Finding {
            id: "lockfile/npm-drift".into(),
            detector: "lockfile".into(),
            severity: FindingSeverity::Medium,
            title: "package.json / lockfile drift".into(),
            message: format!(
                "{} declared dependencies not reflected at lock root: {}",
                missing.len(),
                sample.join(", ")
            ),
            file: Some(rel_display(root, pkg)),
            line: None,
            evidence: Some(format!("missing: {}", sample.join(", "))),
            remediation: Some(
                "Run a clean install to regenerate the lockfile and commit both files together."
                    .into(),
            ),
        });
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn missing_npm_lock() {
        let dir = tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        fs::write(&pkg, r#"{"name":"x","dependencies":{"left-pad":"1.0.0"}}"#).unwrap();
        let findings = scan(dir.path(), &[pkg]).unwrap();
        assert!(findings.iter().any(|f| f.id.contains("npm-missing")));
    }
}
