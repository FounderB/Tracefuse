use anyhow::{Context, Result};
use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::config::Config;
use crate::detect;
use crate::{
    build_next_steps, compute_score, sanitize_findings, Finding, FindingSeverity, ScanReport,
    ScanSummary,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Run all enabled detectors against `root`.
pub fn run_scan(root: &Path, cfg: &Config) -> Result<ScanReport> {
    let root = root
        .canonicalize()
        .with_context(|| format!("resolving scan root {}", root.display()))?;

    ensure_within_or_equal(&root, &root)?;

    let files = collect_files(&root, cfg)?;
    let mut findings: Vec<Finding> = Vec::new();

    if cfg.detectors.secrets {
        findings.extend(detect::secrets::scan(&root, &files, cfg)?);
    }
    if cfg.detectors.scripts {
        findings.extend(detect::scripts::scan(&root, &files)?);
    }
    if cfg.detectors.lockfile {
        findings.extend(detect::lockfile::scan(&root, &files)?);
    }
    if cfg.detectors.dockerfile {
        findings.extend(detect::dockerfile::scan(&root, &files)?);
    }
    if cfg.detectors.ci {
        findings.extend(detect::ci::scan(&root, &files)?);
    }
    if cfg.detectors.env_files {
        findings.extend(detect::env_files::scan(&root, &files)?);
    }
    if cfg.detectors.deps {
        findings.extend(detect::deps::scan(&root, &files)?);
    }

    apply_severity_overrides(&mut findings, cfg);
    sanitize_findings(&mut findings);

    findings.sort_by(|a, b| {
        a.detector
            .cmp(&b.detector)
            .then_with(|| b.severity.cmp(&a.severity))
            .then_with(|| a.title.cmp(&b.title))
            .then_with(|| a.file.cmp(&b.file))
    });

    let summary = ScanSummary::from_findings(&findings);
    let score = compute_score(&summary);
    let next_steps = build_next_steps(&summary);

    Ok(ScanReport {
        tool: "tracefuse".into(),
        version: VERSION.into(),
        root,
        scanned_at: chrono::Utc::now().to_rfc3339(),
        score,
        summary,
        findings,
        next_steps,
    })
}

fn collect_files(root: &Path, cfg: &Config) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let walker = ignore::WalkBuilder::new(root)
        .hidden(false)
        .git_ignore(true)
        .git_global(false)
        .git_exclude(false)
        .parents(false)
        .build();

    for entry in walker {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if should_ignore(root, path, cfg) {
            continue;
        }
        // Path traversal / symlink escape guard
        if let Ok(canon) = path.canonicalize() {
            if !canon.starts_with(root) {
                continue;
            }
        } else {
            continue;
        }
        if let Ok(meta) = fs::metadata(path) {
            if meta.len() > cfg.max_file_bytes {
                continue;
            }
        }
        out.push(path.to_path_buf());
    }
    Ok(out)
}

fn should_ignore(root: &Path, path: &Path, cfg: &Config) -> bool {
    let rel = path.strip_prefix(root).unwrap_or(path);
    for frag in &cfg.ignore_paths {
        // Match whole path components only (so ".git" does not match ".github")
        for component in rel.components() {
            if let Component::Normal(os) = component {
                if os == std::ffi::OsStr::new(frag.as_str()) {
                    return true;
                }
            }
        }
    }
    false
}

fn ensure_within_or_equal(root: &Path, candidate: &Path) -> Result<()> {
    for c in candidate.components() {
        if matches!(c, Component::ParentDir) {
            anyhow::bail!("path traversal rejected: {}", candidate.display());
        }
    }
    let _ = root;
    Ok(())
}

pub fn rel_display(root: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(root)
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|_| path.to_path_buf())
}

fn apply_severity_overrides(findings: &mut [Finding], cfg: &Config) {
    if cfg.severity_overrides.is_empty() {
        return;
    }
    for f in findings.iter_mut() {
        let rule_slug = format!("{}/{}", f.detector, title_slug(&f.title));
        let mut matched: Option<(&str, FindingSeverity)> = None;
        for (key, sev) in &cfg.severity_overrides {
            let k = key.as_str();
            let hit = f.id.starts_with(k)
                || rule_slug.eq_ignore_ascii_case(k)
                || f.detector.eq_ignore_ascii_case(k)
                || f.title.eq_ignore_ascii_case(k);
            if hit {
                match matched {
                    Some((prev, _)) if k.len() <= prev.len() => {}
                    _ => matched = Some((k, *sev)),
                }
            }
        }
        if let Some((_, sev)) = matched {
            f.severity = sev;
        }
    }
}

fn title_slug(s: &str) -> String {
    s.to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn scan_empty_project_is_clean() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("README.md"), "hello").unwrap();
        let report = run_scan(dir.path(), &Config::default()).unwrap();
        assert_eq!(report.summary.total, 0);
        assert_eq!(report.score, 100);
    }

    #[test]
    fn ignore_git_does_not_skip_github() {
        let dir = tempdir().unwrap();
        let wf = dir.path().join(".github/workflows");
        fs::create_dir_all(&wf).unwrap();
        fs::write(wf.join("ci.yml"), "on: push\n").unwrap();
        fs::create_dir_all(dir.path().join(".git")).unwrap();
        fs::write(dir.path().join(".git/config"), "x").unwrap();
        let root = dir.path().canonicalize().unwrap();
        let files = collect_files(&root, &Config::default()).unwrap();
        assert!(files.iter().any(|p| p.ends_with("ci.yml")));
        assert!(!files
            .iter()
            .any(|p| p.to_string_lossy().contains(".git/config")));
    }

    #[test]
    fn ignore_paths_skips_vendor_secret() {
        let dir = tempdir().unwrap();
        let skip = dir.path().join("vendor/secret");
        fs::create_dir_all(&skip).unwrap();
        fs::write(
            skip.join("leak.env"),
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
        )
        .unwrap();
        fs::write(dir.path().join("README.md"), "ok").unwrap();
        let report = run_scan(dir.path(), &Config::default()).unwrap();
        assert_eq!(report.summary.total, 0);
    }

    #[test]
    fn severity_override_lowers_finding() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("cfg.env"),
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
        )
        .unwrap();
        let mut cfg = Config::default();
        cfg.severity_overrides
            .insert("secrets".into(), FindingSeverity::Low);
        let report = run_scan(dir.path(), &cfg).unwrap();
        assert!(!report.findings.is_empty());
        assert!(report
            .findings
            .iter()
            .filter(|f| f.detector == "secrets")
            .all(|f| f.severity == FindingSeverity::Low));
    }
}
