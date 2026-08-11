use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::FindingSeverity;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FailOn {
    Info,
    Low,
    Medium,
    #[default]
    High,
    Critical,
}

impl FailOn {
    pub fn as_severity(self) -> FindingSeverity {
        match self {
            Self::Info => FindingSeverity::Info,
            Self::Low => FindingSeverity::Low,
            Self::Medium => FindingSeverity::Medium,
            Self::High => FindingSeverity::High,
            Self::Critical => FindingSeverity::Critical,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Minimum severity that causes exit code 1
    pub fail_on: FailOn,
    /// Path component names to skip (matched against individual path segments)
    pub ignore_paths: Vec<String>,
    /// Detector toggles
    pub detectors: DetectorToggles,
    /// Max file size to scan (bytes)
    pub max_file_bytes: u64,
    /// Override severity by rule id prefix, detector name, or title.
    /// Example: `"ci/pull-request-target" = "medium"`
    pub severity_overrides: BTreeMap<String, FindingSeverity>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            fail_on: FailOn::High,
            ignore_paths: vec![
                "node_modules".into(),
                "target".into(),
                ".git".into(),
                "dist".into(),
                "build".into(),
                "vendor".into(),
                ".tracefuse".into(),
            ],
            detectors: DetectorToggles::default(),
            max_file_bytes: 2 * 1024 * 1024,
            severity_overrides: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DetectorToggles {
    pub secrets: bool,
    pub scripts: bool,
    pub lockfile: bool,
    pub dockerfile: bool,
    pub ci: bool,
    pub env_files: bool,
    pub deps: bool,
}

impl Default for DetectorToggles {
    fn default() -> Self {
        Self {
            secrets: true,
            scripts: true,
            lockfile: true,
            dockerfile: true,
            ci: true,
            env_files: true,
            deps: true,
        }
    }
}

pub fn load_config(root: &Path, explicit: Option<&Path>) -> Result<Config> {
    let path = if let Some(p) = explicit {
        p.to_path_buf()
    } else {
        root.join(".tracefuse.toml")
    };

    if !path.exists() {
        return Ok(Config::default());
    }

    let text =
        fs::read_to_string(&path).with_context(|| format!("reading config {}", path.display()))?;
    let cfg: Config =
        toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))?;
    Ok(cfg)
}

pub fn write_example_config(dir: &Path, force: bool) -> Result<PathBuf> {
    let path = dir.join(".tracefuse.toml");
    if path.exists() && !force {
        bail!(
            "{} already exists (pass --force to overwrite)",
            path.display()
        );
    }
    fs::create_dir_all(dir)?;
    fs::write(&path, EXAMPLE_CONFIG)?;
    Ok(path)
}

pub const EXAMPLE_CONFIG: &str = r#"# Tracefuse configuration
# https://github.com/FounderB/Tracefuse

# Exit 1 when findings at or above this severity are present
fail_on = "high"

# Path *components* to skip while walking (".git" will not match ".github")
ignore_paths = [
  "node_modules",
  "target",
  ".git",
  "dist",
  "build",
  "vendor",
]

# Skip files larger than this (bytes)
max_file_bytes = 2097152

[detectors]
secrets    = true
scripts    = true
lockfile   = true
dockerfile = true
ci         = true
env_files  = true
deps       = true

# Optional: lower/raise severity by rule id prefix, detector, or title
# [severity_overrides]
# "ci/pull-request-target" = "medium"
# "secrets" = "critical"
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn loads_severity_overrides() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(".tracefuse.toml");
        fs::write(
            &path,
            r#"
fail_on = "medium"
[severity_overrides]
"ci/pull-request-target" = "low"
secrets = "critical"
"#,
        )
        .unwrap();
        let cfg = load_config(dir.path(), None).unwrap();
        assert_eq!(cfg.fail_on, FailOn::Medium);
        assert_eq!(
            cfg.severity_overrides.get("ci/pull-request-target"),
            Some(&FindingSeverity::Low)
        );
        assert_eq!(
            cfg.severity_overrides.get("secrets"),
            Some(&FindingSeverity::Critical)
        );
    }
}
