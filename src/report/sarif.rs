use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::fs;
use std::path::Path;

use crate::{FindingSeverity, ScanReport};

/// Emit SARIF 2.1.0 suitable for GitHub Code Scanning.
pub fn emit_sarif(report: &ScanReport, path: &Path) -> Result<()> {
    let mut rules = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for f in &report.findings {
        let rule_id = format!("{}/{}", f.detector, slug(&f.title));
        if seen.insert(rule_id.clone()) {
            rules.push(json!({
                "id": rule_id,
                "name": f.title,
                "shortDescription": { "text": f.title },
                "fullDescription": { "text": f.message },
                "defaultConfiguration": {
                    "level": sarif_level(f.severity)
                },
                "help": {
                    "text": f.remediation.clone().unwrap_or_default()
                }
            }));
        }
    }

    let results: Vec<Value> = report
        .findings
        .iter()
        .map(|f| {
            let rule_id = format!("{}/{}", f.detector, slug(&f.title));
            let mut result = json!({
                "ruleId": rule_id,
                "level": sarif_level(f.severity),
                "message": { "text": f.message },
            });
            if let Some(file) = &f.file {
                let uri = file.to_string_lossy().replace('\\', "/");
                let region = if let Some(line) = f.line {
                    json!({ "startLine": line })
                } else {
                    json!({})
                };
                result["locations"] = json!([{
                    "physicalLocation": {
                        "artifactLocation": { "uri": uri, "uriBaseId": "%SRCROOT%" },
                        "region": region
                    }
                }]);
            }
            if let Some(ev) = &f.evidence {
                // Evidence is already redacted by detectors
                result["partialFingerprints"] = json!({
                    "evidenceHash": short_hash(ev)
                });
                result["properties"] = json!({
                    "evidenceRedacted": true
                });
            }
            result
        })
        .collect();

    let sarif = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Tracefuse",
                    "version": report.version,
                    "informationUri": "https://github.com/FounderB/Tracefuse",
                    "rules": rules
                }
            },
            "results": results,
            "columnKind": "utf16CodeUnits"
        }]
    });

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let text = serde_json::to_string_pretty(&sarif)?;
    fs::write(path, text).with_context(|| format!("writing SARIF {}", path.display()))?;
    Ok(())
}

fn sarif_level(sev: FindingSeverity) -> &'static str {
    match sev {
        FindingSeverity::Critical | FindingSeverity::High => "error",
        FindingSeverity::Medium => "warning",
        FindingSeverity::Low | FindingSeverity::Info => "note",
    }
}

fn slug(s: &str) -> String {
    s.to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

fn short_hash(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())[..16].to_string()
}
