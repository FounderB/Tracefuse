use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;

fn bin() -> Command {
    Command::cargo_bin("tracefuse").unwrap()
}

fn demo_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/demo-vulnerable")
}

#[test]
fn demo_scan_finds_issues_and_fails_policy() {
    bin()
        .args(["scan", demo_path().to_str().unwrap(), "--fail-on", "high"])
        .assert()
        .failure()
        .code(1)
        .stdout(predicate::str::contains("TRACEFUSE"))
        .stdout(predicate::str::contains("score"));
}

#[test]
fn demo_json_redacts_and_lists_detectors() {
    let assert = bin()
        .args([
            "scan",
            demo_path().to_str().unwrap(),
            "--json",
            "--fail-on",
            "critical",
        ])
        .assert()
        .failure(); // demo has critical findings

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    assert!(stdout.contains("\"detector\""));
    assert!(stdout.contains("secrets") || stdout.contains("ci"));
    assert!(!stdout.contains("FAKEEXAMPLEPRIVATEKEYMATERIALNOTREAL"));
    // Full EXAMPLE AWS key body must not appear unredacted in evidence
    assert!(!stdout.contains("\"evidence\": \"AKIAIOSFODNN7EXAMPLE\""));
}

#[test]
fn init_writes_config() {
    let dir = tempfile::tempdir().unwrap();
    bin()
        .args(["init", dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains(".tracefuse.toml"));
    assert!(dir.path().join(".tracefuse.toml").exists());
}

#[test]
fn sarif_written_with_redacted_properties() {
    let dir = tempfile::tempdir().unwrap();
    let sarif = dir.path().join("out.sarif");
    bin()
        .args([
            "scan",
            demo_path().to_str().unwrap(),
            "--quiet",
            "--sarif",
            sarif.to_str().unwrap(),
            "--fail-on",
            "info",
        ])
        .assert()
        .failure();
    let text = std::fs::read_to_string(&sarif).unwrap();
    assert!(text.contains("\"version\": \"2.1.0\""));
    assert!(text.contains("Tracefuse"));
    assert!(text.contains("evidenceRedacted") || text.contains("partialFingerprints"));
    assert!(!text.contains("FAKEEXAMPLEPRIVATEKEYMATERIALNOTREAL"));
}

#[test]
fn doctor_runs() {
    bin()
        .args(["doctor", "."])
        .assert()
        .success()
        .stdout(predicate::str::contains("TRACEFUSE DOCTOR"))
        .stdout(predicate::str::contains("offline"));
}

#[test]
fn explain_rule() {
    bin()
        .args(["explain", "ci/pull-request-target"])
        .assert()
        .success()
        .stdout(predicate::str::contains("pull_request_target"))
        .stdout(predicate::str::contains("REMEDIATION"));
}

#[test]
fn explain_unknown_fails() {
    bin()
        .args(["explain", "not-a-real-rule-zzzz"])
        .assert()
        .failure()
        .code(2);
}
