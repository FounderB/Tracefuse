# Changelog

All notable changes to Tracefuse will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `tracefuse doctor` and `tracefuse explain <rule-id>` DX commands
- Global `sanitize_findings` / `redact_in_text` safety net across human, JSON, and SARIF
- `[severity_overrides]` in `.tracefuse.toml`
- Detectors: GCP API keys, GitHub fine-grained PATs, Slack webhooks, Dockerfile `curl|sh`, CI OIDC misuse
- Thin composite GitHub Action at `action/action.yml`
- CI: fmt + clippy required; doctor/explain/demo/SARIF smoke

## [0.1.0] — 2026-08-11

### Added

- `tracefuse scan` with offline detectors: secrets, scripts, lockfile, dockerfile, ci, env_files, deps
- Human terminal report with health score, severity badges, redacted evidence, next steps
- `--json` stdout and `--sarif <FILE>` (SARIF 2.1.0) outputs
- `tracefuse init` / `init --force` writes `.tracefuse.toml`
- `--fail-on info|low|medium|high|critical`, `-c` / `--config`, `-q` / `--quiet`
- Exit codes: `0` clean/below threshold · `1` policy fail · `2` tool error
- Demo fixture at `examples/demo-vulnerable/` (FAKE/EXAMPLE secrets only)
- Docs: architecture, detectors, configuration, GitHub Action + SARIF upload
- CI workflow (`.github/workflows/ci.yml`), MIT license, brand mark (`assets/logo.svg`)
