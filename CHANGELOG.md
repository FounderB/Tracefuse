# Changelog

All notable changes to Tracefuse will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — 2026-08-22

### Added

- `[[custom_rules]]` in `.tracefuse.toml` — user regex rules (id, title, pattern, severity)
- `tracefuse scan --git-diff` — scan only files changed vs HEAD (+ untracked)
- GitHub Action input `git-diff`

### Security

- Composite Action passes inputs via env + argv (no shell interpolation of `${{ inputs.* }}` into command strings)
- Stronger path containment check (`ensure_within_or_equal` uses canonicalize + prefix)

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
