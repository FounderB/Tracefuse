# Detectors

All detectors run **offline** against files collected from the scan root. Toggle them in `.tracefuse.toml` under `[detectors]`.

Explain any rule interactively:

```bash
tracefuse explain secrets/aws-access-key-id
tracefuse explain oidc
tracefuse explain curl
```

## secrets

Finds:

- PEM / OpenSSH private key headers
- AWS `AKIA…` / `ASIA…` access key IDs
- GitHub `ghp_…` classic PATs and `github_pat_…` fine-grained PATs
- Stripe `sk_live_…`
- Slack `xox…` tokens and incoming webhook URLs
- GCP API keys (`AIza…`)
- OpenAI-like `sk-` / `sk-proj-` keys
- Hard-coded `password|secret|token|api_key` assignments
- High-entropy values next to credential keywords

Evidence is always redacted (`abcd…wxyz` style), then re-scrubbed by a global sanitize pass before human / JSON / SARIF emit. Skips common binary / image extensions.

## scripts

Parses `package.json` `scripts`. Flags lifecycle hooks (`preinstall`, `postinstall`, `prepare`, `install`, …) that pipe `curl`/`wget` into a shell, use `eval` / `node -e` / encoded PowerShell, or similar installer patterns. Non-lifecycle `curl|bash` is reported at medium.

## lockfile

- **npm:** `package.json` without a lockfile; package-lock root drift vs declared deps
- **Cargo:** application `Cargo.toml` without `Cargo.lock`
- **Go:** `go.mod` without `go.sum`

## dockerfile

Scans `Dockerfile*` for floating `:latest` / untagged bases, secret-like `ENV`, `ADD https://…`, `curl|sh` / `wget|sh` in `RUN`, and root / `--privileged` patterns. ENV values are redacted in evidence.

## ci

Scans `.github/workflows/*.yml` (and similar CI files) for:

- `pull_request_target`
- `curl|bash`
- plaintext secret assignments (skips `${{ secrets.* }}`)
- OIDC misuse: `id-token: write` combined with `pull_request_target` or `permissions: write-all`
- standalone `permissions: write-all`

## env_files

Flags presence of `.env*` (except `.example` / `.sample` / `.template`), credential JSON, SSH key filenames, `.pem` / `.key`, kubeconfig-style names, `.npmrc` / `.pypirc`.

## deps

Light heuristics on `package.json` dependency names: known risky / historically abused names, one-edit typosquats of popular packages, and remote URL / git dependencies. Not a full advisory database — a fast local smell check.

## Configuration

```toml
[detectors]
secrets    = true
scripts    = true
lockfile   = true
dockerfile = true
ci         = true
env_files  = true
deps       = true

[severity_overrides]
"ci/pull-request-target" = "medium"
```

See [CONFIGURATION.md](CONFIGURATION.md).
