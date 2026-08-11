# GitHub Action — scan + SARIF

Run Tracefuse on every PR and push, then upload SARIF to **GitHub Code Scanning**.

Requires a public repo, or Advanced Security enabled on a private repo, for SARIF upload to appear in the Security tab.

## Option A — thin composite action (this repo)

If you vendor Tracefuse (or use it as the workflow repo), reference the bundled action:

```yaml
name: tracefuse

on:
  pull_request:
  push:
    branches: [main, master]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./action
        with:
          path: .
          fail-on: high
          sarif-path: tracefuse.sarif
```

`action/action.yml` installs Tracefuse from the parent crate, scans, and uploads SARIF (`if: always()` equivalent via the upload step).

## Option B — copy-paste workflow

Save as `.github/workflows/tracefuse.yml`:

```yaml
name: tracefuse

on:
  pull_request:
  push:
    branches: [main, master]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: dtolnay/rust-toolchain@stable

      - name: Cache cargo
        uses: Swatinem/rust-cache@v2

      - name: Install Tracefuse
        run: cargo install --path . --locked

      - name: Scan
        # Exit 1 on high/critical is expected policy failure — still upload SARIF via if: always()
        run: tracefuse scan . --sarif tracefuse.sarif --fail-on high -q

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: tracefuse.sarif
          category: tracefuse
```

## Flags used

| Flag | Purpose |
|------|---------|
| `--sarif tracefuse.sarif` | Write SARIF **2.1.0** for Code Scanning |
| `--fail-on high` | Fail the job when high/critical findings exist (matches default config policy) |
| `-q` / `--quiet` | Suppress the human banner; SARIF still written |

JSON for custom tooling:

```bash
tracefuse scan . --json -q --fail-on high
```

## Consuming Tracefuse as a dependency of another repo

Until a published binary / Action exists, either:

1. **Vendor / submodule** this repo and `cargo install --path ./Tracefuse --locked`, or  
2. Install from git once the remote is public:

```yaml
- name: Install Tracefuse
  run: cargo install --git https://github.com/FounderB/Tracefuse --locked
```

## Permissions notes

- `security-events: write` is required for `upload-sarif`.
- Prefer `if: always()` on the upload step so findings still land when the scan exits `1`.
- Tool errors exit `2` — investigate those separately from policy fails.

## Local dry-run

```bash
cargo build --release
./target/release/tracefuse scan . --sarif /tmp/tracefuse.sarif --fail-on high -q
# Inspect /tmp/tracefuse.sarif before enabling Code Scanning upload
```

See also the repo CI smoke job in `.github/workflows/ci.yml`.
