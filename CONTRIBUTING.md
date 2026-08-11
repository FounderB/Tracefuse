# Contributing to Tracefuse

Thanks for helping raise the bar on supply-chain truth.

## Development

```bash
cargo fmt
cargo test
cargo build --release
cargo run -- scan examples/demo-vulnerable
cargo run -- scan examples/demo-vulnerable --json
cargo run -- scan examples/demo-vulnerable --sarif /tmp/out.sarif -q
```

Useful CLI contracts (from `scan --help` / `init --help`):

```bash
tracefuse scan [path] [--json] [--sarif FILE] [--fail-on LEVEL] [-c CONFIG] [-q]
tracefuse init [path] [--force]
```

`--fail-on` values: `info` · `low` · `medium` · `high` · `critical`.

## Guidelines

- Keep the default scan **offline-first** (no network).
- Never commit real secrets. Demo fixtures must be labeled FAKE/EXAMPLE.
- Redact sensitive evidence in all output formats (human, JSON, SARIF).
- Prefer small, focused detectors under `src/detect/`.
- Add unit tests next to new detector logic; extend `tests/cli_integration.rs` for CLI contracts.
- Update [docs/DETECTORS.md](docs/DETECTORS.md) when adding a detector; keep CLI examples aligned with `--help`.
- Match existing module style: `anyhow` for errors, serde for interchange.

## Pull requests

1. Fork / branch from `master` (or `main`).
2. Include tests for new detectors or CLI flags.
3. Update docs when behavior or flags change.
4. Keep commits clean — no secrets, no Co-authored-by spam trailers.

## Code of conduct

Be respectful. Harassment and bad-faith security theatrics are not welcome. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
