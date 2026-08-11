#!/usr/bin/env bash
# Build Tracefuse and scan the intentionally vulnerable demo with pretty output.
# All demo secrets are FAKE/EXAMPLE — offline only.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export PATH="${HOME}/.cargo/bin:${PATH}"

DEMO="${ROOT}/examples/demo-vulnerable"
BIN="${ROOT}/target/release/tracefuse"

echo "==> Building Tracefuse (release)"
cargo build --release

if [[ ! -x "$BIN" ]]; then
  echo "error: missing binary at $BIN" >&2
  exit 2
fi

echo
echo "==> Scanning demo-vulnerable (FAKE/EXAMPLE fixtures)"
echo "    path: $DEMO"
echo

set +e
"$BIN" scan "$DEMO" --fail-on high
code=$?
set -e

echo
if [[ "$code" -eq 1 ]]; then
  echo "==> Demo OK: Tracefuse reported findings and failed the high-severity policy (expected)."
  exit 0
elif [[ "$code" -eq 0 ]]; then
  echo "==> Unexpected: demo-vulnerable scored clean under --fail-on high." >&2
  exit 1
else
  echo "==> Tracefuse exited with tool error ($code)." >&2
  exit "$code"
fi
