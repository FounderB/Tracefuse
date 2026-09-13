# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |
| 0.1.x   | Yes       |

## Reporting a vulnerability

**Do not** open a public issue for security problems in Tracefuse itself.

Email **FounderB@users.noreply.github.com** with:

- Affected version / commit
- Reproduction steps
- Impact assessment (secrets leak in reports, path traversal, etc.)

You should receive an acknowledgment within a few days.

## Product security promises

Tracefuse is designed so a default scan is safe to run on private trees:

| Promise | Behavior |
|---------|----------|
| Offline default | Detectors read local files only — no outbound network for a normal scan |
| Redaction | Secret-like evidence is redacted at detect time and again before human, JSON, and SARIF output |
| Path safety | Symlink / `..` escapes outside the scan root are rejected |
| Size caps | Oversized files are skipped via `max_file_bytes` |

These are engineering guarantees of the current design — not a formal third-party audit.

## Safe demo data

`examples/demo-vulnerable/` contains **intentionally fake** credentials for scanner demos. They are not production secrets. Do not replace them with real keys.
