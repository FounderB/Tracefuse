# Configuration

Tracefuse reads `.tracefuse.toml` from the scan root unless you pass `-c` / `--config`.

Generate a starter file:

```bash
tracefuse init
tracefuse init ./path --force   # overwrite
```

## Example

```toml
# Exit 1 when findings at or above this severity are present
fail_on = "high"

# Path *components* to skip (".git" does not match ".github")
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
[severity_overrides]
# "ci/pull-request-target" = "medium"
# "secrets" = "critical"
```

## Precedence

| Source | Effect |
|--------|--------|
| Built-in defaults | Used when no config file exists |
| `.tracefuse.toml` / `--config` | Overrides defaults |
| `--fail-on` on the CLI | Overrides `fail_on` for that run |
| `[severity_overrides]` | Applied after detectors, before scoring / emit |

## Severity values

`info` · `low` · `medium` · `high` · `critical`

Default policy: **high**.

## Ignore behavior

- `.gitignore` is respected via the `ignore` walker.
- `ignore_paths` entries match **whole path components** relative to the scan root (so `.git` skips `.git/` but not `.github/`).
- Symlinks that resolve outside the scan root are skipped.
- Files larger than `max_file_bytes` are skipped.

## Severity overrides

Keys may be:

- a finding id **prefix** (e.g. `ci/pull-request-target`)
- a detector name (`secrets`, `ci`, …)
- a rule title (case-insensitive / substring)

Longer matching keys win when multiple overrides apply.

```bash
tracefuse explain ci/pull-request-target   # shows the stable rule id
```
