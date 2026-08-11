# Tracefuse demo fixture (intentionally vulnerable)

This directory is a **safe, offline demo** that triggers multiple Tracefuse detectors.

Every secret and remote URL is clearly marked **FAKE / EXAMPLE / invalid**.
Nothing here is a real credential — patterns exist only so Tracefuse can light up.

## What is planted

| Smell | Where |
| --- | --- |
| Fake AWS / Stripe / GitHub / Slack / OpenAI secrets | `.env`, `.env.example`, `src/index.js` |
| Committed private key PEM | `keys/demo_FAKE_id_rsa.pem` |
| npm `postinstall` curl-pipe-bash | `package.json` |
| package.json ↔ lockfile drift | `package.json` + `package-lock.json` |
| `:latest` base, ENV secrets, remote `ADD`, `USER root` | `Dockerfile` |
| `pull_request_target` + remote pipe + plaintext token | `.github/workflows/ci.yml` |
| Typosquat / risky dependency names | `package.json` (`lodahs`, `expresss`, `crossenv`) |

## Run

```bash
# from repo root
make scan-demo
# or
./scripts/demo.sh
# or
cargo run --release -- scan examples/demo-vulnerable
```

Expected detectors: `secrets`, `scripts`, `lockfile`, `dockerfile`, `ci`, `env_files`, `deps`.
