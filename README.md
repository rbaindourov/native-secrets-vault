# Native Secrets Vault (`nsv`)

[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg)](LICENSE)
[![Zero Docker](https://img.shields.io/badge/Architecture-Native%20User--Space%20(Zero%20Docker)-0284c7.svg)](#architecture)
[![Crypto](https://img.shields.io/badge/Crypto-AES--256--GCM%20%2B%20Shamir%20GF(256)-f59e0b.svg)](#cryptographic-design)

**Native Secrets Vault (`native-secrets-vault` / `nsv`)** is a lightweight, zero-Docker, MIT-licensed secrets management server, CLI, and TypeScript SDK designed for bare-metal Linux servers, `systemd` / PM2 clusters, and multi-agent / multi-domain architectures.

Built with **zero runtime npm dependencies** (100% Node.js native `crypto`, `http`, and `fs` primitives), it provides **HashiCorp Vault KV v2 wire compatibility** alongside a lossless `.env` synchronization engine, Shamir's Secret Sharing over $\text{GF}(2^8)$, envelope encryption (`AES-256-GCM` + `HKDF-SHA256`), tamper-evident SHA-256 hash-chained audit logs, Prometheus `/metrics`, and a built-in glassmorphic Web UI.

---

## ✨ Key Features

1. **Shamir's Secret Sharing over $\text{GF}(2^8)$ (`k`-of-`n` Unseal)**:
   - Splits the 256-bit Master Key into $n$ cryptographic shares (using the Rijndael irreducible polynomial `0x11b`) where any $k$ shares reconstruct the Master Key via Lagrange interpolation and $k-1$ shares reveal zero information.
2. **Envelope Encryption (`AES-256-GCM` + `HKDF-SHA256` + `AAD`)**:
   - The Master Key wraps the 256-bit Root Data Encryption Key (DEK).
   - Every secret path and version derives a unique per-version subkey via `HKDF-SHA256` and binds its ciphertext to `nsv-kv-v2:<path>:v<version>` via Additional Authenticated Data (AAD), preventing cross-path or cross-version ciphertext substitution.
   - Sealing the vault (`POST /v1/sys/seal` or `nsv seal`) explicitly zeroes the in-memory DEK buffer (`dek.fill(0)`).
3. **HashiCorp Vault KV v2 Wire Compatibility + Ergonomic Native API**:
   - Drop-in support for `/v1/sys/health`, `/v1/sys/seal-status`, `/v1/sys/init`, `/v1/sys/unseal`, `/v1/sys/seal`, `/v1/secret/data/:path`, and `/v1/secret/metadata/:path`.
   - Native batch endpoints (`/api/v1/export/dotenv`, `/api/v1/export/json`, `/api/v1/paths`, `/api/v1/audit/verify`).
4. **Lossless `.env` Synchronization (`nsv sync-env`)**:
   - Enforces the **Zero Secret Loss Invariant**:
     - Never deletes existing keys, comments, or blank lines in `.env`.
     - Never overwrites an existing non-empty secret with an empty value.
     - Automatically creates a `0600` timestamped `.bak-<ISO>` backup before modifying any `.env` file.
5. **Tamper-Evident SHA-256 Hash-Chained Audit Log**:
   - Every read, write, seal/unseal, token issuance, and snapshot export appends a cryptographically linked record (`prevHash` $\rightarrow$ `hash`) without ever logging raw secret values.
6. **Built-In Web UI (`/ui`) & Prometheus Exporter (`/metrics`)**:
   - Native observability for Grafana & Prometheus (`vault_sealed`, `vault_secrets_total`, `vault_audit_chain_valid`, `vault_http_requests_total`).

---

## 🚀 Quick Start

```bash
# 1. Install dev dependencies & build TypeScript
npm install
npm run build

# 2. Start the Native Secrets Vault daemon (defaults to 127.0.0.1:8200)
npm start

# 3. Initialize with 3 Shamir shares and a threshold of 2
./bin/nsv.js init --shares=3 --threshold=2 --save-file=.vault-data/unseal-init.json

# 4. Store versioned secrets in KV v2
./bin/nsv.js kv put cms/prod JWT_SECRET="super-secret" SESSION_SECRET="sess-key"

# 5. Read secrets or losslessly sync into a local .env file
./bin/nsv.js kv get cms/prod
./bin/nsv.js sync-env ./.env --paths=cms/prod

# 6. Verify SHA-256 audit chain integrity
./bin/nsv.js audit verify
```

---

## 📐 Architecture & Documentation

See [`docs/architecture.md`](docs/architecture.md) for the complete cryptographic specification, API reference, and `systemd` / PM2 production deployment guide.

## 📄 License

Released under the [MIT License](LICENSE).
