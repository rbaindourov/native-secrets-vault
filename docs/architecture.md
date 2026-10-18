# Native Secrets Vault — Cryptographic Architecture & Operations Guide

## 1. Cryptographic Hierarchy

```mermaid
flowchart TD
    Shamir["Shamir GF(256) Shares (Share 1 .. Share N)"] -->|Lagrange Interpolation (Threshold K)| MasterKey["256-Bit Master Unseal Key (Zeroed After Unseal)"]
    MasterKey -->|AES-256-GCM Unwrap (AAD: nsv-root-dek-v1)| RootDEK["256-Bit Root Data Encryption Key (In-Memory Only)"]
    RootDEK -->|HKDF-SHA256 (salt, info: nsv-envelope-v1:path:vN)| SubKey["256-Bit Per-Path Per-Version Key"]
    SubKey -->|AES-256-GCM + AAD (nsv-kv-v2:path:vN)| Ciphertext[("vault-state.json (0600 Disk Persistence)")]
```

1. **Shamir's Secret Sharing ($\text{GF}(2^8)$)**:
   - Implemented in [`src/crypto/shamir.ts`](../src/crypto/shamir.ts) over the finite field $\text{GF}(2^8)$ with irreducible polynomial $x^8 + x^4 + x^3 + x + 1$ (`0x11b`).
   - During `init`, a 32-byte cryptographically random Master Key is split into $N$ shares (`secret_shares`) with reconstruction threshold $K$ (`secret_threshold`).
2. **Envelope Encryption (`AES-256-GCM` + `HKDF-SHA256`)**:
   - Implemented in [`src/crypto/envelope.ts`](../src/crypto/envelope.ts).
   - Every secret write derives a fresh 256-bit subkey using `crypto.hkdfSync('sha256', rootDek, randomSalt16, info, 32)` and encrypts with a random 96-bit IV and 128-bit GCM authentication tag.
   - Additional Authenticated Data (`AAD`) binds the ciphertext to the exact `path` and `version`, preventing an attacker with disk access from swapping encrypted blobs between secret paths or rolling back versions undetected.

---

## 2. REST API Reference (`127.0.0.1:8200`)

### HashiCorp Vault KV v2 Compatible Endpoints
- `GET /v1/sys/health` — Returns `200` when initialized and unsealed, `503` when sealed, `501` when uninitialized.
- `GET /v1/sys/seal-status` — Returns Shamir threshold (`t`, `n`), `initialized`, and `sealed` posture.
- `POST /v1/sys/init` — Initializes the vault and returns Shamir shares + `root_token`.
- `POST /v1/sys/unseal` — Submits a Shamir share (`{ "key": "<hex-or-base64>" }`) toward the unseal threshold.
- `POST /v1/sys/seal` — Zeroes the in-memory Root DEK and seals the vault.
- `POST /v1/secret/data/:path` — Creates a new encrypted secret version (`{ "data": { "KEY": "VAL" } }`).
- `GET /v1/secret/data/:path` — Decrypts and returns the latest (or `?version=N`) secret version.
- `GET /v1/secret/metadata/:path` — Returns version history and key names without decrypting secret values.

### Native Ergonomic & Observability Endpoints
- `GET /ui` — Interactive dark-mode glassmorphic Web UI.
- `GET /metrics` — Prometheus text-format metrics (`vault_sealed`, `vault_secrets_total`, `vault_audit_chain_valid`, `vault_http_requests_total`).
- `GET /api/v1/export/json?paths=cms/prod,oauth/prod` — Exports flattened key-value JSON across multiple paths.
- `GET /api/v1/export/dotenv?paths=cms/prod,oauth/prod` — Exports `.env`-formatted lines across multiple paths.
- `GET /api/v1/audit/verify` — Recomputes and verifies the entire SHA-256 audit chain from genesis.
- `POST /api/v1/tokens` — Issues a scoped service token restricted to specific path globs and capabilities (`read`, `write`, `list`, `delete`).
- `POST /api/v1/snapshot/export` — Exports a passphrase-encrypted (`scrypt` + `AES-256-GCM`) disaster-recovery snapshot.
