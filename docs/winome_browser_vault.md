# Winome Browser Vault Integration (`native-secrets-vault`)

`native-secrets-vault` serves as the AES-256-GCM envelope-encrypted credential, RFC 6238 TOTP, payment/sensitive-form, and cluster-key backend for the **Winome** Chromium fork.

## Security & Cryptographic Isolation Model

1. **Per-User Scoped Token Broker (`POST /api/v1/tokens/mint-user-scope`)**:
   - `users_backend` authenticates a browser user via JWT or `apiKey` and requests a short-lived Vault token scoped exclusively to `allowedPaths: ["winome/<userId>/*"]` with non-root `["read", "write", "list", "delete"]` capabilities.
   - Only a `root` token or a dedicated broker token (`allowedPaths` containing `winome/*` or `*`) may mint user-scoped tokens; a user token (`winome/alice/*`) can never mint tokens or read `winome/bob/*` or cluster infrastructure secrets (`cms/prod`, `oauth/prod`, etc.).
2. **Envelope Encryption & Cryptographic Shredding**:
   - Every secret version derives an isolated per-path, per-version key via HKDF-SHA256 from the Shamir-unsealed Root DEK with strict AAD binding (`nsv-kv-v2:winome/<userId>/...`).
   - Deleting a login or sensitive form entry (`DELETE /api/v1/browser/:userId/...`) marks the version `destroyed: true` and nulls `encryptedBlob` on disk while recording `kv.delete` in the SHA-256 hash-chained audit log.

## KV v2 Path Hierarchy

- `winome/<userId>/logins/<credentialId>` — Website logins (`origin`, `registrableDomain`, `signonRealm`, `username`, `password`, optional `totpSecret`, `formAction`, `urls`, `notes`).
- `winome/<userId>/sensitive-forms/<entryId>` — Sensitive form secrets (`payment_card`, `identity_document`, `secret_field`) rejected from standard `users_backend` autofill sync.
- `winome/<userId>/auth-tokens/<domain>` — Portable encrypted session cookies & bearer headers.
- `winome/<userId>/integrations` — Per-user ABM workbench credentials (`crmApiKey`, `cmsPitchApiKey`, `campaignsApiKey`).

## HTTP REST Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/`, `/ui`, `/passwords` | Glassmorphic Vault Dashboard & searchable Password Manager UI (supports Winome login or Vault token) |
| `GET` | `/api/v1/tokens/self` | Inspect caller capabilities and discover accessible `winome/<userId>` namespaces |
| `POST` | `/api/v1/browser/auth/winome-login` | Authenticate with Winome credentials via `users-backend` (`registry.local`) for a scoped `nsv_usr_*` session token |
| `POST` | `/api/v1/tokens/mint-user-scope` | Mint time-bounded token scoped to `winome/<userId>/*` |
| `GET` | `/api/v1/browser/:userId/logins?origin=...` | List all logins or match exact origin + `eTLD+1` subdomains with live TOTP codes |
| `POST` | `/api/v1/browser/:userId/logins` | Create or update an encrypted website login |
| `POST` | `/api/v1/browser/:userId/logins/batch` | Batch upsert website logins with SHA-256 content-hash deduplication |
| `DELETE` | `/api/v1/browser/:userId/logins/:credentialId` | Cryptographically destroy a login entry |
| `POST` | `/api/v1/browser/:userId/totp/generate` | Compute RFC 6238 TOTP code from Base32 secret or `otpauth://` URI |
| `GET` | `/api/v1/browser/:userId/sensitive-forms` | List encrypted payment cards, addresses & non-web app entries |
| `POST` | `/api/v1/browser/:userId/sensitive-forms` | Create or update a sensitive form entry |
| `POST` | `/api/v1/browser/:userId/sensitive-forms/batch` | Batch upsert sensitive form entries in one SHA-256 deduplicated commit |
| `POST` | `/api/v1/browser/:userId/ingest` | Unified Smart Ingest for CSV, `logins[]`, and `sensitiveForms[]` bundles |
| `DELETE` | `/api/v1/browser/:userId/sensitive-forms/:entryId` | Destroy a sensitive form entry |
| `GET/PUT` | `/api/v1/browser/:userId/auth-tokens/:domain` | Read or store encrypted session cookies/tokens for a domain |
| `GET/PUT` | `/api/v1/browser/:userId/integrations` | Read or store ABM/CRM/CMS API keys for zero-manual-config browser bootstrap |
