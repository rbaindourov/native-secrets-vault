/**
 * src/index.ts
 * ──────────────────────────────────────────────────────────────────────────────
 * Public SDK entrypoint for `native-secrets-vault`.
 */

export * from './crypto/shamir';
export * from './crypto/envelope';
export * from './storage/auditLog';
export * from './storage/vaultEngine';
export * from './browser/browserVaultService';
export * from './ingest/smartIngestService';
export * from './sync/dotenvSync';
export * from './server';
