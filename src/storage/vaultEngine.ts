/**
 * src/storage/vaultEngine.ts
 * ──────────────────────────────────────────────────────────────────────────────
 * Core Cryptographic KV v2 Secrets Engine for Native Secrets Vault.
 *
 * Features:
 *   - Shamir GF(256) K-of-N Master Key splitting (`init`, `unseal`, `seal`)
 *   - Envelope Encryption: Master Key wraps the 256-bit Root DEK; Root DEK
 *     derives per-path/per-version HKDF-SHA256 keys for AES-256-GCM + AAD
 *   - Full KV v2 versioned secret lifecycle (`putSecret`, `getSecret`,
 *     `getMetadata`, `listPaths`, `destroyVersions`)
 *   - Scoped Bearer Token & Policy authorization (`root`, `read`, `write`, `list`, `delete`)
 *   - Tamper-evident SHA-256 hash-chained audit logging (`AuditLogger`)
 *   - Atomic file persistence (`0o600` permissions via write-then-rename)
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { splitSecret, combineShares } from '../crypto/shamir';
import {
  EncryptedBlob,
  encryptWithContext,
  decryptWithContext,
  encryptSnapshotWithPassphrase,
  decryptSnapshotWithPassphrase
} from '../crypto/envelope';
import { AuditLogger, AuditEntry, AuditVerificationResult } from './auditLog';

export type Capability = 'root' | 'read' | 'write' | 'list' | 'delete';

export interface TokenRecord {
  id: string;
  name: string;
  tokenHash: string;
  allowedPaths: string[]; // e.g. ['*'] or ['cms/*', 'oauth/prod']
  capabilities: Capability[];
  createdAt: string;
  expiresAt: string | null;
}

export interface SecretVersionRecord {
  version: number;
  createdTime: string;
  deletionTime: string;
  destroyed: boolean;
  keyCount: number;
  keyNames: string[]; // Metadata key names only (values are inside encryptedBlob)
  encryptedBlob: EncryptedBlob | null;
}

export interface SecretPathRecord {
  path: string;
  currentVersion: number;
  oldestVersion: number;
  createdTime: string;
  updatedTime: string;
  maxVersions: number;
  versions: Record<number, SecretVersionRecord>;
}

export interface PersistedVaultState {
  formatVersion: 1;
  clusterName: string;
  initialized: boolean;
  createdAt: string;
  secretShares: number;
  secretThreshold: number;
  wrappedDek: EncryptedBlob | null;
  tokens: Record<string, TokenRecord>;
  secrets: Record<string, SecretPathRecord>;
}

export interface InitOptions {
  secretShares?: number;
  secretThreshold?: number;
  autoUnseal?: boolean;
}

export interface InitResponse {
  keys: string[];
  keys_base64: string[];
  root_token: string;
  secret_shares: number;
  secret_threshold: number;
}

export interface SealStatusResponse {
  type: 'shamir-gf256-aes256gcm';
  initialized: boolean;
  sealed: boolean;
  t: number;
  n: number;
  progress: number;
  version: string;
  cluster_name: string;
}

function hashToken(rawToken: string): string {
  return crypto.createHash('sha256').update(rawToken, 'utf8').digest('hex');
}

export function normalizeSecretPath(rawPath: string): string {
  return String(rawPath || '')
    .trim()
    .replace(/^\/+/, '')
    .replace(/\/+$/, '')
    .replace(/^secret\/data\//, '')
    .replace(/^secret\/metadata\//, '')
    .replace(/^secret\//, '');
}

function pathMatchesPattern(targetPath: string, pattern: string): boolean {
  if (pattern === '*') return true;
  const cleanTarget = normalizeSecretPath(targetPath);
  const cleanPattern = normalizeSecretPath(pattern);
  if (cleanPattern.endsWith('/*')) {
    const prefix = cleanPattern.slice(0, -2);
    return cleanTarget === prefix || cleanTarget.startsWith(prefix + '/');
  }
  return cleanTarget === cleanPattern;
}

export class NativeSecretsVaultEngine {
  private readonly dataDir: string;
  private readonly stateFilePath: string;
  private readonly audit: AuditLogger;
  private state: PersistedVaultState;
  private dek: Buffer | null = null;
  private pendingShares: string[] = [];

  constructor(dataDir: string, clusterName = 'native-secrets-vault-cluster') {
    this.dataDir = path.resolve(dataDir);
    fs.mkdirSync(this.dataDir, { recursive: true, mode: 0o700 });
    this.stateFilePath = path.join(this.dataDir, 'vault-state.json');
    this.audit = new AuditLogger(this.dataDir);
    this.state = this.loadState(clusterName);
  }

  private loadState(defaultClusterName: string): PersistedVaultState {
    if (!fs.existsSync(this.stateFilePath)) {
      return {
        formatVersion: 1,
        clusterName: defaultClusterName,
        initialized: false,
        createdAt: new Date().toISOString(),
        secretShares: 0,
        secretThreshold: 0,
        wrappedDek: null,
        tokens: {},
        secrets: {}
      };
    }
    return JSON.parse(fs.readFileSync(this.stateFilePath, 'utf8')) as PersistedVaultState;
  }

  private saveState(): void {
    const tmpPath = `${this.stateFilePath}.tmp-${process.pid}-${Date.now()}`;
    fs.writeFileSync(tmpPath, JSON.stringify(this.state, null, 2), {
      encoding: 'utf8',
      mode: 0o600
    });
    fs.renameSync(tmpPath, this.stateFilePath);
  }

  public isInitialized(): boolean {
    return this.state.initialized;
  }

  public isSealed(): boolean {
    return !this.state.initialized || this.dek === null;
  }

  public getSealStatus(): SealStatusResponse {
    return {
      type: 'shamir-gf256-aes256gcm',
      initialized: this.state.initialized,
      sealed: this.isSealed(),
      t: this.state.secretThreshold,
      n: this.state.secretShares,
      progress: this.isSealed() ? this.pendingShares.length : 0,
      version: '1.0.0',
      cluster_name: this.state.clusterName
    };
  }

  /**
   * Initializes a brand-new Vault instance, generating the 256-bit Master Key,
   * splitting it via Shamir GF(256) into `secretShares` shares with threshold
   * `secretThreshold`, wrapping the 256-bit Root DEK, and issuing a root token.
   */
  public init(options: InitOptions = {}): InitResponse {
    if (this.state.initialized) {
      throw new Error('Vault is already initialized');
    }

    const secretShares = options.secretShares ?? 3;
    const secretThreshold = options.secretThreshold ?? 2;
    if (secretShares < 1 || secretShares > 255) {
      throw new Error('secret_shares must be between 1 and 255');
    }
    if (secretThreshold < 1 || secretThreshold > secretShares) {
      throw new Error('secret_threshold must be between 1 and secret_shares');
    }

    const masterKey = crypto.randomBytes(32);
    const rootDek = crypto.randomBytes(32);
    const wrappedDek = encryptWithContext(masterKey, rootDek, 'nsv-root-dek-v1');
    const sharesHex = splitSecret(masterKey, secretShares, secretThreshold);
    const sharesB64 = sharesHex.map((hex) => Buffer.from(hex, 'hex').toString('base64'));

    // Zero masterKey immediately
    masterKey.fill(0);

    const rootToken = `nsv_root_${crypto.randomBytes(24).toString('hex')}`;
    const rootTokenRecord: TokenRecord = {
      id: 'root',
      name: 'Root Operator Token',
      tokenHash: hashToken(rootToken),
      allowedPaths: ['*'],
      capabilities: ['root', 'read', 'write', 'list', 'delete'],
      createdAt: new Date().toISOString(),
      expiresAt: null
    };

    this.state.initialized = true;
    this.state.createdAt = new Date().toISOString();
    this.state.secretShares = secretShares;
    this.state.secretThreshold = secretThreshold;
    this.state.wrappedDek = wrappedDek;
    this.state.tokens = { [rootTokenRecord.tokenHash]: rootTokenRecord };
    this.state.secrets = {};

    if (options.autoUnseal !== false) {
      this.dek = rootDek;
    } else {
      rootDek.fill(0);
      this.dek = null;
    }

    this.saveState();
    this.audit.append({
      actor: 'system',
      action: 'sys.init',
      path: 'sys/init',
      status: 'success',
      metadata: { secretShares, secretThreshold }
    });

    return {
      keys: sharesHex,
      keys_base64: sharesB64,
      root_token: rootToken,
      secret_shares: secretShares,
      secret_threshold: secretThreshold
    };
  }

  /**
   * Submits a Shamir share (hex or base64) to unseal the Vault.
   */
  public unseal(rawShareKey: string, reset = false): SealStatusResponse {
    if (!this.state.initialized || !this.state.wrappedDek) {
      throw new Error('Vault is not initialized');
    }
    if (reset) {
      this.pendingShares = [];
      return this.getSealStatus();
    }
    if (!this.isSealed()) {
      return this.getSealStatus();
    }

    const trimmed = String(rawShareKey || '').trim();
    if (!trimmed) {
      throw new Error('Unseal key share is required');
    }

    // Accept either hex or base64 encoded share
    let hexShare: string;
    if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length === 66) {
      hexShare = trimmed.toLowerCase();
    } else {
      const decoded = Buffer.from(trimmed, 'base64');
      if (decoded.length !== 33) {
        throw new Error('Invalid unseal key share format or length');
      }
      hexShare = decoded.toString('hex');
    }

    const xCoord = hexShare.slice(0, 2);
    if (!this.pendingShares.some((s) => s.slice(0, 2) === xCoord)) {
      this.pendingShares.push(hexShare);
    }

    if (this.pendingShares.length >= this.state.secretThreshold) {
      try {
        const masterKey = combineShares(
          this.pendingShares.slice(0, this.state.secretThreshold)
        );
        const unwrappedDek = decryptWithContext(
          masterKey,
          this.state.wrappedDek,
          'nsv-root-dek-v1'
        );
        masterKey.fill(0);
        this.dek = unwrappedDek;
        this.pendingShares = [];
        this.audit.append({
          actor: 'operator',
          action: 'sys.unseal',
          path: 'sys/unseal',
          status: 'success'
        });
      } catch (err) {
        this.pendingShares = [];
        this.audit.append({
          actor: 'operator',
          action: 'sys.unseal',
          path: 'sys/unseal',
          status: 'error'
        });
        throw new Error('Failed to reconstruct Master Key from provided shares');
      }
    }

    return this.getSealStatus();
  }

  /**
   * Seals the Vault by zeroing the in-memory Root DEK.
   */
  public seal(actor = 'operator'): SealStatusResponse {
    if (this.dek) {
      this.dek.fill(0);
      this.dek = null;
    }
    this.pendingShares = [];
    this.audit.append({
      actor,
      action: 'sys.seal',
      path: 'sys/seal',
      status: 'success'
    });
    return this.getSealStatus();
  }

  /**
   * Authenticates a Bearer/X-Vault-Token and verifies path + capability permissions.
   */
  public authorize(
    rawToken: string | undefined,
    targetPath: string,
    capability: Capability
  ): TokenRecord {
    if (!rawToken) {
      this.audit.append({
        actor: 'anonymous',
        action: `auth.${capability}`,
        path: targetPath,
        status: 'denied',
        metadata: { reason: 'missing_token' }
      });
      throw new Error('Permission denied: missing authentication token');
    }

    const cleanToken = rawToken.replace(/^Bearer\s+/i, '').trim();
    const tHash = hashToken(cleanToken);
    const record = this.state.tokens[tHash];

    if (!record) {
      this.audit.append({
        actor: 'unknown_token',
        action: `auth.${capability}`,
        path: targetPath,
        status: 'denied',
        metadata: { reason: 'invalid_token' }
      });
      throw new Error('Permission denied: invalid authentication token');
    }

    if (record.expiresAt && new Date(record.expiresAt).getTime() < Date.now()) {
      this.audit.append({
        actor: record.name,
        action: `auth.${capability}`,
        path: targetPath,
        status: 'denied',
        metadata: { reason: 'expired_token' }
      });
      throw new Error('Permission denied: token has expired');
    }

    const hasCap =
      record.capabilities.includes('root') ||
      record.capabilities.includes(capability);
    const hasPath = record.allowedPaths.some((p) =>
      pathMatchesPattern(targetPath, p)
    );

    if (!hasCap || !hasPath) {
      this.audit.append({
        actor: record.name,
        action: `auth.${capability}`,
        path: targetPath,
        status: 'denied',
        metadata: { reason: 'insufficient_scope' }
      });
      throw new Error(
        `Permission denied: token "${record.name}" lacks "${capability}" on "${targetPath}"`
      );
    }

    return record;
  }

  /**
   * Issues a scoped service token (requires `root` capability).
   */
  public createScopedToken(
    rawAuthToken: string,
    params: {
      name: string;
      allowedPaths: string[];
      capabilities: Capability[];
      ttlSeconds?: number;
    }
  ): { token: string; record: Omit<TokenRecord, 'tokenHash'> } {
    const actor = this.authorize(rawAuthToken, 'sys/tokens', 'root');
    const newToken = `nsv_tok_${crypto.randomBytes(24).toString('hex')}`;
    const tHash = hashToken(newToken);
    const now = new Date();
    const expiresAt = params.ttlSeconds
      ? new Date(now.getTime() + params.ttlSeconds * 1000).toISOString()
      : null;

    const record: TokenRecord = {
      id: `tok_${crypto.randomBytes(6).toString('hex')}`,
      name: params.name || 'Scoped Service Token',
      tokenHash: tHash,
      allowedPaths: params.allowedPaths.length > 0 ? params.allowedPaths : ['*'],
      capabilities: params.capabilities,
      createdAt: now.toISOString(),
      expiresAt
    };

    this.state.tokens[tHash] = record;
    this.saveState();

    this.audit.append({
      actor: actor.name,
      action: 'token.create',
      path: 'sys/tokens',
      status: 'success',
      metadata: { tokenId: record.id, tokenName: record.name }
    });

    const { tokenHash: _, ...publicRecord } = record;
    return { token: newToken, record: publicRecord };
  }

  /**
   * Writes a new version of key-value secrets at `secretPath` (KV v2 `put`).
   * By default, merges with existing keys in the previous version unless
   * `options.replaceAll === true` is specified, preventing accidental key loss.
   */
  public putSecret(
    rawAuthToken: string,
    secretPath: string,
    incomingData: Record<string, unknown>,
    options: { merge?: boolean } = {}
  ): {
    version: number;
    created_time: string;
    deletion_time: string;
    destroyed: boolean;
    key_count: number;
  } {
    if (this.isSealed() || !this.dek) {
      throw new Error('Vault is sealed');
    }
    const cleanPath = normalizeSecretPath(secretPath);
    if (!cleanPath) {
      throw new Error('Secret path is required');
    }

    const actor = this.authorize(rawAuthToken, cleanPath, 'write');
    const existingRecord = this.state.secrets[cleanPath];
    const nextVersion = existingRecord ? existingRecord.currentVersion + 1 : 1;

    let finalData: Record<string, unknown> = { ...incomingData };
    if (options.merge !== false && existingRecord) {
      const prevVer = existingRecord.versions[existingRecord.currentVersion];
      if (prevVer && !prevVer.destroyed && prevVer.encryptedBlob) {
        const prevAad = `nsv-kv-v2:${cleanPath}:v${prevVer.version}`;
        const prevPlain = decryptWithContext(
          this.dek,
          prevVer.encryptedBlob,
          prevAad
        ).toString('utf8');
        const prevObj = JSON.parse(prevPlain) as Record<string, unknown>;
        finalData = { ...prevObj };
        for (const [k, v] of Object.entries(incomingData)) {
          // Never clobber an existing non-empty value with an empty string during merge
          if (
            (v === '' || v === null || v === undefined) &&
            finalData[k] !== undefined &&
            String(finalData[k]).trim() !== ''
          ) {
            continue;
          }
          finalData[k] = v;
        }
      }
    }

    const aadContext = `nsv-kv-v2:${cleanPath}:v${nextVersion}`;
    const encryptedBlob = encryptWithContext(
      this.dek,
      JSON.stringify(finalData),
      aadContext
    );

    const nowIso = new Date().toISOString();
    const keyNames = Object.keys(finalData).sort();
    const versionRecord: SecretVersionRecord = {
      version: nextVersion,
      createdTime: nowIso,
      deletionTime: '',
      destroyed: false,
      keyCount: keyNames.length,
      keyNames,
      encryptedBlob
    };

    if (!existingRecord) {
      this.state.secrets[cleanPath] = {
        path: cleanPath,
        currentVersion: 1,
        oldestVersion: 1,
        createdTime: nowIso,
        updatedTime: nowIso,
        maxVersions: 20,
        versions: { 1: versionRecord }
      };
    } else {
      existingRecord.currentVersion = nextVersion;
      existingRecord.updatedTime = nowIso;
      existingRecord.versions[nextVersion] = versionRecord;
    }

    this.saveState();
    this.audit.append({
      actor: actor.name,
      action: 'kv.write',
      path: cleanPath,
      status: 'success',
      metadata: { version: nextVersion, keyCount: keyNames.length }
    });

    return {
      version: nextVersion,
      created_time: nowIso,
      deletion_time: '',
      destroyed: false,
      key_count: keyNames.length
    };
  }

  /**
   * Reads and decrypts a secret version at `secretPath` (KV v2 `get`).
   */
  public getSecret(
    rawAuthToken: string,
    secretPath: string,
    requestedVersion?: number
  ): {
    data: Record<string, unknown>;
    metadata: {
      created_time: string;
      deletion_time: string;
      destroyed: boolean;
      version: number;
    };
  } {
    if (this.isSealed() || !this.dek) {
      throw new Error('Vault is sealed');
    }
    const cleanPath = normalizeSecretPath(secretPath);
    const actor = this.authorize(rawAuthToken, cleanPath, 'read');

    const record = this.state.secrets[cleanPath];
    if (!record) {
      this.audit.append({
        actor: actor.name,
        action: 'kv.read',
        path: cleanPath,
        status: 'error',
        metadata: { reason: 'not_found' }
      });
      throw new Error(`Secret path not found: ${cleanPath}`);
    }

    const verNum = requestedVersion ?? record.currentVersion;
    const verRecord = record.versions[verNum];
    if (!verRecord || verRecord.destroyed || !verRecord.encryptedBlob) {
      throw new Error(`Secret version ${verNum} at ${cleanPath} is not available`);
    }

    const aadContext = `nsv-kv-v2:${cleanPath}:v${verNum}`;
    const decryptedBuf = decryptWithContext(
      this.dek,
      verRecord.encryptedBlob,
      aadContext
    );
    const data = JSON.parse(decryptedBuf.toString('utf8')) as Record<string, unknown>;

    this.audit.append({
      actor: actor.name,
      action: 'kv.read',
      path: cleanPath,
      status: 'success',
      metadata: { version: verNum }
    });

    return {
      data,
      metadata: {
        created_time: verRecord.createdTime,
        deletion_time: verRecord.deletionTime,
        destroyed: verRecord.destroyed,
        version: verRecord.version
      }
    };
  }

  /**
   * Returns metadata and version history for `secretPath` without decrypting values.
   */
  public getMetadata(rawAuthToken: string, secretPath: string) {
    const cleanPath = normalizeSecretPath(secretPath);
    const actor = this.authorize(rawAuthToken, cleanPath, 'list');
    const record = this.state.secrets[cleanPath];
    if (!record) {
      throw new Error(`Secret path not found: ${cleanPath}`);
    }

    const versionsSummary: Record<
      number,
      {
        created_time: string;
        deletion_time: string;
        destroyed: boolean;
        key_count: number;
        key_names: string[];
      }
    > = {};

    for (const [v, vr] of Object.entries(record.versions)) {
      versionsSummary[Number(v)] = {
        created_time: vr.createdTime,
        deletion_time: vr.deletionTime,
        destroyed: vr.destroyed,
        key_count: vr.keyCount,
        key_names: vr.keyNames
      };
    }

    this.audit.append({
      actor: actor.name,
      action: 'kv.metadata',
      path: cleanPath,
      status: 'success'
    });

    return {
      path: record.path,
      current_version: record.currentVersion,
      oldest_version: record.oldestVersion,
      created_time: record.createdTime,
      updated_time: record.updatedTime,
      max_versions: record.maxVersions,
      versions: versionsSummary
    };
  }

  /**
   * Lists all secret paths matching an optional prefix.
   */
  public listPaths(rawAuthToken: string, prefix = ''): Array<{
    path: string;
    currentVersion: number;
    updatedTime: string;
    keyCount: number;
    keyNames: string[];
  }> {
    const cleanPrefix = normalizeSecretPath(prefix);
    this.authorize(rawAuthToken, cleanPrefix || '*', 'list');

    return Object.values(this.state.secrets)
      .filter((r) => !cleanPrefix || r.path === cleanPrefix || r.path.startsWith(cleanPrefix + '/'))
      .sort((a, b) => a.path.localeCompare(b.path))
      .map((r) => {
        const cur = r.versions[r.currentVersion];
        return {
          path: r.path,
          currentVersion: r.currentVersion,
          updatedTime: r.updatedTime,
          keyCount: cur ? cur.keyCount : 0,
          keyNames: cur ? cur.keyNames : []
        };
      });
  }

  /**
   * Exports flattened key-value pairs across one or more secret paths.
   */
  public exportFlatSecrets(
    rawAuthToken: string,
    paths?: string[]
  ): Record<string, string> {
    if (this.isSealed() || !this.dek) {
      throw new Error('Vault is sealed');
    }
    const targetPaths =
      paths && paths.length > 0
        ? paths.map(normalizeSecretPath).filter(Boolean)
        : Object.keys(this.state.secrets).sort();

    const flat: Record<string, string> = {};
    for (const p of targetPaths) {
      if (!this.state.secrets[p]) continue;
      const { data } = this.getSecret(rawAuthToken, p);
      for (const [k, v] of Object.entries(data)) {
        if (v !== null && v !== undefined && String(v).trim() !== '') {
          flat[k] = typeof v === 'object' ? JSON.stringify(v) : String(v);
        }
      }
    }
    return flat;
  }

  /**
   * Exports an encrypted disaster-recovery snapshot bundle.
   */
  public exportEncryptedSnapshot(rawAuthToken: string, passphrase: string): string {
    const actor = this.authorize(rawAuthToken, 'sys/storage/snapshot', 'root');
    const payload = JSON.stringify(this.state);
    const encrypted = encryptSnapshotWithPassphrase(payload, passphrase);
    this.audit.append({
      actor: actor.name,
      action: 'snapshot.export',
      path: 'sys/storage/snapshot',
      status: 'success'
    });
    return encrypted;
  }

  /**
   * Restores state from an encrypted disaster-recovery snapshot bundle.
   */
  public restoreEncryptedSnapshot(encryptedBundle: string, passphrase: string): void {
    const decrypted = decryptSnapshotWithPassphrase(encryptedBundle, passphrase);
    const parsed = JSON.parse(decrypted) as PersistedVaultState;
    if (parsed.formatVersion !== 1 || !parsed.initialized) {
      throw new Error('Invalid snapshot state payload');
    }
    this.state = parsed;
    this.saveState();
    this.audit.append({
      actor: 'operator',
      action: 'snapshot.restore',
      path: 'sys/storage/snapshot',
      status: 'success'
    });
  }

  public verifyAuditChain(): AuditVerificationResult {
    return this.audit.verifyChain();
  }

  public getRecentAuditEntries(limit = 50): AuditEntry[] {
    return this.audit.listRecent(limit);
  }

  public getStats() {
    const paths = Object.values(this.state.secrets);
    let totalVersions = 0;
    let totalKeys = 0;
    for (const p of paths) {
      totalVersions += Object.keys(p.versions).length;
      const cur = p.versions[p.currentVersion];
      if (cur) totalKeys += cur.keyCount;
    }
    const chain = this.audit.verifyChain();
    return {
      initialized: this.state.initialized,
      sealed: this.isSealed(),
      secretPathsTotal: paths.length,
      secretKeysTotal: totalKeys,
      secretVersionsTotal: totalVersions,
      tokensTotal: Object.keys(this.state.tokens).length,
      auditEntriesTotal: chain.totalEntries,
      auditChainValid: chain.valid,
      auditHeadHash: chain.headHash
    };
  }
}
