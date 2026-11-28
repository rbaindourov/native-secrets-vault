/**
 * src/browser/browserVaultService.ts
 * ──────────────────────────────────────────────────────────────────────────────
 * Winome Browser Credential, RFC 6238 TOTP, Sensitive Autofill & Service Key
 * Vault Layer built on top of `NativeSecretsVaultEngine` (`winome/<userId>/*`).
 *
 * Includes:
 *   - Version-coherent in-memory per-user domain index (`O(1)` origin autofill
 *     lookups without N+1 AES decryptions or audit log write amplification;
 *     wiped automatically whenever Vault is sealed)
 *   - Chunked batch credential upsert (`upsertLoginsBatch`) flushing
 *     `vault-state.json` once per chunk instead of once per credential
 */

import crypto from 'crypto';
import { URL } from 'url';
import { NativeSecretsVaultEngine } from '../storage/vaultEngine';
import {
  BrowserPasskeySummary,
  PasskeyAuthenticateRequest,
  PasskeyAuthenticateResult,
  PasskeyRegisterRequest,
  PasskeyRegisterResult,
  StoredPasskeyRecord,
  buildPasskeyAssertion,
  buildPasskeyRegistration,
  sanitizePasskeySummary,
  validateRpIdForOrigin
} from './webauthnPasskey';

export interface BrowserLoginInput {
  id?: string;
  origin: string;
  signonRealm?: string;
  username: string;
  password: string;
  totpSecret?: string;
  formAction?: string;
  urls?: string[];
  notes?: string;
}

export interface BrowserLoginRecord {
  id: string;
  origin: string;
  registrableDomain: string;
  signonRealm: string;
  username: string;
  password: string;
  totpSecret?: string;
  totpCode?: string;
  totpRemainingSeconds?: number;
  formAction?: string;
  urls: string[];
  notes?: string;
  matchType?: 'exact_origin' | 'subdomain' | 'all';
  createdAt: string;
  updatedAt: string;
  lastUsedAt: string;
}

export type SensitiveFormCategory = 'payment_card' | 'identity_document' | 'secret_field';

export interface SensitiveFormInput {
  id?: string;
  category: SensitiveFormCategory;
  label: string;
  fields: Record<string, string>;
  origins?: string[];
}

export interface SensitiveFormRecord {
  id: string;
  category: SensitiveFormCategory;
  label: string;
  fields: Record<string, string>;
  origins: string[];
  createdAt: string;
  updatedAt: string;
}

export interface BrowserAuthTokenRecord {
  domain: string;
  cookies?: Array<{
    name: string;
    value: string;
    domain: string;
    path?: string;
    secure?: boolean;
    httpOnly?: boolean;
    sameSite?: string;
    expires?: number;
  }>;
  headers?: Record<string, string>;
  localStorageEntries?: Record<string, string>;
  updatedAt: string;
}

export interface BrowserServiceIntegrations {
  crmUrl?: string;
  crmApiKey?: string;
  cmsPitchUrl?: string;
  cmsPitchApiKey?: string;
  campaignsUrl?: string;
  campaignsApiKey?: string;
  updatedAt?: string;
}

interface CachedVersionedItem<T> {
  version: number;
  record: T;
}

const MULTI_PART_TLDS = new Set([
  'co.uk',
  'org.uk',
  'gov.uk',
  'ac.uk',
  'com.au',
  'net.au',
  'org.au',
  'co.nz',
  'co.jp',
  'com.br',
  'com.mx',
  'co.in',
  'com.sg'
]);

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const MAX_BATCH_UPSERT = 5000;

export function sanitizeVaultUserId(rawUserId: string): string {
  const clean = String(rawUserId || '').trim();
  if (!/^[a-zA-Z0-9._@-]{1,128}$/.test(clean) || clean.includes('..')) {
    throw new Error('Invalid browser vault userId');
  }
  return clean;
}

export function normalizeOriginUrl(rawUrlOrOrigin: string): {
  origin: string;
  hostname: string;
  registrableDomain: string;
} {
  const trimmed = String(rawUrlOrOrigin || '').trim();
  if (!trimmed) {
    throw new Error('Origin URL is required');
  }
  const withScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)
    ? trimmed
    : `https://${trimmed}`;

  const parsed = new URL(withScheme);
  const hostname = parsed.hostname.toLowerCase();
  const origin = parsed.origin.toLowerCase();
  const registrableDomain = extractRegistrableDomain(hostname);
  return { origin, hostname, registrableDomain };
}

export function extractRegistrableDomain(hostname: string): string {
  const clean = String(hostname || '').trim().toLowerCase().replace(/\.+$/, '');
  if (!clean || clean === 'localhost' || /^\d+\.\d+\.\d+\.\d+$/.test(clean) || clean.includes(':')) {
    return clean;
  }
  const parts = clean.split('.');
  if (parts.length <= 2) return clean;
  const lastTwo = parts.slice(-2).join('.');
  if (MULTI_PART_TLDS.has(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join('.');
  }
  return lastTwo;
}

export function decodeBase32Secret(rawSecret: string): Buffer {
  let secretStr = String(rawSecret || '').trim();
  if (secretStr.toLowerCase().startsWith('otpauth://')) {
    const u = new URL(secretStr);
    secretStr = u.searchParams.get('secret') || '';
  }
  const cleaned = secretStr.toUpperCase().replace(/[\s=-]+/g, '');
  if (!cleaned) {
    throw new Error('Empty TOTP Base32 secret');
  }

  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (let i = 0; i < cleaned.length; i++) {
    const idx = BASE32_ALPHABET.indexOf(cleaned[i]);
    if (idx === -1) {
      throw new Error(`Invalid Base32 character in TOTP secret: "${cleaned[i]}"`);
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

/**
 * Generates an RFC 6238 TOTP code from a Base32 secret or `otpauth://` URI.
 */
export function generateTotpCode(
  rawSecret: string,
  options: { nowMs?: number; periodSeconds?: number; digits?: number; algorithm?: 'sha1' | 'sha256' | 'sha512' } = {}
): { code: string; periodSeconds: number; remainingSeconds: number } {
  const periodSeconds = options.periodSeconds ?? 30;
  const digits = options.digits ?? 6;
  const algorithm = options.algorithm ?? 'sha1';
  const nowMs = options.nowMs ?? Date.now();

  const key = decodeBase32Secret(rawSecret);
  const epochSeconds = Math.floor(nowMs / 1000);
  const counter = Math.floor(epochSeconds / periodSeconds);
  const remainingSeconds = periodSeconds - (epochSeconds % periodSeconds);

  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(counter), 0);

  const digest = crypto.createHmac(algorithm, key).update(counterBuf).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);

  const mod = Math.pow(10, digits);
  const code = String(binary % mod).padStart(digits, '0');
  return { code, periodSeconds, remainingSeconds };
}

function deterministicCredentialId(origin: string, username: string): string {
  const digest = crypto
    .createHash('sha256')
    .update(`${origin.toLowerCase()}|${username.trim().toLowerCase()}`, 'utf8')
    .digest('hex')
    .slice(0, 20);
  return `cred_${digest}`;
}

export class BrowserVaultService {
  private readonly loginCacheByUser = new Map<string, Map<string, CachedVersionedItem<BrowserLoginRecord>>>();
  private readonly sensitiveCacheByUser = new Map<string, Map<string, CachedVersionedItem<SensitiveFormRecord>>>();
  private readonly passkeyCacheByUser = new Map<string, Map<string, CachedVersionedItem<StoredPasskeyRecord>>>();

  constructor(private readonly engine: NativeSecretsVaultEngine) {}

  private ensureUnsealedOrClearCaches(): void {
    if (this.engine.isSealed()) {
      this.loginCacheByUser.clear();
      this.sensitiveCacheByUser.clear();
      this.passkeyCacheByUser.clear();
      throw new Error('Vault is sealed');
    }
  }

  private getHydratedUserLogins(rawToken: string, userId: string): Map<string, CachedVersionedItem<BrowserLoginRecord>> {
    this.ensureUnsealedOrClearCaches();
    const prefix = `winome/${userId}/logins`;
    this.engine.authorize(rawToken, `${prefix}/*`, 'read');
    const pathMeta = this.engine.listPaths(rawToken, prefix);

    let userMap = this.loginCacheByUser.get(userId);
    if (!userMap) {
      userMap = new Map();
      // Cold hydrate with a single aggregated audit entry instead of N individual kv.read writes
      const bulk = this.engine.getSecretsByPrefix(rawToken, prefix);
      for (const item of bulk) {
        const rec = item.data as unknown as BrowserLoginRecord;
        if (rec && rec.origin) {
          userMap.set(item.path, { version: item.version, record: rec });
        }
      }
      this.loginCacheByUser.set(userId, userMap);
      return userMap;
    }

    // Reconcile any externally added/updated/deleted paths via version metadata (0 disk writes when unchanged)
    const activePaths = new Set<string>();
    for (const meta of pathMeta) {
      activePaths.add(meta.path);
      const cached = userMap.get(meta.path);
      if (!cached || cached.version !== meta.currentVersion) {
        try {
          const { data, metadata } = this.engine.getSecret(rawToken, meta.path);
          const rec = data as unknown as BrowserLoginRecord;
          if (rec && rec.origin) {
            userMap.set(meta.path, { version: metadata.version, record: rec });
          }
        } catch (_) {}
      }
    }
    for (const cachedPath of Array.from(userMap.keys())) {
      if (!activePaths.has(cachedPath)) {
        userMap.delete(cachedPath);
      }
    }
    return userMap;
  }

  private buildLoginRecord(
    userId: string,
    input: BrowserLoginInput,
    nowIso: string,
    existingCreatedAt?: string
  ): { secretPath: string; record: BrowserLoginRecord; persistedPayload: Record<string, unknown> } {
    const { origin, registrableDomain } = normalizeOriginUrl(input.origin);
    const username = String(input.username || '').trim();
    const password = String(input.password ?? '');
    if (!password) {
      throw new Error('Password is required to store a browser credential');
    }

    const id =
      input.id && /^[a-zA-Z0-9_-]{4,64}$/.test(input.id)
        ? input.id
        : deterministicCredentialId(origin, username);

    const secretPath = `winome/${userId}/logins/${id}`;
    const record: BrowserLoginRecord = {
      id,
      origin,
      registrableDomain,
      signonRealm: input.signonRealm ? String(input.signonRealm).trim() : `${origin}/`,
      username,
      password,
      ...(input.totpSecret ? { totpSecret: String(input.totpSecret).trim() } : {}),
      ...(input.formAction ? { formAction: String(input.formAction).trim() } : {}),
      urls: Array.isArray(input.urls) && input.urls.length > 0 ? input.urls : [origin],
      ...(input.notes ? { notes: String(input.notes) } : {}),
      createdAt: existingCreatedAt || nowIso,
      updatedAt: nowIso,
      lastUsedAt: nowIso
    };

    if (record.totpSecret) {
      const totp = generateTotpCode(record.totpSecret);
      record.totpCode = totp.code;
      record.totpRemainingSeconds = totp.remainingSeconds;
    }

    const persistedPayload: Record<string, unknown> = { ...record };
    delete persistedPayload.totpCode;
    delete persistedPayload.totpRemainingSeconds;
    delete persistedPayload.matchType;

    return { secretPath, record, persistedPayload };
  }

  public upsertLogin(
    rawToken: string,
    rawUserId: string,
    input: BrowserLoginInput
  ): BrowserLoginRecord {
    this.ensureUnsealedOrClearCaches();
    const userId = sanitizeVaultUserId(rawUserId);
    const nowIso = new Date().toISOString();

    const { origin } = normalizeOriginUrl(input.origin);
    const username = String(input.username || '').trim();
    const id =
      input.id && /^[a-zA-Z0-9_-]{4,64}$/.test(input.id)
        ? input.id
        : deterministicCredentialId(origin, username);
    const secretPath = `winome/${userId}/logins/${id}`;

    let createdAt = nowIso;
    const cachedUserMap = this.loginCacheByUser.get(userId);
    const cachedExisting = cachedUserMap?.get(secretPath);
    if (cachedExisting?.record?.createdAt) {
      createdAt = cachedExisting.record.createdAt;
    } else {
      try {
        const existing = this.engine.getSecret(rawToken, secretPath);
        if (typeof existing.data.createdAt === 'string') {
          createdAt = existing.data.createdAt;
        }
      } catch (_) {}
    }

    const built = this.buildLoginRecord(userId, input, nowIso, createdAt);
    const meta = this.engine.putSecret(rawToken, built.secretPath, built.persistedPayload, {
      merge: false,
      skipIfUnchanged: true
    });
    if (cachedUserMap) {
      cachedUserMap.set(built.secretPath, { version: meta.version, record: built.record });
    }
    return built.record;
  }

  /**
   * Batch credential upsert (up to 5,000 logins per request) with SHA-256
   * content-hash no-op deduplication. Flushes `vault-state.json` ONCE only if
   * at least one credential actually changed, and appends 1 summary audit entry.
   */
  public upsertLoginsBatch(
    rawToken: string,
    rawUserId: string,
    inputs: BrowserLoginInput[]
  ): { upserted: number; mutated: number; skippedUnchanged: number; logins: BrowserLoginRecord[] } {
    this.ensureUnsealedOrClearCaches();
    const userId = sanitizeVaultUserId(rawUserId);
    if (!Array.isArray(inputs) || inputs.length === 0) {
      return { upserted: 0, mutated: 0, skippedUnchanged: 0, logins: [] };
    }
    if (inputs.length > MAX_BATCH_UPSERT) {
      throw new Error(`Batch size ${inputs.length} exceeds maximum chunk size of ${MAX_BATCH_UPSERT}`);
    }

    const userMap = this.getHydratedUserLogins(rawToken, userId);
    const nowIso = new Date().toISOString();
    // Deduplicate duplicate (origin + username) rows within the same batch (last wins)
    const dedupedByPath = new Map<
      string,
      { secretPath: string; record: BrowserLoginRecord; persistedPayload: Record<string, unknown> }
    >();

    for (const input of inputs) {
      const { origin } = normalizeOriginUrl(input.origin);
      const username = String(input.username || '').trim();
      const id =
        input.id && /^[a-zA-Z0-9_-]{4,64}$/.test(input.id)
          ? input.id
          : deterministicCredentialId(origin, username);
      const secretPath = `winome/${userId}/logins/${id}`;
      const existingCreatedAt = userMap.get(secretPath)?.record?.createdAt || nowIso;

      const built = this.buildLoginRecord(userId, input, nowIso, existingCreatedAt);
      dedupedByPath.set(secretPath, built);
    }

    const builtRecords = Array.from(dedupedByPath.values());
    const batchWrites = builtRecords.map((b) => ({
      path: b.secretPath,
      data: b.persistedPayload,
      merge: false,
      skipIfUnchanged: true
    }));

    const writeResults = this.engine.putSecretsBatch(
      rawToken,
      batchWrites,
      'browser.logins.ingest_batch'
    );
    let mutated = 0;
    let skippedUnchanged = 0;
    for (let i = 0; i < builtRecords.length; i++) {
      if (writeResults[i].unchanged) {
        skippedUnchanged++;
      } else {
        mutated++;
      }
      userMap.set(builtRecords[i].secretPath, {
        version: writeResults[i].version,
        record: builtRecords[i].record
      });
    }

    return {
      upserted: mutated,
      mutated,
      skippedUnchanged,
      logins: builtRecords.map((b) => b.record)
    };
  }

  public listLogins(
    rawToken: string,
    rawUserId: string,
    filterOriginOrUrl?: string
  ): BrowserLoginRecord[] {
    const userId = sanitizeVaultUserId(rawUserId);
    const userMap = this.getHydratedUserLogins(rawToken, userId);

    let targetOrigin = '';
    let targetRegDomain = '';
    if (filterOriginOrUrl && filterOriginOrUrl.trim()) {
      const norm = normalizeOriginUrl(filterOriginOrUrl);
      targetOrigin = norm.origin;
      targetRegDomain = norm.registrableDomain;
    }

    const results: BrowserLoginRecord[] = [];
    for (const { record: rec } of userMap.values()) {
      if (!rec || !rec.origin) continue;

      let matchType: BrowserLoginRecord['matchType'] = 'all';
      if (targetOrigin) {
        if (rec.origin.toLowerCase() === targetOrigin) {
          matchType = 'exact_origin';
        } else if (
          targetRegDomain &&
          rec.registrableDomain &&
          rec.registrableDomain.toLowerCase() === targetRegDomain
        ) {
          matchType = 'subdomain';
        } else {
          continue;
        }
      }

      const enriched: BrowserLoginRecord = { ...rec, matchType };
      if (rec.totpSecret) {
        try {
          const totp = generateTotpCode(rec.totpSecret);
          enriched.totpCode = totp.code;
          enriched.totpRemainingSeconds = totp.remainingSeconds;
        } catch (_) {}
      }
      results.push(enriched);
    }

    return results.sort((a, b) => {
      if (a.matchType !== b.matchType) {
        if (a.matchType === 'exact_origin') return -1;
        if (b.matchType === 'exact_origin') return 1;
      }
      return (b.updatedAt || '').localeCompare(a.updatedAt || '');
    });
  }

  public deleteLogin(rawToken: string, rawUserId: string, credentialId: string) {
    this.ensureUnsealedOrClearCaches();
    const userId = sanitizeVaultUserId(rawUserId);
    if (!/^[a-zA-Z0-9_-]{4,64}$/.test(credentialId)) {
      throw new Error('Invalid credentialId');
    }
    const secretPath = `winome/${userId}/logins/${credentialId}`;
    const res = this.engine.deleteSecret(rawToken, secretPath);
    this.loginCacheByUser.get(userId)?.delete(secretPath);
    return res;
  }

  private buildSensitiveFormRecord(
    input: SensitiveFormInput,
    nowIso: string,
    existingCreatedAt?: string,
    deterministicId = false
  ): SensitiveFormRecord {
    const allowedCategories: SensitiveFormCategory[] = [
      'payment_card',
      'identity_document',
      'secret_field'
    ];
    if (!allowedCategories.includes(input.category)) {
      throw new Error(`Invalid sensitive form category: ${input.category}`);
    }
    const label = String(input.label || '').trim();
    if (!label) {
      throw new Error('Label is required for sensitive form vault record');
    }
    if (!input.fields || typeof input.fields !== 'object' || Object.keys(input.fields).length === 0) {
      throw new Error('Sensitive form fields object must not be empty');
    }

    const id =
      input.id && /^[a-zA-Z0-9_-]{4,64}$/.test(input.id)
        ? input.id
        : deterministicId
        ? `sform_${crypto
            .createHash('sha256')
            .update(`${input.category}|${label.toLowerCase()}`, 'utf8')
            .digest('hex')
            .slice(0, 16)}`
        : `sform_${crypto.randomBytes(8).toString('hex')}`;

    const sanitizedFields: Record<string, string> = {};
    for (const [k, v] of Object.entries(input.fields)) {
      if (v !== undefined && v !== null) {
        sanitizedFields[String(k).trim()] = String(v);
      }
    }

    return {
      id,
      category: input.category,
      label,
      fields: sanitizedFields,
      origins: Array.isArray(input.origins) ? input.origins.map((o) => String(o).trim()).filter(Boolean) : [],
      createdAt: existingCreatedAt || nowIso,
      updatedAt: nowIso
    };
  }

  private getHydratedSensitiveForms(
    rawToken: string,
    userId: string
  ): Map<string, CachedVersionedItem<SensitiveFormRecord>> {
    this.ensureUnsealedOrClearCaches();
    const prefix = `winome/${userId}/sensitive-forms`;
    this.engine.authorize(rawToken, `${prefix}/*`, 'read');
    const entries = this.engine.listPaths(rawToken, prefix);

    let userMap = this.sensitiveCacheByUser.get(userId);
    if (!userMap) {
      userMap = new Map();
      const bulk = this.engine.getSecretsByPrefix(rawToken, prefix);
      for (const item of bulk) {
        userMap.set(item.path, {
          version: item.version,
          record: item.data as unknown as SensitiveFormRecord
        });
      }
      this.sensitiveCacheByUser.set(userId, userMap);
    } else {
      const activePaths = new Set<string>();
      for (const meta of entries) {
        activePaths.add(meta.path);
        const cached = userMap.get(meta.path);
        if (!cached || cached.version !== meta.currentVersion) {
          try {
            const { data, metadata } = this.engine.getSecret(rawToken, meta.path);
            userMap.set(meta.path, {
              version: metadata.version,
              record: data as unknown as SensitiveFormRecord
            });
          } catch (_) {}
        }
      }
      for (const k of Array.from(userMap.keys())) {
        if (!activePaths.has(k)) userMap.delete(k);
      }
    }
    return userMap;
  }

  public upsertSensitiveForm(
    rawToken: string,
    rawUserId: string,
    input: SensitiveFormInput
  ): SensitiveFormRecord {
    this.ensureUnsealedOrClearCaches();
    const userId = sanitizeVaultUserId(rawUserId);
    const nowIso = new Date().toISOString();
    const preliminary = this.buildSensitiveFormRecord(input, nowIso);
    const secretPath = `winome/${userId}/sensitive-forms/${preliminary.id}`;

    let createdAt = nowIso;
    const cachedForms = this.sensitiveCacheByUser.get(userId);
    if (cachedForms?.get(secretPath)?.record?.createdAt) {
      createdAt = cachedForms.get(secretPath)!.record.createdAt;
    } else {
      try {
        const existing = this.engine.getSecret(rawToken, secretPath);
        if (typeof existing.data.createdAt === 'string') {
          createdAt = existing.data.createdAt;
        }
      } catch (_) {}
    }

    const record: SensitiveFormRecord = { ...preliminary, createdAt };
    const meta = this.engine.putSecret(
      rawToken,
      secretPath,
      record as unknown as Record<string, unknown>,
      { merge: false, skipIfUnchanged: true }
    );
    if (cachedForms) {
      cachedForms.set(secretPath, { version: meta.version, record });
    }
    return record;
  }

  /**
   * Batch sensitive-form upsert (cards, addresses, non-web app entries) in one
   * SHA-256 deduplicated commit with zero N+1 disk flushes.
   */
  public upsertSensitiveFormsBatch(
    rawToken: string,
    rawUserId: string,
    inputs: SensitiveFormInput[]
  ): { upserted: number; mutated: number; skippedUnchanged: number; entries: SensitiveFormRecord[] } {
    this.ensureUnsealedOrClearCaches();
    const userId = sanitizeVaultUserId(rawUserId);
    if (!Array.isArray(inputs) || inputs.length === 0) {
      return { upserted: 0, mutated: 0, skippedUnchanged: 0, entries: [] };
    }
    if (inputs.length > MAX_BATCH_UPSERT) {
      throw new Error(`Batch size ${inputs.length} exceeds maximum chunk size of ${MAX_BATCH_UPSERT}`);
    }

    const userMap = this.getHydratedSensitiveForms(rawToken, userId);
    const nowIso = new Date().toISOString();
    const dedupedByPath = new Map<string, { secretPath: string; record: SensitiveFormRecord }>();

    for (const input of inputs) {
      const prelim = this.buildSensitiveFormRecord(input, nowIso, undefined, true);
      const secretPath = `winome/${userId}/sensitive-forms/${prelim.id}`;
      const existingCreatedAt = userMap.get(secretPath)?.record?.createdAt || nowIso;
      dedupedByPath.set(secretPath, {
        secretPath,
        record: { ...prelim, createdAt: existingCreatedAt }
      });
    }

    const built = Array.from(dedupedByPath.values());
    const writes = built.map((b) => ({
      path: b.secretPath,
      data: b.record as unknown as Record<string, unknown>,
      merge: false,
      skipIfUnchanged: true
    }));

    const writeResults = this.engine.putSecretsBatch(
      rawToken,
      writes,
      'browser.sensitive_forms.ingest_batch'
    );
    let mutated = 0;
    let skippedUnchanged = 0;
    for (let i = 0; i < built.length; i++) {
      if (writeResults[i].unchanged) {
        skippedUnchanged++;
      } else {
        mutated++;
      }
      userMap.set(built[i].secretPath, {
        version: writeResults[i].version,
        record: built[i].record
      });
    }

    return {
      upserted: mutated,
      mutated,
      skippedUnchanged,
      entries: built.map((b) => b.record)
    };
  }

  public listSensitiveForms(
    rawToken: string,
    rawUserId: string,
    category?: string
  ): SensitiveFormRecord[] {
    const userId = sanitizeVaultUserId(rawUserId);
    const userMap = this.getHydratedSensitiveForms(rawToken, userId);

    const out: SensitiveFormRecord[] = [];
    for (const { record: rec } of userMap.values()) {
      if (category && rec.category !== category) continue;
      out.push(rec);
    }
    return out.sort((a, b) => (b.updatedAt || '').localeCompare(a.updatedAt || ''));
  }

  public deleteSensitiveForm(rawToken: string, rawUserId: string, entryId: string) {
    this.ensureUnsealedOrClearCaches();
    const userId = sanitizeVaultUserId(rawUserId);
    if (!/^[a-zA-Z0-9_-]{4,64}$/.test(entryId)) {
      throw new Error('Invalid entryId');
    }
    const secretPath = `winome/${userId}/sensitive-forms/${entryId}`;
    const res = this.engine.deleteSecret(rawToken, secretPath);
    this.sensitiveCacheByUser.get(userId)?.delete(secretPath);
    return res;
  }

  public putAuthTokens(
    rawToken: string,
    rawUserId: string,
    domain: string,
    payload: Omit<BrowserAuthTokenRecord, 'domain' | 'updatedAt'>
  ): BrowserAuthTokenRecord {
    const userId = sanitizeVaultUserId(rawUserId);
    const cleanDomain = extractRegistrableDomain(domain);
    if (!cleanDomain || !/^[a-z0-9.-]+$/.test(cleanDomain)) {
      throw new Error('Invalid domain for auth-tokens record');
    }
    const record: BrowserAuthTokenRecord = {
      domain: cleanDomain,
      cookies: Array.isArray(payload.cookies) ? payload.cookies : [],
      headers: payload.headers || {},
      localStorageEntries: payload.localStorageEntries || {},
      updatedAt: new Date().toISOString()
    };
    this.engine.putSecret(
      rawToken,
      `winome/${userId}/auth-tokens/${cleanDomain}`,
      record as unknown as Record<string, unknown>,
      { merge: false, skipIfUnchanged: true, maxVersions: 5 }
    );
    return record;
  }

  public getAuthTokens(
    rawToken: string,
    rawUserId: string,
    domain: string
  ): BrowserAuthTokenRecord {
    const userId = sanitizeVaultUserId(rawUserId);
    const cleanDomain = extractRegistrableDomain(domain);
    const { data } = this.engine.getSecret(rawToken, `winome/${userId}/auth-tokens/${cleanDomain}`);
    return data as unknown as BrowserAuthTokenRecord;
  }

  public putIntegrations(
    rawToken: string,
    rawUserId: string,
    input: BrowserServiceIntegrations
  ): BrowserServiceIntegrations {
    const userId = sanitizeVaultUserId(rawUserId);
    const payload: Record<string, unknown> = {
      ...input,
      updatedAt: new Date().toISOString()
    };
    this.engine.putSecret(rawToken, `winome/${userId}/integrations`, payload, { merge: true });
    const { data } = this.engine.getSecret(rawToken, `winome/${userId}/integrations`);
    return data as unknown as BrowserServiceIntegrations;
  }

  public getIntegrations(
    rawToken: string,
    rawUserId: string
  ): BrowserServiceIntegrations {
    const userId = sanitizeVaultUserId(rawUserId);
    try {
      const { data } = this.engine.getSecret(rawToken, `winome/${userId}/integrations`);
      return data as unknown as BrowserServiceIntegrations;
    } catch (err: any) {
      if (String(err?.message || '').includes('not found')) {
        return {};
      }
      throw err;
    }
  }

  private getHydratedPasskeys(
    rawToken: string,
    userId: string
  ): Map<string, CachedVersionedItem<StoredPasskeyRecord>> {
    this.ensureUnsealedOrClearCaches();
    const prefix = `winome/${userId}/passkeys`;
    this.engine.authorize(rawToken, `${prefix}/*`, 'read');
    const entries = this.engine.listPaths(rawToken, prefix);

    let userMap = this.passkeyCacheByUser.get(userId);
    if (!userMap) {
      userMap = new Map();
      const bulk = this.engine.getSecretsByPrefix(rawToken, prefix);
      for (const item of bulk) {
        const rec = item.data as unknown as StoredPasskeyRecord;
        if (rec && rec.credentialId && rec.rpId) {
          userMap.set(item.path, { version: item.version, record: rec });
        }
      }
      this.passkeyCacheByUser.set(userId, userMap);
      return userMap;
    }

    const activePaths = new Set<string>();
    for (const meta of entries) {
      activePaths.add(meta.path);
      const cached = userMap.get(meta.path);
      if (!cached || cached.version !== meta.currentVersion) {
        try {
          const { data, metadata } = this.engine.getSecret(rawToken, meta.path);
          const rec = data as unknown as StoredPasskeyRecord;
          if (rec && rec.credentialId && rec.rpId) {
            userMap.set(meta.path, { version: metadata.version, record: rec });
          }
        } catch (_) {}
      }
    }
    for (const k of Array.from(userMap.keys())) {
      if (!activePaths.has(k)) {
        userMap.delete(k);
      }
    }
    return userMap;
  }

  public listPasskeys(
    rawToken: string,
    rawUserId: string,
    filter: { origin?: string; rpId?: string } = {}
  ): BrowserPasskeySummary[] {
    const userId = sanitizeVaultUserId(rawUserId);
    const userMap = this.getHydratedPasskeys(rawToken, userId);

    let targetRpId = filter.rpId ? String(filter.rpId).trim().toLowerCase().replace(/\.+$/, '') : '';
    let originHost = '';
    if (filter.origin && filter.origin.trim()) {
      const norm = normalizeOriginUrl(filter.origin);
      originHost = norm.hostname;
      if (targetRpId) {
        const validated = validateRpIdForOrigin(targetRpId, norm.origin);
        targetRpId = validated.effectiveRpId;
      }
    }

    const out: BrowserPasskeySummary[] = [];
    for (const { record: rec } of userMap.values()) {
      if (!rec || !rec.rpId || !rec.credentialId) continue;
      const recRp = rec.rpId.toLowerCase();

      let matchType: BrowserPasskeySummary['matchType'] = 'all';
      if (targetRpId) {
        if (recRp !== targetRpId) continue;
        matchType = 'exact_rpid';
      } else if (originHost) {
        if (originHost === recRp) {
          matchType = 'exact_rpid';
        } else if (originHost.endsWith(`.${recRp}`)) {
          matchType = 'parent_rpid';
        } else {
          continue;
        }
      }

      out.push(sanitizePasskeySummary(rec, matchType));
    }

    return out.sort((a, b) => {
      if (a.matchType !== b.matchType) {
        if (a.matchType === 'exact_rpid') return -1;
        if (b.matchType === 'exact_rpid') return 1;
      }
      return (b.lastUsedAt || b.updatedAt || '').localeCompare(a.lastUsedAt || a.updatedAt || '');
    });
  }

  public registerPasskey(
    rawToken: string,
    rawUserId: string,
    input: PasskeyRegisterRequest
  ): PasskeyRegisterResult {
    this.ensureUnsealedOrClearCaches();
    const userId = sanitizeVaultUserId(rawUserId);
    const { normalizedOrigin, effectiveRpId } = validateRpIdForOrigin(input.rpId, input.origin);
    const { registrableDomain } = normalizeOriginUrl(normalizedOrigin);

    const userMap = this.getHydratedPasskeys(rawToken, userId);
    const excludedSet = new Set(
      (input.excludeCredentialIds || []).map((id) => String(id || '').trim()).filter(Boolean)
    );

    if (excludedSet.size > 0) {
      for (const { record: existing } of userMap.values()) {
        if (
          existing.rpId.toLowerCase() === effectiveRpId &&
          excludedSet.has(existing.credentialId)
        ) {
          throw new Error(
            `InvalidStateError: Passkey ${existing.credentialId} is already registered in Vault for ${effectiveRpId}`
          );
        }
      }
    }

    const nowIso = new Date().toISOString();
    const { storedRecord, response } = buildPasskeyRegistration(
      { ...input, origin: normalizedOrigin, rpId: effectiveRpId },
      registrableDomain,
      nowIso
    );

    const secretPath = `winome/${userId}/passkeys/${storedRecord.id}`;
    const meta = this.engine.putSecret(
      rawToken,
      secretPath,
      storedRecord as unknown as Record<string, unknown>,
      { merge: false, skipIfUnchanged: true, maxVersions: 5 }
    );
    userMap.set(secretPath, { version: meta.version, record: storedRecord });

    return response;
  }

  public authenticatePasskey(
    rawToken: string,
    rawUserId: string,
    input: PasskeyAuthenticateRequest
  ): PasskeyAuthenticateResult {
    this.ensureUnsealedOrClearCaches();
    const userId = sanitizeVaultUserId(rawUserId);
    const { normalizedOrigin, effectiveRpId } = validateRpIdForOrigin(input.rpId, input.origin);
    const userMap = this.getHydratedPasskeys(rawToken, userId);

    const allowSet = new Set(
      (input.allowCredentialIds || []).map((id) => String(id || '').trim()).filter(Boolean)
    );
    const requestedCredId = input.credentialId ? String(input.credentialId).trim() : '';

    const candidates: Array<{ secretPath: string; record: StoredPasskeyRecord }> = [];
    for (const [secretPath, { record: rec }] of userMap.entries()) {
      if (!rec || rec.rpId.toLowerCase() !== effectiveRpId) continue;
      if (requestedCredId && rec.credentialId !== requestedCredId && rec.id !== requestedCredId) {
        continue;
      }
      if (allowSet.size > 0 && !allowSet.has(rec.credentialId)) {
        continue;
      }
      candidates.push({ secretPath, record: rec });
    }

    if (candidates.length === 0) {
      throw new Error(`NotAllowedError: Matching passkey not found in Vault for ${effectiveRpId}`);
    }

    candidates.sort((a, b) =>
      (b.record.lastUsedAt || b.record.updatedAt || '').localeCompare(
        a.record.lastUsedAt || a.record.updatedAt || ''
      )
    );
    const chosen = candidates[0];

    const signed = buildPasskeyAssertion(chosen.record, {
      ...input,
      origin: normalizedOrigin,
      rpId: effectiveRpId
    });

    const nowIso = new Date().toISOString();
    const updatedRecord: StoredPasskeyRecord = {
      ...chosen.record,
      usageCount: (Number(chosen.record.usageCount) || 0) + 1,
      updatedAt: nowIso,
      lastUsedAt: nowIso
    };

    const meta = this.engine.putSecret(
      rawToken,
      chosen.secretPath,
      updatedRecord as unknown as Record<string, unknown>,
      { merge: false, skipIfUnchanged: true, maxVersions: 5 }
    );
    userMap.set(chosen.secretPath, { version: meta.version, record: updatedRecord });

    return {
      passkey: sanitizePasskeySummary(updatedRecord, 'exact_rpid'),
      assertion: {
        id: updatedRecord.credentialId,
        rawIdBase64Url: updatedRecord.credentialId,
        type: 'public-key',
        authenticatorAttachment: 'platform',
        clientDataJSONBase64Url: signed.clientDataJSONBase64Url,
        authenticatorDataBase64Url: signed.authenticatorDataBase64Url,
        signatureBase64Url: signed.signatureBase64Url,
        userHandleBase64Url: updatedRecord.userHandleBase64Url,
        clientExtensionResults: {}
      }
    };
  }

  public deletePasskey(rawToken: string, rawUserId: string, passkeyIdOrCredentialId: string) {
    this.ensureUnsealedOrClearCaches();
    const userId = sanitizeVaultUserId(rawUserId);
    const cleanTarget = String(passkeyIdOrCredentialId || '').trim();
    if (!cleanTarget || !/^[a-zA-Z0-9_-]{4,128}$/.test(cleanTarget)) {
      throw new Error('Invalid passkey identifier');
    }

    const userMap = this.getHydratedPasskeys(rawToken, userId);
    let targetPath = `winome/${userId}/passkeys/${cleanTarget}`;
    if (!userMap.has(targetPath)) {
      for (const [p, { record }] of userMap.entries()) {
        if (record.id === cleanTarget || record.credentialId === cleanTarget) {
          targetPath = p;
          break;
        }
      }
    }

    const res = this.engine.deleteSecret(rawToken, targetPath);
    userMap.delete(targetPath);
    return res;
  }

  public updatePasskey(
    rawToken: string,
    rawUserId: string,
    passkeyIdOrCredentialId: string,
    updates: { label?: string; userName?: string; userDisplayName?: string }
  ): BrowserPasskeySummary {
    this.ensureUnsealedOrClearCaches();
    const userId = sanitizeVaultUserId(rawUserId);
    const cleanTarget = String(passkeyIdOrCredentialId || '').trim();
    if (!cleanTarget || !/^[a-zA-Z0-9_-]{4,128}$/.test(cleanTarget)) {
      throw new Error('Invalid passkey identifier');
    }

    const userMap = this.getHydratedPasskeys(rawToken, userId);
    let targetEntry: { secretPath: string; record: StoredPasskeyRecord } | null = null;
    const directPath = `winome/${userId}/passkeys/${cleanTarget}`;
    const directHit = userMap.get(directPath);
    if (directHit) {
      targetEntry = { secretPath: directPath, record: directHit.record };
    } else {
      for (const [p, { record }] of userMap.entries()) {
        if (record.id === cleanTarget || record.credentialId === cleanTarget) {
          targetEntry = { secretPath: p, record };
          break;
        }
      }
    }

    if (!targetEntry) {
      throw new Error(`Passkey not found: ${cleanTarget}`);
    }

    const nowIso = new Date().toISOString();
    const updatedRecord: StoredPasskeyRecord = {
      ...targetEntry.record,
      ...(typeof updates.label === 'string' ? { label: updates.label.trim() } : {}),
      ...(typeof updates.userName === 'string' && updates.userName.trim()
        ? { userName: updates.userName.trim() }
        : {}),
      ...(typeof updates.userDisplayName === 'string' && updates.userDisplayName.trim()
        ? { userDisplayName: updates.userDisplayName.trim() }
        : {}),
      updatedAt: nowIso
    };

    const meta = this.engine.putSecret(
      rawToken,
      targetEntry.secretPath,
      updatedRecord as unknown as Record<string, unknown>,
      { merge: false, skipIfUnchanged: true, maxVersions: 5 }
    );
    userMap.set(targetEntry.secretPath, { version: meta.version, record: updatedRecord });
    return sanitizePasskeySummary(updatedRecord);
  }

  public signalPasskeys(
    rawToken: string,
    rawUserId: string,
    payload: {
      signalType: 'unknownCredential' | 'allAcceptedCredentials' | 'currentUserDetails';
      origin: string;
      rpId?: string;
      credentialId?: string;
      userId?: string;
      allAcceptedCredentialIds?: string[];
      name?: string;
      displayName?: string;
    }
  ): { updated: number; deleted: number } {
    this.ensureUnsealedOrClearCaches();
    const userId = sanitizeVaultUserId(rawUserId);
    const { effectiveRpId } = validateRpIdForOrigin(payload.rpId, payload.origin);
    const isValidB64Url = (val: unknown): val is string =>
      typeof val === 'string' &&
      val.length > 0 &&
      val.length % 4 !== 1 &&
      /^[A-Za-z0-9_-]+$/.test(val);

    const userMap = this.getHydratedPasskeys(rawToken, userId);
    let updated = 0;
    let deleted = 0;

    if (payload.signalType === 'unknownCredential') {
      if (!isValidB64Url(payload.credentialId)) {
        throw new Error('TypeError: Invalid base64url credentialId for signalUnknownCredential');
      }
      for (const [secretPath, { record }] of Array.from(userMap.entries())) {
        if (record.rpId.toLowerCase() === effectiveRpId && record.credentialId === payload.credentialId) {
          this.engine.deleteSecret(rawToken, secretPath);
          userMap.delete(secretPath);
          deleted++;
        }
      }
      return { updated, deleted };
    }

    if (payload.signalType === 'allAcceptedCredentials') {
      if (
        !isValidB64Url(payload.userId) ||
        !Array.isArray(payload.allAcceptedCredentialIds) ||
        !payload.allAcceptedCredentialIds.every(isValidB64Url)
      ) {
        throw new Error(
          'TypeError: Invalid base64url userId or allAcceptedCredentialIds for signalAllAcceptedCredentials'
        );
      }
      const acceptedSet = new Set(payload.allAcceptedCredentialIds);
      for (const [secretPath, { record }] of Array.from(userMap.entries())) {
        if (
          record.rpId.toLowerCase() === effectiveRpId &&
          record.userHandleBase64Url === payload.userId &&
          !acceptedSet.has(record.credentialId)
        ) {
          this.engine.deleteSecret(rawToken, secretPath);
          userMap.delete(secretPath);
          deleted++;
        }
      }
      return { updated, deleted };
    }

    if (payload.signalType === 'currentUserDetails') {
      if (!isValidB64Url(payload.userId)) {
        throw new Error('TypeError: Invalid base64url userId for signalCurrentUserDetails');
      }
      const nowIso = new Date().toISOString();
      for (const [secretPath, { record }] of Array.from(userMap.entries())) {
        if (record.rpId.toLowerCase() === effectiveRpId && record.userHandleBase64Url === payload.userId) {
          const nextRec: StoredPasskeyRecord = {
            ...record,
            ...(typeof payload.name === 'string' && payload.name.trim()
              ? { userName: payload.name.trim() }
              : {}),
            ...(typeof payload.displayName === 'string' && payload.displayName.trim()
              ? { userDisplayName: payload.displayName.trim() }
              : {}),
            updatedAt: nowIso
          };
          const meta = this.engine.putSecret(
            rawToken,
            secretPath,
            nextRec as unknown as Record<string, unknown>,
            { merge: false, skipIfUnchanged: true, maxVersions: 5 }
          );
          userMap.set(secretPath, { version: meta.version, record: nextRec });
          updated++;
        }
      }
      return { updated, deleted };
    }

    throw new Error(`Unsupported WebAuthn signalType: ${String(payload.signalType)}`);
  }
}
