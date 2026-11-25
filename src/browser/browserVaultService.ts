/**
 * src/browser/browserVaultService.ts
 * ──────────────────────────────────────────────────────────────────────────────
 * Winome Browser Credential, RFC 6238 TOTP, Sensitive Autofill & Service Key
 * Vault Layer built on top of `NativeSecretsVaultEngine` (`winome/<userId>/*`).
 */

import crypto from 'crypto';
import { URL } from 'url';
import { NativeSecretsVaultEngine } from '../storage/vaultEngine';

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
  // Support otpauth://totp/...?secret=BASE32 URIs as well as raw Base32 strings
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
  constructor(private readonly engine: NativeSecretsVaultEngine) {}

  public upsertLogin(
    rawToken: string,
    rawUserId: string,
    input: BrowserLoginInput
  ): BrowserLoginRecord {
    const userId = sanitizeVaultUserId(rawUserId);
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
    const nowIso = new Date().toISOString();

    let createdAt = nowIso;
    try {
      const existing = this.engine.getSecret(rawToken, secretPath);
      if (typeof existing.data.createdAt === 'string') {
        createdAt = existing.data.createdAt;
      }
    } catch (_) {
      // New login entry
    }

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
      createdAt,
      updatedAt: nowIso,
      lastUsedAt: nowIso
    };

    // Validate TOTP secret upfront if provided
    if (record.totpSecret) {
      const totp = generateTotpCode(record.totpSecret);
      record.totpCode = totp.code;
      record.totpRemainingSeconds = totp.remainingSeconds;
    }

    const persistedPayload: Record<string, unknown> = { ...record };
    delete persistedPayload.totpCode;
    delete persistedPayload.totpRemainingSeconds;
    delete persistedPayload.matchType;

    this.engine.putSecret(rawToken, secretPath, persistedPayload, { merge: false });
    return record;
  }

  public listLogins(
    rawToken: string,
    rawUserId: string,
    filterOriginOrUrl?: string
  ): BrowserLoginRecord[] {
    const userId = sanitizeVaultUserId(rawUserId);
    const prefix = `winome/${userId}/logins`;
    const entries = this.engine.listPaths(rawToken, prefix);

    let targetOrigin = '';
    let targetRegDomain = '';
    if (filterOriginOrUrl && filterOriginOrUrl.trim()) {
      const norm = normalizeOriginUrl(filterOriginOrUrl);
      targetOrigin = norm.origin;
      targetRegDomain = norm.registrableDomain;
    }

    const results: BrowserLoginRecord[] = [];
    for (const item of entries) {
      try {
        const { data } = this.engine.getSecret(rawToken, item.path);
        const rec = data as unknown as BrowserLoginRecord;
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
      } catch (_) {}
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
    const userId = sanitizeVaultUserId(rawUserId);
    if (!/^[a-zA-Z0-9_-]{4,64}$/.test(credentialId)) {
      throw new Error('Invalid credentialId');
    }
    return this.engine.deleteSecret(rawToken, `winome/${userId}/logins/${credentialId}`);
  }

  public upsertSensitiveForm(
    rawToken: string,
    rawUserId: string,
    input: SensitiveFormInput
  ): SensitiveFormRecord {
    const userId = sanitizeVaultUserId(rawUserId);
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
        : `sform_${crypto.randomBytes(8).toString('hex')}`;

    const secretPath = `winome/${userId}/sensitive-forms/${id}`;
    const nowIso = new Date().toISOString();
    let createdAt = nowIso;
    try {
      const existing = this.engine.getSecret(rawToken, secretPath);
      if (typeof existing.data.createdAt === 'string') {
        createdAt = existing.data.createdAt;
      }
    } catch (_) {}

    const sanitizedFields: Record<string, string> = {};
    for (const [k, v] of Object.entries(input.fields)) {
      if (v !== undefined && v !== null) {
        sanitizedFields[String(k).trim()] = String(v);
      }
    }

    const record: SensitiveFormRecord = {
      id,
      category: input.category,
      label,
      fields: sanitizedFields,
      origins: Array.isArray(input.origins) ? input.origins.map((o) => String(o).trim()) : [],
      createdAt,
      updatedAt: nowIso
    };

    this.engine.putSecret(
      rawToken,
      secretPath,
      record as unknown as Record<string, unknown>,
      { merge: false }
    );
    return record;
  }

  public listSensitiveForms(
    rawToken: string,
    rawUserId: string,
    category?: string
  ): SensitiveFormRecord[] {
    const userId = sanitizeVaultUserId(rawUserId);
    const prefix = `winome/${userId}/sensitive-forms`;
    const entries = this.engine.listPaths(rawToken, prefix);
    const out: SensitiveFormRecord[] = [];
    for (const item of entries) {
      try {
        const { data } = this.engine.getSecret(rawToken, item.path);
        const rec = data as unknown as SensitiveFormRecord;
        if (category && rec.category !== category) continue;
        out.push(rec);
      } catch (_) {}
    }
    return out.sort((a, b) => (b.updatedAt || '').localeCompare(a.updatedAt || ''));
  }

  public deleteSensitiveForm(rawToken: string, rawUserId: string, entryId: string) {
    const userId = sanitizeVaultUserId(rawUserId);
    if (!/^[a-zA-Z0-9_-]{4,64}$/.test(entryId)) {
      throw new Error('Invalid entryId');
    }
    return this.engine.deleteSecret(rawToken, `winome/${userId}/sensitive-forms/${entryId}`);
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
      { merge: false }
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
}
