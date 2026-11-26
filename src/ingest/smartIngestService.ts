/**
 * src/ingest/smartIngestService.ts
 * ──────────────────────────────────────────────────────────────────────────────
 * Unified Smart Ingest Engine for Native Secrets Vault.
 *
 * Accepts mixed secret & credential formats in a single atomic batch call:
 *   1. `csv`: RFC-4180 password exports (Chrome, Brave, Google Passwords,
 *      Bitwarden, 1Password) -> `winome/<userId>/logins/*`
 *   2. `browser-logins-json`: Winome `BrowserLoginInput[]` -> `winome/<userId>/logins/*`
 *   3. `dotenv`: Raw `.env` text -> auto-classified into canonical KV v2 paths
 *      (`cms/prod`, `oauth/prod`, `billing/prod`, `email-crm/prod`,
 *      `google-apis/prod`, `users-backend/prod`, `job-runner/prod`, `infra/r7000`)
 *   4. `kv-bundle-json`: Nested `{ "<secretPath>": { KEY: VALUE } }` or flat
 *      `{ KEY: VALUE }` JSON objects
 *
 * Enforces SHA-256 content-hash deduplication (`skipIfUnchanged: true`) so
 * re-ingesting unchanged files produces 0 AES-GCM re-encryptions, 0 version
 * increments, and 0 `vault-state.json` disk writes.
 */

import { NativeSecretsVaultEngine, normalizeSecretPath } from '../storage/vaultEngine';
import {
  BrowserLoginInput,
  BrowserVaultService,
  sanitizeVaultUserId
} from '../browser/browserVaultService';

export type SmartIngestFormat =
  | 'auto'
  | 'csv'
  | 'browser-logins-json'
  | 'dotenv'
  | 'kv-bundle-json';

export interface SmartIngestRequest {
  format?: SmartIngestFormat;
  userId?: string;
  targetPath?: string;
  merge?: boolean;
  dryRun?: boolean;
  payload: unknown;
}

export interface SmartIngestReport {
  ok: true;
  detectedFormat: Exclude<SmartIngestFormat, 'auto'>;
  dryRun: boolean;
  totalInputItems: number;
  mutated: number;
  skippedUnchanged: number;
  rejected: number;
  targetPaths: string[];
  errors: Array<{ index: number; reason: string }>;
}

const EXACT_ENV_KEY_TO_PATH: Record<string, string> = {
  JWT_SECRET: 'cms/prod',
  SESSION_SECRET: 'cms/prod',
  ADMIN_USER: 'cms/prod',
  ADMIN_PASSWORD: 'cms/prod',
  INTERNAL_API_TOKEN: 'cms/prod',
  GRAFANA_API_KEY: 'cms/prod',
  SPARK_MCP_API_KEY: 'cms/prod',
  MONGODB_URI: 'cms/prod',
  REDIS_URL: 'cms/prod',

  USERS_BACKEND_SECRET_KEY: 'users-backend/prod',
  SECRET_KEY: 'users-backend/prod',
  ADMIN_API_KEY: 'users-backend/prod',
  GRAFANA_CLIENT_ID: 'users-backend/prod',
  GRAFANA_CLIENT_SECRET: 'users-backend/prod',

  FORUM_ADMIN_SECRET: 'forum-backend/prod',

  CMS_CLIENT_ID: 'job-runner/prod',
  CMS_CLIENT_SECRET: 'job-runner/prod'
};

export function classifyEnvKeyNamespace(rawKey: string, overrideTargetPath?: string): string {
  if (overrideTargetPath && overrideTargetPath.trim()) {
    return normalizeSecretPath(overrideTargetPath);
  }
  const key = String(rawKey || '').trim().toUpperCase();
  if (EXACT_ENV_KEY_TO_PATH[key]) {
    return EXACT_ENV_KEY_TO_PATH[key];
  }
  if (/^(R7000_|ROUTER_)/.test(key)) return 'infra/r7000';
  if (/^(GITHUB_|LINKEDIN_|OAUTH_)/.test(key)) return 'oauth/prod';
  if (/^(PAYPAL_|STRIPE_|ASC_|X402_)/.test(key)) return 'billing/prod';
  if (/^(RESEND_|CRM_|SMSGATE_|MAKE_|BREVO_|SENDGRID_)/.test(key)) return 'email-crm/prod';
  if (/^(GOOGLE_|GMAIL_|GSC_|INDEXNOW_|GEMINI_)/.test(key)) return 'google-apis/prod';
  if (/^(A2A_|NOSTR_|COLONY_|HASHN_)/.test(key)) return 'a2a-agents/prod';
  if (/^(JOB_RUNNER_)/.test(key)) return 'job-runner/prod';
  return 'cms/prod';
}

export function parseRfc4180Csv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let inQuotes = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        field += ch;
      }
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ',') {
      row.push(field);
      field = '';
    } else if (ch === '\r') {
      if (text[i + 1] === '\n') i++;
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
    } else if (ch === '\n') {
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
    } else {
      field += ch;
    }
  }
  if (field.length > 0 || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

export function parseDotenvKeyValues(rawText: string): Record<string, string> {
  const out: Record<string, string> = {};
  const lines = rawText.split(/\r?\n/);
  for (const rawLine of lines) {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const withoutExport = trimmed.replace(/^export\s+/, '');
    const eqIdx = withoutExport.indexOf('=');
    if (eqIdx <= 0) continue;

    const key = withoutExport.slice(0, eqIdx).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;

    let rawVal = withoutExport.slice(eqIdx + 1).trim();
    if (!rawVal) continue;

    if (
      (rawVal.startsWith('"') && rawVal.endsWith('"') && rawVal.length >= 2) ||
      (rawVal.startsWith("'") && rawVal.endsWith("'") && rawVal.length >= 2)
    ) {
      const q = rawVal[0];
      const inner = rawVal.slice(1, -1);
      rawVal = q === '"' ? inner.replace(/\\"/g, '"').replace(/\\n/g, '\n') : inner;
    } else {
      const commentMatch = rawVal.match(/^([^#]*?)\s+#.*$/);
      if (commentMatch) {
        rawVal = commentMatch[1].trim();
      }
    }

    if (rawVal !== '') {
      out[key] = rawVal;
    }
  }
  return out;
}

function detectFormat(req: SmartIngestRequest): Exclude<SmartIngestFormat, 'auto'> {
  if (req.format && req.format !== 'auto') {
    return req.format;
  }

  const p = req.payload;
  if (Array.isArray(p)) {
    return 'browser-logins-json';
  }
  if (p !== null && typeof p === 'object') {
    const obj = p as Record<string, unknown>;
    if (Array.isArray(obj.logins) || Array.isArray(obj.items)) {
      return 'browser-logins-json';
    }
    if (typeof obj.csv === 'string') {
      return 'csv';
    }
    if (typeof obj.dotenv === 'string' || typeof obj.env === 'string') {
      return 'dotenv';
    }
    return 'kv-bundle-json';
  }

  const str = String(p ?? '').trim();
  if (!str) {
    throw new Error('Smart ingest payload cannot be empty');
  }
  if (str.startsWith('[') || str.startsWith('{')) {
    const parsed = JSON.parse(str);
    if (Array.isArray(parsed)) return 'browser-logins-json';
    if (parsed && (Array.isArray(parsed.logins) || Array.isArray(parsed.items))) {
      return 'browser-logins-json';
    }
    return 'kv-bundle-json';
  }

  const firstLine = str.split(/\r?\n/, 1)[0].toLowerCase();
  if (
    firstLine.includes(',') &&
    (firstLine.includes('password') ||
      firstLine.includes('username') ||
      firstLine.includes('login_uri') ||
      firstLine.includes('url'))
  ) {
    return 'csv';
  }
  return 'dotenv';
}

export class SmartIngestService {
  constructor(
    private readonly engine: NativeSecretsVaultEngine,
    private readonly browserVault: BrowserVaultService
  ) {}

  public ingest(rawToken: string, request: SmartIngestRequest): SmartIngestReport {
    const format = detectFormat(request);
    const dryRun = Boolean(request.dryRun);

    if (format === 'csv') {
      const rawCsv =
        typeof request.payload === 'string'
          ? request.payload
          : String((request.payload as Record<string, unknown>)?.csv || '');
      return this.ingestCsvLogins(rawToken, request.userId || 'default', rawCsv, dryRun);
    }

    if (format === 'browser-logins-json') {
      const arr = this.extractLoginsArray(request.payload);
      return this.ingestBrowserLoginsArray(rawToken, request.userId || 'default', arr, dryRun);
    }

    if (format === 'dotenv') {
      const rawEnv =
        typeof request.payload === 'string'
          ? request.payload
          : String(
              (request.payload as Record<string, unknown>)?.dotenv ||
                (request.payload as Record<string, unknown>)?.env ||
                ''
            );
      return this.ingestDotenv(rawToken, rawEnv, request.targetPath, request.merge !== false, dryRun);
    }

    return this.ingestKvBundle(
      rawToken,
      request.payload,
      request.targetPath,
      request.merge !== false,
      dryRun
    );
  }

  private extractLoginsArray(payload: unknown): BrowserLoginInput[] {
    if (Array.isArray(payload)) return payload as BrowserLoginInput[];
    if (typeof payload === 'string') {
      const parsed = JSON.parse(payload);
      if (Array.isArray(parsed)) return parsed as BrowserLoginInput[];
      if (Array.isArray(parsed?.logins)) return parsed.logins as BrowserLoginInput[];
      if (Array.isArray(parsed?.items)) return parsed.items as BrowserLoginInput[];
    }
    if (payload && typeof payload === 'object') {
      const obj = payload as Record<string, unknown>;
      if (Array.isArray(obj.logins)) return obj.logins as BrowserLoginInput[];
      if (Array.isArray(obj.items)) return obj.items as BrowserLoginInput[];
    }
    return [];
  }

  private ingestCsvLogins(
    rawToken: string,
    rawUserId: string,
    csvText: string,
    dryRun: boolean
  ): SmartIngestReport {
    const userId = sanitizeVaultUserId(rawUserId);
    const rows = parseRfc4180Csv(csvText.replace(/^\uFEFF/, ''));
    if (rows.length < 2) {
      return {
        ok: true,
        detectedFormat: 'csv',
        dryRun,
        totalInputItems: 0,
        mutated: 0,
        skippedUnchanged: 0,
        rejected: 0,
        targetPaths: [],
        errors: []
      };
    }

    const headers = rows[0].map((h) => h.trim().toLowerCase());
    const findCol = (...candidates: string[]) =>
      headers.findIndex((h) => candidates.includes(h));

    const urlIdx = findCol('url', 'login_uri', 'website', 'origin');
    const nameIdx = findCol('name', 'title');
    const userIdx = findCol('username', 'login_username', 'user', 'email');
    const passIdx = findCol('password', 'login_password', 'pass');
    const totpIdx = findCol('totp', 'login_totp', 'otpauth', 'totpsecret');
    const noteIdx = findCol('note', 'notes', 'comment');

    if (passIdx === -1 || (urlIdx === -1 && nameIdx === -1)) {
      throw new Error(
        'CSV header must contain password and url/origin columns (Chrome, Brave, Bitwarden, or 1Password format)'
      );
    }

    const validInputs: BrowserLoginInput[] = [];
    const errors: Array<{ index: number; reason: string }> = [];

    for (let i = 1; i < rows.length; i++) {
      const r = rows[i];
      if (!r || r.every((c) => !String(c || '').trim())) continue;

      const rawOrigin = (urlIdx >= 0 ? r[urlIdx] : '') || (nameIdx >= 0 ? r[nameIdx] : '');
      const password = passIdx >= 0 ? String(r[passIdx] ?? '') : '';
      const username = userIdx >= 0 ? String(r[userIdx] ?? '').trim() : '';
      const totpSecret = totpIdx >= 0 ? String(r[totpIdx] ?? '').trim() : '';
      const notes = noteIdx >= 0 ? String(r[noteIdx] ?? '').trim() : '';

      if (!rawOrigin || !password) {
        errors.push({ index: i, reason: 'Missing origin/url or password' });
        continue;
      }

      // Filter non-HTTP internal browser schemes (e.g. android:// or chrome://) unless valid hostname
      if (/^(android|chrome|edge|brave|about):\/\//i.test(rawOrigin.trim())) {
        errors.push({ index: i, reason: 'Unsupported non-web URI scheme' });
        continue;
      }

      validInputs.push({
        origin: rawOrigin.trim(),
        username,
        password,
        ...(totpSecret ? { totpSecret } : {}),
        ...(notes ? { notes } : {})
      });
    }

    return this.ingestBrowserLoginsArray(rawToken, userId, validInputs, dryRun, 'csv', errors);
  }

  private ingestBrowserLoginsArray(
    rawToken: string,
    rawUserId: string,
    inputs: BrowserLoginInput[],
    dryRun: boolean,
    detectedFormat: 'csv' | 'browser-logins-json' = 'browser-logins-json',
    preErrors: Array<{ index: number; reason: string }> = []
  ): SmartIngestReport {
    const userId = sanitizeVaultUserId(rawUserId);
    const sanitized: BrowserLoginInput[] = [];
    const errors = [...preErrors];

    inputs.forEach((item, idx) => {
      if (!item || !String(item.origin || '').trim() || !String(item.password ?? '')) {
        errors.push({ index: idx, reason: 'Missing origin or password' });
        return;
      }
      sanitized.push(item);
    });

    const totalInputItems = sanitized.length + errors.length;
    const namespacePrefix = `winome/${userId}/logins`;

    if (dryRun || sanitized.length === 0) {
      this.engine.authorize(rawToken, `${namespacePrefix}/*`, 'write');
      return {
        ok: true,
        detectedFormat,
        dryRun,
        totalInputItems,
        mutated: dryRun ? sanitized.length : 0,
        skippedUnchanged: 0,
        rejected: errors.length,
        targetPaths: sanitized.length > 0 ? [namespacePrefix] : [],
        errors
      };
    }

    const batchRes = this.browserVault.upsertLoginsBatch(rawToken, userId, sanitized);
    return {
      ok: true,
      detectedFormat,
      dryRun: false,
      totalInputItems,
      mutated: batchRes.mutated,
      skippedUnchanged: batchRes.skippedUnchanged,
      rejected: errors.length,
      targetPaths: [namespacePrefix],
      errors
    };
  }

  private ingestDotenv(
    rawToken: string,
    dotenvText: string,
    overrideTargetPath: string | undefined,
    merge: boolean,
    dryRun: boolean
  ): SmartIngestReport {
    const pairs = parseDotenvKeyValues(dotenvText);
    const groupedByPath = new Map<string, Record<string, unknown>>();
    let totalKeys = 0;

    for (const [k, v] of Object.entries(pairs)) {
      const targetPath = classifyEnvKeyNamespace(k, overrideTargetPath);
      if (!groupedByPath.has(targetPath)) {
        groupedByPath.set(targetPath, {});
      }
      groupedByPath.get(targetPath)![k] = v;
      totalKeys++;
    }

    const targetPaths = Array.from(groupedByPath.keys()).sort();
    if (dryRun || targetPaths.length === 0) {
      for (const p of targetPaths) {
        this.engine.authorize(rawToken, p, 'write');
      }
      return {
        ok: true,
        detectedFormat: 'dotenv',
        dryRun,
        totalInputItems: totalKeys,
        mutated: dryRun ? targetPaths.length : 0,
        skippedUnchanged: 0,
        rejected: 0,
        targetPaths,
        errors: []
      };
    }

    const writes = targetPaths.map((p) => ({
      path: p,
      data: groupedByPath.get(p)!,
      merge,
      skipIfUnchanged: true
    }));

    const res = this.engine.putSecretsBatch(rawToken, writes, 'ingest.smart_dotenv');
    const mutated = res.filter((r) => !r.unchanged).length;
    return {
      ok: true,
      detectedFormat: 'dotenv',
      dryRun: false,
      totalInputItems: totalKeys,
      mutated,
      skippedUnchanged: res.length - mutated,
      rejected: 0,
      targetPaths,
      errors: []
    };
  }

  private ingestKvBundle(
    rawToken: string,
    rawPayload: unknown,
    overrideTargetPath: string | undefined,
    merge: boolean,
    dryRun: boolean
  ): SmartIngestReport {
    const parsed =
      typeof rawPayload === 'string'
        ? (JSON.parse(rawPayload) as Record<string, unknown>)
        : ((rawPayload || {}) as Record<string, unknown>);

    const unwrapped =
      parsed.secrets && typeof parsed.secrets === 'object' && !Array.isArray(parsed.secrets)
        ? (parsed.secrets as Record<string, unknown>)
        : parsed;

    // Detect whether unwrapped is nested `{ "cms/prod": { KEY: VAL } }` or flat `{ KEY: VAL }`
    const values = Object.values(unwrapped);
    const isNestedPaths =
      values.length > 0 &&
      values.every((v) => v !== null && typeof v === 'object' && !Array.isArray(v));

    const groupedByPath = new Map<string, Record<string, unknown>>();
    let totalItems = 0;

    if (isNestedPaths && !overrideTargetPath) {
      for (const [rawPath, mapVal] of Object.entries(unwrapped)) {
        const cleanPath = normalizeSecretPath(rawPath);
        if (!cleanPath) continue;
        const kvObj = mapVal as Record<string, unknown>;
        const nonEmpty: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(kvObj)) {
          if (v !== null && v !== undefined && String(v).trim() !== '') {
            nonEmpty[k] = v;
            totalItems++;
          }
        }
        if (Object.keys(nonEmpty).length > 0) {
          groupedByPath.set(cleanPath, nonEmpty);
        }
      }
    } else {
      for (const [k, v] of Object.entries(unwrapped)) {
        if (v === null || v === undefined || String(v).trim() === '') continue;
        const targetPath = classifyEnvKeyNamespace(k, overrideTargetPath);
        if (!groupedByPath.has(targetPath)) {
          groupedByPath.set(targetPath, {});
        }
        groupedByPath.get(targetPath)![k] = v;
        totalItems++;
      }
    }

    const targetPaths = Array.from(groupedByPath.keys()).sort();
    if (dryRun || targetPaths.length === 0) {
      for (const p of targetPaths) {
        this.engine.authorize(rawToken, p, 'write');
      }
      return {
        ok: true,
        detectedFormat: 'kv-bundle-json',
        dryRun,
        totalInputItems: totalItems,
        mutated: dryRun ? targetPaths.length : 0,
        skippedUnchanged: 0,
        rejected: 0,
        targetPaths,
        errors: []
      };
    }

    const writes = targetPaths.map((p) => ({
      path: p,
      data: groupedByPath.get(p)!,
      merge,
      skipIfUnchanged: true
    }));

    const res = this.engine.putSecretsBatch(rawToken, writes, 'ingest.smart_kv_bundle');
    const mutated = res.filter((r) => !r.unchanged).length;
    return {
      ok: true,
      detectedFormat: 'kv-bundle-json',
      dryRun: false,
      totalInputItems: totalItems,
      mutated,
      skippedUnchanged: res.length - mutated,
      rejected: 0,
      targetPaths,
      errors: []
    };
  }
}
