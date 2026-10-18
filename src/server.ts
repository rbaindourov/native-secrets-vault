/**
 * src/server.ts
 * ──────────────────────────────────────────────────────────────────────────────
 * Native Secrets Vault HTTP Server (Loopback-first 127.0.0.1:8200).
 *
 * Implements:
 *   1. HashiCorp Vault KV v2 wire-compatible API (`/v1/sys/*`, `/v1/secret/data/*`,
 *      `/v1/secret/metadata/*`)
 *   2. Ergonomic Native REST API (`/api/v1/status`, `/api/v1/paths`,
 *      `/api/v1/export/dotenv`, `/api/v1/export/json`, `/api/v1/audit`,
 *      `/api/v1/tokens`, `/api/v1/snapshot/export`)
 *   3. Prometheus Metrics Exporter (`GET /metrics`)
 *   4. Interactive Glassmorphic Web Dashboard (`GET /ui` and `GET /`)
 */

import http, { IncomingMessage, ServerResponse } from 'http';
import fs from 'fs';
import path from 'path';
import { URL } from 'url';
import { NativeSecretsVaultEngine } from './storage/vaultEngine';
import { formatEnvValue } from './sync/dotenvSync';
import { renderVaultDashboardHtml } from './ui/dashboardHtml';

export interface VaultServerOptions {
  dataDir?: string;
  host?: string;
  port?: number;
  autoUnsealFile?: string;
}

function extractAuthToken(req: IncomingMessage): string {
  const vaultHeader = req.headers['x-vault-token'];
  if (typeof vaultHeader === 'string' && vaultHeader.trim()) {
    return vaultHeader.trim();
  }
  const authHeader = req.headers['authorization'];
  if (typeof authHeader === 'string' && authHeader.trim()) {
    return authHeader.replace(/^Bearer\s+/i, '').trim();
  }
  return '';
}

function readJsonBody(req: IncomingMessage): Promise<Record<string, any>> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let totalBytes = 0;
    req.on('data', (chunk: Buffer) => {
      totalBytes += chunk.length;
      if (totalBytes > 5 * 1024 * 1024) {
        reject(new Error('Request body exceeds 5MB limit'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8').trim();
      if (!raw) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(raw));
      } catch (err) {
        reject(new Error('Invalid JSON payload'));
      }
    });
    req.on('error', reject);
  });
}

function sendJson(res: ServerResponse, statusCode: number, payload: unknown): void {
  const body = JSON.stringify(payload, null, 2);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  });
  res.end(body);
}

export function createVaultServer(options: VaultServerOptions = {}) {
  const dataDir =
    options.dataDir ||
    process.env.NSV_DATA_DIR ||
    path.join(process.cwd(), '.vault-data');
  const engine = new NativeSecretsVaultEngine(dataDir);
  const startTime = Date.now();
  let httpRequestsTotal = 0;

  // Attempt optional unattended auto-unseal if keyfile exists on local host
  const autoUnsealFile =
    options.autoUnsealFile ||
    process.env.NSV_AUTO_UNSEAL_FILE ||
    path.join(dataDir, 'unseal-init.json');

  if (engine.isInitialized() && engine.isSealed() && fs.existsSync(autoUnsealFile)) {
    try {
      const rawInit = JSON.parse(fs.readFileSync(autoUnsealFile, 'utf8'));
      const keys: string[] = rawInit.keys || rawInit.unseal_keys_hex || rawInit.unseal_keys_b64 || [];
      for (const k of keys) {
        const status = engine.unseal(k);
        if (!status.sealed) break;
      }
    } catch (_) {
      // Leave sealed if auto-unseal file cannot be parsed
    }
  }

  const server = http.createServer(async (req: IncomingMessage, res: ServerResponse) => {
    httpRequestsTotal++;
    const method = (req.method || 'GET').toUpperCase();
    const parsedUrl = new URL(req.url || '/', `http://${req.headers.host || '127.0.0.1:8200'}`);
    const pathname = parsedUrl.pathname;

    try {
      // 1. Web UI Dashboard
      if (method === 'GET' && (pathname === '/' || pathname === '/ui')) {
        const html = renderVaultDashboardHtml();
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(html);
        return;
      }

      // 2. Prometheus Metrics Exporter
      if (method === 'GET' && pathname === '/metrics') {
        const st = engine.getStats();
        const uptimeSeconds = Math.floor((Date.now() - startTime) / 1000);
        const lines = [
          '# HELP vault_initialized Whether the Native Secrets Vault is initialized (1 = yes, 0 = no)',
          '# TYPE vault_initialized gauge',
          `vault_initialized ${st.initialized ? 1 : 0}`,
          '# HELP vault_sealed Whether the Native Secrets Vault is sealed (1 = sealed, 0 = unsealed)',
          '# TYPE vault_sealed gauge',
          `vault_sealed ${st.sealed ? 1 : 0}`,
          '# HELP vault_secret_paths_total Total number of KV v2 secret paths stored',
          '# TYPE vault_secret_paths_total gauge',
          `vault_secret_paths_total ${st.secretPathsTotal}`,
          '# HELP vault_secrets_total Total number of active encrypted secret keys across all paths',
          '# TYPE vault_secrets_total gauge',
          `vault_secrets_total ${st.secretKeysTotal}`,
          '# HELP vault_secret_versions_total Total number of encrypted secret versions stored',
          '# TYPE vault_secret_versions_total gauge',
          `vault_secret_versions_total ${st.secretVersionsTotal}`,
          '# HELP vault_audit_entries_total Total number of SHA-256 hash-chained audit log entries',
          '# TYPE vault_audit_entries_total counter',
          `vault_audit_entries_total ${st.auditEntriesTotal}`,
          '# HELP vault_audit_chain_valid Cryptographic integrity of the SHA-256 audit log chain (1 = valid, 0 = tampered)',
          '# TYPE vault_audit_chain_valid gauge',
          `vault_audit_chain_valid ${st.auditChainValid ? 1 : 0}`,
          '# HELP vault_http_requests_total Total HTTP requests handled by Native Secrets Vault',
          '# TYPE vault_http_requests_total counter',
          `vault_http_requests_total ${httpRequestsTotal}`,
          '# HELP vault_uptime_seconds Uptime of the Native Secrets Vault daemon in seconds',
          '# TYPE vault_uptime_seconds gauge',
          `vault_uptime_seconds ${uptimeSeconds}`
        ];
        res.writeHead(200, { 'Content-Type': 'text/plain; version=0.0.4; charset=utf-8' });
        res.end(lines.join('\n') + '\n');
        return;
      }

      // 3. HashiCorp Vault KV v2 Compatible System Endpoints
      if (method === 'GET' && pathname === '/v1/sys/health') {
        const seal = engine.getSealStatus();
        const code = !seal.initialized ? 501 : seal.sealed ? 503 : 200;
        sendJson(res, code, {
          initialized: seal.initialized,
          sealed: seal.sealed,
          standby: false,
          performance_standby: false,
          replication_performance_mode: 'disabled',
          replication_dr_mode: 'disabled',
          server_time_utc: Math.floor(Date.now() / 1000),
          version: seal.version,
          cluster_name: seal.cluster_name
        });
        return;
      }

      if (method === 'GET' && pathname === '/v1/sys/seal-status') {
        sendJson(res, 200, engine.getSealStatus());
        return;
      }

      if ((method === 'POST' || method === 'PUT') && pathname === '/v1/sys/init') {
        const body = await readJsonBody(req);
        const result = engine.init({
          secretShares: body.secret_shares ?? body.secretShares ?? 3,
          secretThreshold: body.secret_threshold ?? body.secretThreshold ?? 2,
          autoUnseal: body.auto_unseal ?? true
        });
        sendJson(res, 200, result);
        return;
      }

      if ((method === 'POST' || method === 'PUT') && pathname === '/v1/sys/unseal') {
        const body = await readJsonBody(req);
        const status = engine.unseal(body.key || '', Boolean(body.reset));
        sendJson(res, 200, status);
        return;
      }

      if ((method === 'POST' || method === 'PUT') && pathname === '/v1/sys/seal') {
        const token = extractAuthToken(req);
        engine.authorize(token, 'sys/seal', 'root');
        const status = engine.seal('operator');
        sendJson(res, 200, status);
        return;
      }

      // 4. HashiCorp Vault KV v2 Secret Data Endpoints (/v1/secret/data/*)
      if (pathname.startsWith('/v1/secret/data/')) {
        const secretPath = pathname.slice('/v1/secret/data/'.length);
        const token = extractAuthToken(req);

        if (method === 'GET') {
          const verParam = parsedUrl.searchParams.get('version');
          const ver = verParam ? parseInt(verParam, 10) : undefined;
          const result = engine.getSecret(token, secretPath, ver);
          sendJson(res, 200, {
            request_id: `req_${Date.now()}`,
            data: {
              data: result.data,
              metadata: result.metadata
            }
          });
          return;
        }

        if (method === 'POST' || method === 'PUT') {
          const body = await readJsonBody(req);
          const secretPayload =
            body && typeof body.data === 'object' && body.data !== null
              ? body.data
              : body;
          const merge = body.options?.merge !== false;
          const meta = engine.putSecret(token, secretPath, secretPayload, { merge });
          sendJson(res, 200, {
            request_id: `req_${Date.now()}`,
            data: meta
          });
          return;
        }
      }

      // 5. HashiCorp Vault KV v2 Secret Metadata Endpoints (/v1/secret/metadata/*)
      if (pathname.startsWith('/v1/secret/metadata/')) {
        const secretPath = pathname.slice('/v1/secret/metadata/'.length);
        const token = extractAuthToken(req);
        const listParam = parsedUrl.searchParams.get('list');

        if (method === 'LIST' || (method === 'GET' && listParam === 'true')) {
          const items = engine.listPaths(token, secretPath);
          sendJson(res, 200, {
            data: {
              keys: items.map((i) => i.path)
            }
          });
          return;
        }

        if (method === 'GET') {
          const meta = engine.getMetadata(token, secretPath);
          sendJson(res, 200, { data: meta });
          return;
        }
      }

      // 6. Native Ergonomic API Endpoints (/api/v1/*)
      if (method === 'GET' && pathname === '/api/v1/status') {
        sendJson(res, 200, engine.getStats());
        return;
      }

      if (method === 'GET' && pathname === '/api/v1/paths') {
        const token = extractAuthToken(req);
        const prefix = parsedUrl.searchParams.get('prefix') || '';
        const paths = engine.listPaths(token, prefix);
        sendJson(res, 200, { total: paths.length, paths });
        return;
      }

      if (method === 'GET' && pathname === '/api/v1/export/json') {
        const token = extractAuthToken(req);
        const pathsParam = parsedUrl.searchParams.get('paths');
        const paths = pathsParam
          ? pathsParam.split(',').map((s) => s.trim()).filter(Boolean)
          : undefined;
        const secrets = engine.exportFlatSecrets(token, paths);
        sendJson(res, 200, {
          exportedAt: new Date().toISOString(),
          keyCount: Object.keys(secrets).length,
          secrets
        });
        return;
      }

      if (method === 'GET' && pathname === '/api/v1/export/dotenv') {
        const token = extractAuthToken(req);
        const pathsParam = parsedUrl.searchParams.get('paths');
        const paths = pathsParam
          ? pathsParam.split(',').map((s) => s.trim()).filter(Boolean)
          : undefined;
        const secrets = engine.exportFlatSecrets(token, paths);
        const lines = Object.keys(secrets)
          .sort()
          .map((k) => `${k}=${formatEnvValue(secrets[k])}`);
        res.writeHead(200, {
          'Content-Type': 'text/plain; charset=utf-8',
          'Cache-Control': 'no-store'
        });
        res.end(lines.join('\n') + '\n');
        return;
      }

      if (method === 'GET' && pathname === '/api/v1/audit') {
        const token = extractAuthToken(req);
        engine.authorize(token, 'sys/audit', 'list');
        const limit = parseInt(parsedUrl.searchParams.get('limit') || '50', 10);
        const verification = engine.verifyAuditChain();
        const entries = engine.getRecentAuditEntries(limit);
        sendJson(res, 200, { verification, entries });
        return;
      }

      if (method === 'GET' && pathname === '/api/v1/audit/verify') {
        sendJson(res, 200, engine.verifyAuditChain());
        return;
      }

      if (method === 'POST' && pathname === '/api/v1/tokens') {
        const token = extractAuthToken(req);
        const body = await readJsonBody(req);
        const created = engine.createScopedToken(token || '', {
          name: body.name || 'Scoped Token',
          allowedPaths: Array.isArray(body.allowedPaths) ? body.allowedPaths : ['*'],
          capabilities: Array.isArray(body.capabilities) ? body.capabilities : ['read', 'list'],
          ttlSeconds: body.ttlSeconds
        });
        sendJson(res, 201, created);
        return;
      }

      if (method === 'POST' && pathname === '/api/v1/snapshot/export') {
        const token = extractAuthToken(req);
        const body = await readJsonBody(req);
        if (!body.passphrase || String(body.passphrase).length < 8) {
          sendJson(res, 400, { error: 'Passphrase of at least 8 characters is required' });
          return;
        }
        const bundle = engine.exportEncryptedSnapshot(token || '', String(body.passphrase));
        sendJson(res, 200, JSON.parse(bundle));
        return;
      }

      sendJson(res, 404, { errors: [`Route not found: ${method} ${pathname}`] });
    } catch (err: any) {
      const msg = err?.message || 'Internal Vault Error';
      const status = msg.startsWith('Permission denied')
        ? 403
        : msg.includes('not found')
        ? 404
        : msg.includes('sealed') || msg.includes('not initialized')
        ? 503
        : 400;
      sendJson(res, status, { errors: [msg] });
    }
  });

  return { server, engine };
}

if (require.main === module) {
  const host = process.env.NSV_HOST || '127.0.0.1';
  const port = parseInt(process.env.NSV_PORT || '8200', 10);
  const dataDir =
    process.env.NSV_DATA_DIR || path.join(process.cwd(), '.vault-data');

  const { server } = createVaultServer({ dataDir, host, port });
  server.listen(port, host, () => {
    console.log(
      `[Native Secrets Vault] Listening on http://${host}:${port} (Web UI: http://${host}:${port}/ui, Metrics: http://${host}:${port}/metrics)`
    );
  });
}
