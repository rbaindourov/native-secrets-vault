import fs from 'fs';
import os from 'os';
import path from 'path';
import http from 'http';
import { createVaultServer } from '../src';

function httpRequest(
  port: number,
  method: string,
  urlPath: string,
  options: {
    body?: string | Record<string, unknown>;
    contentType?: string;
    token?: string;
    origin?: string;
  } = {}
): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: any }> {
  return new Promise((resolve, reject) => {
    const rawPayload =
      options.body === undefined
        ? undefined
        : typeof options.body === 'string'
        ? options.body
        : JSON.stringify(options.body);

    const headers: Record<string, string> = { Accept: 'application/json' };
    if (options.token) headers['Authorization'] = `Bearer ${options.token}`;
    if (options.origin) headers['Origin'] = options.origin;
    if (rawPayload !== undefined) {
      headers['Content-Type'] = options.contentType || 'application/json';
      headers['Content-Length'] = String(Buffer.byteLength(rawPayload));
    }

    const req = http.request(
      { host: '127.0.0.1', port, method, path: urlPath, headers },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let parsed: any = text;
          try {
            parsed = text ? JSON.parse(text) : {};
          } catch (_) {}
          resolve({ status: res.statusCode || 0, headers: res.headers, body: parsed });
        });
      }
    );
    req.on('error', reject);
    if (rawPayload !== undefined) req.write(rawPayload);
    req.end();
  });
}

describe('Smart Ingest, SHA-256 Deduplication & maxVersions Pruning', () => {
  let tmpDir: string;
  let server: http.Server;
  let port: number;
  let rootToken: string;

  beforeAll(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nsv-smart-ingest-'));
    const created = createVaultServer({ dataDir: tmpDir });
    server = created.server;
    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => resolve());
    });
    port = (server.address() as any).port;

    const initRes = await httpRequest(port, 'POST', '/v1/sys/init', {
      body: { secret_shares: 3, secret_threshold: 2 }
    });
    expect(initRes.status).toBe(200);
    rootToken = initRes.body.root_token;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('ingests 500 RFC-4180 CSV credentials in one commit, skips 100% on re-import with 0 disk writes, and mutates only changed rows', async () => {
    const lines = ['name,url,username,password,note'];
    for (let i = 1; i <= 500; i++) {
      lines.push(
        `"Site ${i}, Inc.",https://app${i}.example.com/login,user${i}@example.com,"p@ss,${i}""quote","Note ${i}"`
      );
    }
    // Add an android:// row to ensure unsupported schemes are cleanly rejected without failing batch
    lines.push('Android App,android://hash@com.example.app,user,secret,ignored');
    const csvPayload = lines.join('\r\n');

    const firstRes = await httpRequest(
      port,
      'POST',
      '/api/v1/browser/robert/ingest',
      {
        body: csvPayload,
        contentType: 'text/csv',
        token: rootToken,
        origin: 'http://cockpit.local'
      }
    );
    expect(firstRes.status).toBe(200);
    expect(firstRes.headers['access-control-allow-origin']).toBe('http://cockpit.local');
    expect(firstRes.body.detectedFormat).toBe('csv');
    expect(firstRes.body.mutated).toBe(500);
    expect(firstRes.body.skippedUnchanged).toBe(0);
    expect(firstRes.body.rejected).toBe(1);

    const stateFile = path.join(tmpDir, 'vault-state.json');
    const statBefore = fs.statSync(stateFile);
    const statusBefore = await httpRequest(port, 'GET', '/api/v1/status');

    await new Promise((r) => setTimeout(r, 25));

    // Re-ingest exact same 500-row CSV -> 0 mutations, 0 state-file flushes, 0 new versions
    const secondRes = await httpRequest(
      port,
      'POST',
      '/api/v1/browser/robert/ingest',
      {
        body: csvPayload,
        contentType: 'text/csv',
        token: rootToken
      }
    );
    expect(secondRes.status).toBe(200);
    expect(secondRes.body.mutated).toBe(0);
    expect(secondRes.body.skippedUnchanged).toBe(500);

    const statAfter = fs.statSync(stateFile);
    const statusAfter = await httpRequest(port, 'GET', '/api/v1/status');
    expect(statAfter.mtimeMs).toBe(statBefore.mtimeMs);
    expect(statusAfter.body.secretVersionsTotal).toBe(statusBefore.body.secretVersionsTotal);

    // Negative control: mutate exactly 1 password out of 500 -> mutated: 1, skippedUnchanged: 499
    const updatedCsv = csvPayload.replace('"p@ss,42""quote"', '"rotated-pass-42"');
    const thirdRes = await httpRequest(
      port,
      'POST',
      '/api/v1/browser/robert/ingest',
      {
        body: updatedCsv,
        contentType: 'text/csv',
        token: rootToken
      }
    );
    expect(thirdRes.status).toBe(200);
    expect(thirdRes.body.mutated).toBe(1);
    expect(thirdRes.body.skippedUnchanged).toBe(499);

    // Verify O(1) origin filter lookup returns rotated password
    const lookupRes = await httpRequest(
      port,
      'GET',
      '/api/v1/browser/robert/logins?origin=https://app42.example.com',
      { token: rootToken }
    );
    expect(lookupRes.status).toBe(200);
    expect(lookupRes.body.logins[0].password).toBe('rotated-pass-42');
  });

  it('auto-classifies .env payloads into canonical KV v2 namespaces and skips unchanged re-imports', async () => {
    const dotenvText = [
      '# Cluster Secrets',
      'JWT_SECRET="jwt_prod_123"',
      'GITHUB_CLIENT_SECRET=gh_sec_456',
      'PAYPAL_CLIENT_SECRET=pp_sec_789',
      'RESEND_API_KEY=re_live_abc',
      'R7000_ADMIN_USER=admin',
      'R7000_ADMIN_PASSWORD="router_pass_xyz"'
    ].join('\n');

    const res1 = await httpRequest(port, 'POST', '/api/v1/ingest/smart', {
      body: { format: 'auto', payload: dotenvText },
      token: rootToken
    });
    expect(res1.status).toBe(200);
    expect(res1.body.detectedFormat).toBe('dotenv');
    expect(res1.body.mutated).toBe(5);
    expect(res1.body.targetPaths).toEqual([
      'billing/prod',
      'cms/prod',
      'email-crm/prod',
      'infra/r7000',
      'oauth/prod'
    ]);

    const r7000Secret = await httpRequest(
      port,
      'GET',
      '/v1/secret/data/infra/r7000',
      { token: rootToken }
    );
    expect(r7000Secret.status).toBe(200);
    expect(r7000Secret.body.data.data.R7000_ADMIN_PASSWORD).toBe('router_pass_xyz');

    const res2 = await httpRequest(port, 'POST', '/api/v1/ingest/smart', {
      body: { format: 'dotenv', payload: dotenvText },
      token: rootToken
    });
    expect(res2.status).toBe(200);
    expect(res2.body.mutated).toBe(0);
    expect(res2.body.skippedUnchanged).toBe(5);
  });

  it('enforces maxVersions pruning (5 for auth-tokens, 20 for standard KV paths)', async () => {
    for (let i = 1; i <= 12; i++) {
      const r = await httpRequest(
        port,
        'PUT',
        '/api/v1/browser/robert/auth-tokens/github.com',
        {
          body: {
            cookies: [{ name: 'user_session', value: `tok_${i}`, domain: '.github.com' }],
            headers: {},
            localStorageEntries: {}
          },
          token: rootToken
        }
      );
      expect(r.status).toBe(200);
    }

    const authMeta = await httpRequest(
      port,
      'GET',
      '/v1/secret/metadata/winome/robert/auth-tokens/github.com',
      { token: rootToken }
    );
    expect(authMeta.status).toBe(200);
    expect(authMeta.body.data.current_version).toBe(12);
    expect(authMeta.body.data.oldest_version).toBe(8);
    expect(Object.keys(authMeta.body.data.versions)).toHaveLength(5);

    for (let i = 1; i <= 25; i++) {
      const r = await httpRequest(port, 'POST', '/v1/secret/data/test/rotation', {
        body: { data: { ROTATING_KEY: `val_${i}` } },
        token: rootToken
      });
      expect(r.status).toBe(200);
    }

    const stdMeta = await httpRequest(
      port,
      'GET',
      '/v1/secret/metadata/test/rotation',
      { token: rootToken }
    );
    expect(stdMeta.status).toBe(200);
    expect(stdMeta.body.data.current_version).toBe(25);
    expect(stdMeta.body.data.oldest_version).toBe(6);
    expect(Object.keys(stdMeta.body.data.versions)).toHaveLength(20);
  });
});
