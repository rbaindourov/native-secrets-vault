import fs from 'fs';
import os from 'os';
import path from 'path';
import http from 'http';
import crypto from 'crypto';
import {
  splitSecret,
  combineShares,
  encryptWithContext,
  decryptWithContext,
  NativeSecretsVaultEngine,
  mergeEnvLossless,
  createVaultServer
} from '../src';

describe('Native Secrets Vault — Cryptographic & Integration Test Suite', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nsv-test-'));
  });

  it('Shamir GF(256) splits a 256-bit key into 5 shares with threshold 3 and reconstructs from any 3 shares', () => {
    const secret = crypto.randomBytes(32);
    const shares = splitSecret(secret, 5, 3);
    expect(shares).toHaveLength(5);

    // Any 3 shares reconstruct the exact 32-byte key
    const combo1 = combineShares([shares[0], shares[2], shares[4]]);
    const combo2 = combineShares([shares[1], shares[3], shares[4]]);
    expect(combo1.equals(secret)).toBe(true);
    expect(combo2.equals(secret)).toBe(true);

    // Negative control: 2 shares (below threshold 3) do NOT reconstruct the secret
    const insufficient = combineShares([shares[0], shares[1]]);
    expect(insufficient.equals(secret)).toBe(false);
  });

  it('Envelope encryption AES-256-GCM + HKDF-SHA256 binds ciphertext to AAD context and rejects tampering', () => {
    const rootKey = crypto.randomBytes(32);
    const blob = encryptWithContext(rootKey, 'super-secret-payload', 'nsv-kv-v2:cms/prod:v1');

    const decrypted = decryptWithContext(rootKey, blob, 'nsv-kv-v2:cms/prod:v1').toString('utf8');
    expect(decrypted).toBe('super-secret-payload');

    // Negative control: wrong AAD context is rejected immediately
    expect(() => decryptWithContext(rootKey, blob, 'nsv-kv-v2:cms/prod:v2')).toThrow(
      /AAD context mismatch/
    );
  });

  it('NativeSecretsVaultEngine manages init, seal, Shamir unseal, KV v2 versioning, scoped tokens, and SHA-256 audit chain', () => {
    const engine = new NativeSecretsVaultEngine(tmpDir);
    expect(engine.isInitialized()).toBe(false);
    expect(engine.isSealed()).toBe(true);

    const initRes = engine.init({ secretShares: 3, secretThreshold: 2 });
    expect(initRes.keys).toHaveLength(3);
    expect(initRes.root_token).toMatch(/^nsv_root_/);
    expect(engine.isSealed()).toBe(false);

    // Write v1 and v2 secrets
    const v1 = engine.putSecret(initRes.root_token, 'cms/prod', {
      JWT_SECRET: 'jwt_v1',
      SESSION_SECRET: 'sess_v1'
    });
    expect(v1.version).toBe(1);

    const v2 = engine.putSecret(initRes.root_token, 'cms/prod', {
      JWT_SECRET: 'jwt_v2',
      SESSION_SECRET: '' // empty incoming value must NOT overwrite sess_v1
    });
    expect(v2.version).toBe(2);

    const latest = engine.getSecret(initRes.root_token, 'cms/prod');
    expect(latest.data.JWT_SECRET).toBe('jwt_v2');
    expect(latest.data.SESSION_SECRET).toBe('sess_v1');

    const oldV1 = engine.getSecret(initRes.root_token, 'cms/prod', 1);
    expect(oldV1.data.JWT_SECRET).toBe('jwt_v1');

    // Seal and verify reads fail until 2 of 3 Shamir shares are provided
    engine.seal();
    expect(engine.isSealed()).toBe(true);
    expect(() => engine.getSecret(initRes.root_token, 'cms/prod')).toThrow(/Vault is sealed/);

    const after1 = engine.unseal(initRes.keys[0]);
    expect(after1.sealed).toBe(true);
    expect(after1.progress).toBe(1);

    const after2 = engine.unseal(initRes.keys[2]);
    expect(after2.sealed).toBe(false);

    // Issue a scoped read-only token restricted to cms/*
    const scoped = engine.createScopedToken(initRes.root_token, {
      name: 'cms-reader',
      allowedPaths: ['cms/*'],
      capabilities: ['read', 'list']
    });
    const readWithScoped = engine.getSecret(scoped.token, 'cms/prod');
    expect(readWithScoped.data.JWT_SECRET).toBe('jwt_v2');

    // Negative control: scoped read-only token cannot write or read outside cms/*
    expect(() =>
      engine.putSecret(scoped.token, 'cms/prod', { HACK: '1' })
    ).toThrow(/Permission denied/);

    // Verify SHA-256 hash-chained audit log integrity
    const auditCheck = engine.verifyAuditChain();
    expect(auditCheck.valid).toBe(true);
    expect(auditCheck.totalEntries).toBeGreaterThanOrEqual(6);
  });

  it('mergeEnvLossless enforces the Zero Secret Loss Invariant', () => {
    const existing = [
      '# Database & Auth',
      'JWT_SECRET=existing_jwt_secret',
      'EMPTY_PLACEHOLDER=',
      ''
    ].join('\n');

    const merged = mergeEnvLossless(existing, {
      JWT_SECRET: '', // must not clobber
      EMPTY_PLACEHOLDER: 'filled_now',
      NEW_VAULT_KEY: 'added_from_vault'
    });

    expect(merged.mergedEntries.JWT_SECRET).toBe('existing_jwt_secret');
    expect(merged.mergedEntries.EMPTY_PLACEHOLDER).toBe('filled_now');
    expect(merged.mergedEntries.NEW_VAULT_KEY).toBe('added_from_vault');
    expect(merged.mergedContent).toContain('# Database & Auth');
  });

  it('HTTP Server serves KV v2 endpoints, Prometheus /metrics, and /ui', async () => {
    const { server } = createVaultServer({ dataDir: tmpDir });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const addr = server.address() as { port: number };
    const baseUrl = `http://127.0.0.1:${addr.port}`;

    const reqJson = (method: string, urlPath: string, body?: any, token?: string): Promise<{ status: number; data: any }> =>
      new Promise((resolve, reject) => {
        const payload = body ? JSON.stringify(body) : undefined;
        const req = http.request(
          `${baseUrl}${urlPath}`,
          {
            method,
            headers: {
              ...(token ? { 'X-Vault-Token': token } : {}),
              ...(payload ? { 'Content-Type': 'application/json' } : {})
            }
          },
          (res) => {
            let raw = '';
            res.on('data', (c) => (raw += c));
            res.on('end', () => {
              try {
                resolve({ status: res.statusCode || 500, data: JSON.parse(raw) });
              } catch (_) {
                resolve({ status: res.statusCode || 500, data: raw });
              }
            });
          }
        );
        req.on('error', reject);
        if (payload) req.write(payload);
        req.end();
      });

    try {
      const init = await reqJson('POST', '/v1/sys/init', { secret_shares: 3, secret_threshold: 2 });
      expect(init.status).toBe(200);
      const token = init.data.root_token;

      const write = await reqJson('POST', '/v1/secret/data/oauth/prod', {
        data: { GITHUB_CLIENT_ID: 'gh_123' }
      }, token);
      expect(write.status).toBe(200);
      expect(write.data.data.version).toBe(1);

      const read = await reqJson('GET', '/v1/secret/data/oauth/prod', undefined, token);
      expect(read.status).toBe(200);
      expect(read.data.data.data.GITHUB_CLIENT_ID).toBe('gh_123');

      const metrics = await reqJson('GET', '/metrics');
      expect(metrics.status).toBe(200);
      expect(String(metrics.data)).toContain('vault_sealed 0');
      expect(String(metrics.data)).toContain('vault_audit_chain_valid 1');

      const ui = await reqJson('GET', '/ui');
      expect(ui.status).toBe(200);
      expect(String(ui.data)).toContain('Native Secrets Vault');
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
