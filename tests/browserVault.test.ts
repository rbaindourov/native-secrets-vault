import fs from 'fs';
import os from 'os';
import path from 'path';
import http from 'http';
import { createVaultServer, generateTotpCode } from '../src';

function httpJson(
  port: number,
  method: string,
  urlPath: string,
  body?: unknown,
  token?: string,
  originHeader?: string
): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: any }> {
  return new Promise((resolve, reject) => {
    const payload = body !== undefined ? JSON.stringify(body) : undefined;
    const headers: Record<string, string> = { Accept: 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    if (originHeader) headers['Origin'] = originHeader;
    if (payload !== undefined) {
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = String(Buffer.byteLength(payload));
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
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}

describe('Winome Browser Vault Service & Scoped User Isolation', () => {
  let tmpDir: string;
  let server: http.Server;
  let port: number;
  let rootToken: string;

  beforeAll(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nsv-winome-test-'));
    const created = createVaultServer({ dataDir: tmpDir });
    server = created.server;
    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => resolve());
    });
    port = (server.address() as any).port;

    const initRes = await httpJson(port, 'POST', '/v1/sys/init', {
      secret_shares: 3,
      secret_threshold: 2
    });
    expect(initRes.status).toBe(200);
    rootToken = initRes.body.root_token;

    // Seed an infrastructure secret to prove user tokens cannot access it
    await httpJson(
      port,
      'POST',
      '/v1/secret/data/cms/prod',
      { data: { JWT_SECRET: 'super-secret-cluster-key' } },
      rootToken
    );
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('computes deterministic RFC 6238 TOTP codes', () => {
    // JBSWY3DPEHPK3PXP == "Hello!\xDE\xAD\xBE\xEF"
    const res = generateTotpCode('JBSWY3DPEHPK3PXP', { nowMs: 1700000000000 });
    expect(res.code).toMatch(/^\d{6}$/);
    expect(res.remainingSeconds).toBeGreaterThan(0);
    expect(res.remainingSeconds).toBeLessThanOrEqual(30);
  });

  it('mints isolated user tokens via broker token and blocks cross-user or cluster reads', async () => {
    // Create a non-root users_backend broker token restricted to winome/*
    const brokerRes = await httpJson(
      port,
      'POST',
      '/api/v1/tokens',
      {
        name: 'users-backend-broker',
        allowedPaths: ['winome/*'],
        capabilities: ['read', 'write', 'list', 'delete']
      },
      rootToken
    );
    expect(brokerRes.status).toBe(201);
    const brokerToken = brokerRes.body.token;

    const aliceMint = await httpJson(
      port,
      'POST',
      '/api/v1/tokens/mint-user-scope',
      { userId: 'user_alice_01', ttlSeconds: 3600 },
      brokerToken
    );
    expect(aliceMint.status).toBe(201);
    expect(aliceMint.body.namespace).toBe('winome/user_alice_01');
    const aliceToken = aliceMint.body.token;

    const bobMint = await httpJson(
      port,
      'POST',
      '/api/v1/tokens/mint-user-scope',
      { userId: 'user_bob_02', ttlSeconds: 3600 },
      brokerToken
    );
    expect(bobMint.status).toBe(201);
    const bobToken = bobMint.body.token;

    // Alice's user token MUST NOT be able to mint tokens for Bob
    const escalationAttempt = await httpJson(
      port,
      'POST',
      '/api/v1/tokens/mint-user-scope',
      { userId: 'user_bob_02' },
      aliceToken
    );
    expect(escalationAttempt.status).toBe(403);

    // Alice's token MUST NOT be able to read cms/prod
    const clusterReadAttempt = await httpJson(
      port,
      'GET',
      '/v1/secret/data/cms/prod',
      undefined,
      aliceToken
    );
    expect(clusterReadAttempt.status).toBe(403);

    // Store login with TOTP for Alice
    const saveLogin = await httpJson(
      port,
      'POST',
      '/api/v1/browser/user_alice_01/logins',
      {
        origin: 'https://app.acme.co.uk/login',
        username: 'alice@acme.co.uk',
        password: 'CorrectHorseBatteryStaple!99',
        totpSecret: 'JBSWY3DPEHPK3PXP'
      },
      aliceToken,
      'chrome-extension://abcdefghijklmnop'
    );
    expect(saveLogin.status).toBe(200);
    expect(saveLogin.headers['access-control-allow-origin']).toBe(
      'chrome-extension://abcdefghijklmnop'
    );
    expect(saveLogin.body.login.totpCode).toMatch(/^\d{6}$/);

    // Bob MUST get 403 trying to list Alice's logins
    const bobReadsAlice = await httpJson(
      port,
      'GET',
      '/api/v1/browser/user_alice_01/logins',
      undefined,
      bobToken
    );
    expect(bobReadsAlice.status).toBe(403);

    // Exact origin + sibling subdomain matching on co.uk multi-part TLD
    const exactMatch = await httpJson(
      port,
      'GET',
      '/api/v1/browser/user_alice_01/logins?origin=https://app.acme.co.uk',
      undefined,
      aliceToken
    );
    expect(exactMatch.status).toBe(200);
    expect(exactMatch.body.count).toBe(1);
    expect(exactMatch.body.logins[0].matchType).toBe('exact_origin');
    expect(exactMatch.body.logins[0].password).toBe('CorrectHorseBatteryStaple!99');

    const subMatch = await httpJson(
      port,
      'GET',
      '/api/v1/browser/user_alice_01/logins?origin=https://billing.acme.co.uk',
      undefined,
      aliceToken
    );
    expect(subMatch.status).toBe(200);
    expect(subMatch.body.count).toBe(1);
    expect(subMatch.body.logins[0].matchType).toBe('subdomain');

    const unrelatedMatch = await httpJson(
      port,
      'GET',
      '/api/v1/browser/user_alice_01/logins?origin=https://evil.co.uk',
      undefined,
      aliceToken
    );
    expect(unrelatedMatch.status).toBe(200);
    expect(unrelatedMatch.body.count).toBe(0);

    // Sensitive payment card storage + deletion
    const cardSave = await httpJson(
      port,
      'POST',
      '/api/v1/browser/user_alice_01/sensitive-forms',
      {
        category: 'payment_card',
        label: 'Corporate Visa 4242',
        fields: { cardNumber: '4242424242424242', cvv: '889', expiry: '11/29' }
      },
      aliceToken
    );
    expect(cardSave.status).toBe(200);
    const cardId = cardSave.body.entry.id;

    const cardList = await httpJson(
      port,
      'GET',
      '/api/v1/browser/user_alice_01/sensitive-forms?category=payment_card',
      undefined,
      aliceToken
    );
    expect(cardList.body.count).toBe(1);
    expect(cardList.body.entries[0].fields.cvv).toBe('889');

    const cardDel = await httpJson(
      port,
      'DELETE',
      `/api/v1/browser/user_alice_01/sensitive-forms/${cardId}`,
      undefined,
      aliceToken
    );
    expect(cardDel.status).toBe(200);

    const cardListAfter = await httpJson(
      port,
      'GET',
      '/api/v1/browser/user_alice_01/sensitive-forms',
      undefined,
      aliceToken
    );
    expect(cardListAfter.body.count).toBe(0);

    // ABM Service Integrations round-trip
    await httpJson(
      port,
      'PUT',
      '/api/v1/browser/user_alice_01/integrations',
      { crmApiKey: 'crm_live_123', cmsPitchApiKey: 'cms_pitch_456' },
      aliceToken
    );
    const integRes = await httpJson(
      port,
      'GET',
      '/api/v1/browser/user_alice_01/integrations',
      undefined,
      aliceToken
    );
    expect(integRes.body.integrations.crmApiKey).toBe('crm_live_123');
    expect(integRes.body.integrations.cmsPitchApiKey).toBe('cms_pitch_456');

    // Audit chain must remain 100% cryptographically valid
    const auditVerify = await httpJson(port, 'GET', '/api/v1/audit/verify');
    expect(auditVerify.body.valid).toBe(true);
  });
});
