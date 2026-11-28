import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import http from 'http';
import {
  createVaultServer,
  fromBase64Url,
  toBase64Url,
  FLAGS_ASSERTION_SYNCED,
  FLAGS_ATTESTATION_SYNCED
} from '../src';

function httpJson(
  port: number,
  method: string,
  urlPath: string,
  body?: unknown,
  token?: string
): Promise<{ status: number; body: any }> {
  return new Promise((resolve, reject) => {
    const payload = body !== undefined ? JSON.stringify(body) : undefined;
    const headers: Record<string, string> = { Accept: 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;
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
          resolve({ status: res.statusCode || 0, body: parsed });
        });
      }
    );
    req.on('error', reject);
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}

describe('WebAuthn / FIDO2 Synced Passkeys (Transit Key Isolation + RP Verification)', () => {
  let tmpDir: string;
  let server: http.Server;
  let port: number;
  let rootToken: string;
  let aliceToken: string;
  let bobToken: string;

  beforeAll(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nsv-passkeys-test-'));
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

    const aliceMint = await httpJson(
      port,
      'POST',
      '/api/v1/tokens/mint-user-scope',
      { userId: 'alice_ws', ttlSeconds: 3600 },
      rootToken
    );
    expect(aliceMint.status).toBe(201);
    aliceToken = aliceMint.body.token;

    const bobMint = await httpJson(
      port,
      'POST',
      '/api/v1/tokens/mint-user-scope',
      { userId: 'bob_ws', ttlSeconds: 3600 },
      rootToken
    );
    expect(bobMint.status).toBe(201);
    bobToken = bobMint.body.token;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('registers ES256 (P-256) synced passkey, never leaks private key, and verifies Relying Party signature across subdomains', async () => {
    const createChallenge = toBase64Url(crypto.randomBytes(32));
    const userHandle = toBase64Url(Buffer.from('x_uid_123456789', 'utf8'));
    const createClientData = toBase64Url(
      Buffer.from(
        JSON.stringify({
          type: 'webauthn.create',
          challenge: createChallenge,
          origin: 'https://x.com',
          crossOrigin: false
        }),
        'utf8'
      )
    );

    const regRes = await httpJson(
      port,
      'POST',
      '/api/v1/browser/alice_ws/passkeys/register',
      {
        origin: 'https://x.com',
        rpId: 'x.com',
        rpName: 'X',
        userHandleBase64Url: userHandle,
        userName: '@RBaindourov',
        userDisplayName: 'Robert Baindourov',
        clientDataJSONBase64Url: createClientData,
        pubKeyCredParams: [
          { type: 'public-key', alg: -7 },
          { type: 'public-key', alg: -257 }
        ],
        credPropsRequested: true
      },
      aliceToken
    );

    expect(regRes.status).toBe(201);
    expect(regRes.body.ok).toBe(true);
    // HashiCorp Transit invariant: privateKeyPkcs8Base64 MUST NEVER appear anywhere in response
    expect(JSON.stringify(regRes.body)).not.toContain('privateKeyPkcs8Base64');
    expect(regRes.body.credential.publicKeyAlgorithm).toBe(-7);
    expect(regRes.body.credential.clientExtensionResults).toEqual({ credProps: { rk: true } });

    const credId = regRes.body.credential.id;
    const spkiDer = fromBase64Url(regRes.body.credential.publicKeySpkiBase64Url);
    const createAuthData = fromBase64Url(regRes.body.credential.authenticatorDataBase64Url);

    // Verify AuthenticatorData layout: rpIdHash(32) || flags(1: 0x5d) || signCount(4: 0) || aaguid(16: 0) || credIdLen(2) || credId(16) || COSE_Key
    const expectedRpIdHash = crypto.createHash('sha256').update('x.com', 'utf8').digest();
    expect(createAuthData.subarray(0, 32).equals(expectedRpIdHash)).toBe(true);
    expect(createAuthData[32]).toBe(FLAGS_ATTESTATION_SYNCED); // 0x5d
    expect(createAuthData.readUInt32BE(33)).toBe(0);
    expect(createAuthData.subarray(37, 53).equals(Buffer.alloc(16, 0))).toBe(true);
    expect(createAuthData.readUInt16BE(53)).toBe(16);

    // Duplicate registration with excludeCredentials MUST return 409 InvalidStateError
    const dupRes = await httpJson(
      port,
      'POST',
      '/api/v1/browser/alice_ws/passkeys/register',
      {
        origin: 'https://x.com',
        rpId: 'x.com',
        userHandleBase64Url: userHandle,
        userName: '@RBaindourov',
        challengeBase64Url: toBase64Url(crypto.randomBytes(32)),
        excludeCredentialIds: [credId]
      },
      aliceToken
    );
    expect(dupRes.status).toBe(409);
    expect(dupRes.body.errors[0]).toContain('InvalidStateError:');

    // Authenticate from sibling subdomain https://mobile.x.com with rpId = "x.com"
    const getChallenge = toBase64Url(crypto.randomBytes(32));
    const getClientDataBytes = Buffer.from(
      JSON.stringify({
        type: 'webauthn.get',
        challenge: getChallenge,
        origin: 'https://mobile.x.com',
        crossOrigin: false
      }),
      'utf8'
    );

    const authRes = await httpJson(
      port,
      'POST',
      '/api/v1/browser/alice_ws/passkeys/authenticate',
      {
        origin: 'https://mobile.x.com',
        rpId: 'x.com',
        allowCredentialIds: [credId],
        clientDataJSONBase64Url: toBase64Url(getClientDataBytes)
      },
      aliceToken
    );

    expect(authRes.status).toBe(200);
    expect(JSON.stringify(authRes.body)).not.toContain('privateKeyPkcs8Base64');
    expect(authRes.body.passkey.usageCount).toBe(1);
    expect(authRes.body.assertion.id).toBe(credId);
    expect(authRes.body.assertion.userHandleBase64Url).toBe(userHandle);

    // Genuine Relying Party cryptographic verification using only SPKI public key
    const assertAuthData = fromBase64Url(authRes.body.assertion.authenticatorDataBase64Url);
    const signatureDer = fromBase64Url(authRes.body.assertion.signatureBase64Url);
    expect(assertAuthData.length).toBe(37);
    expect(assertAuthData.subarray(0, 32).equals(expectedRpIdHash)).toBe(true);
    expect(assertAuthData[32]).toBe(FLAGS_ASSERTION_SYNCED); // 0x1d (UP|UV|BE|BS)
    expect(assertAuthData.readUInt32BE(33)).toBe(0); // Synced passkey wire signCount = 0

    const clientDataHash = crypto.createHash('sha256').update(getClientDataBytes).digest();
    const publicKeyObj = crypto.createPublicKey({ key: spkiDer, format: 'der', type: 'spki' });
    const sigValid = crypto.verify(
      'sha256',
      Buffer.concat([assertAuthData, clientDataHash]),
      { key: publicKeyObj, dsaEncoding: 'der' },
      signatureDer
    );
    expect(sigValid).toBe(true);

    // Listing passkeys from workstation #2 returns synced metadata without private key
    const listRes = await httpJson(
      port,
      'GET',
      '/api/v1/browser/alice_ws/passkeys?origin=https://x.com',
      undefined,
      aliceToken
    );
    expect(listRes.status).toBe(200);
    expect(listRes.body.count).toBe(1);
    expect(listRes.body.passkeys[0].userName).toBe('@RBaindourov');
    expect(listRes.body.passkeys[0].usageCount).toBe(1);
    expect(listRes.body.passkeys[0].privateKeyPkcs8Base64).toBeUndefined();
  });

  it('supports EdDSA (-8 / Ed25519) passkeys and verifies signatures', async () => {
    const regRes = await httpJson(
      port,
      'POST',
      '/api/v1/browser/alice_ws/passkeys/register',
      {
        origin: 'https://github.com',
        rpId: 'github.com',
        userHandleBase64Url: toBase64Url(Buffer.from('gh_999', 'utf8')),
        userName: 'rbaindourov',
        challengeBase64Url: toBase64Url(crypto.randomBytes(32)),
        pubKeyCredParams: [{ type: 'public-key', alg: -8 }]
      },
      aliceToken
    );
    expect(regRes.status).toBe(201);
    expect(regRes.body.credential.publicKeyAlgorithm).toBe(-8);

    const authRes = await httpJson(
      port,
      'POST',
      '/api/v1/browser/alice_ws/passkeys/authenticate',
      {
        origin: 'https://github.com',
        rpId: 'github.com',
        challengeBase64Url: toBase64Url(crypto.randomBytes(32))
      },
      aliceToken
    );
    expect(authRes.status).toBe(200);

    const spkiDer = fromBase64Url(regRes.body.credential.publicKeySpkiBase64Url);
    const authData = fromBase64Url(authRes.body.assertion.authenticatorDataBase64Url);
    const clientDataBytes = fromBase64Url(authRes.body.assertion.clientDataJSONBase64Url);
    const sig = fromBase64Url(authRes.body.assertion.signatureBase64Url);
    const pubKey = crypto.createPublicKey({ key: spkiDer, format: 'der', type: 'spki' });

    const valid = crypto.verify(
      null,
      Buffer.concat([authData, crypto.createHash('sha256').update(clientDataBytes).digest()]),
      pubKey,
      sig
    );
    expect(valid).toBe(true);
  });

  it('blocks phishing origins, public-suffix rpIds, clientDataJSON spoofing, cross-user access, and supports deletion', async () => {
    // 1. Phishing domain evil-x.com attempting to sign x.com passkey
    const phishing = await httpJson(
      port,
      'POST',
      '/api/v1/browser/alice_ws/passkeys/authenticate',
      {
        origin: 'https://evil-x.com',
        rpId: 'x.com',
        challengeBase64Url: toBase64Url(crypto.randomBytes(32))
      },
      aliceToken
    );
    expect(phishing.status).toBe(400);
    expect(phishing.body.errors[0]).toContain('SecurityError:');

    // 2. Public suffix rpId ("co.uk" or "com") rejected
    const pslAttack = await httpJson(
      port,
      'POST',
      '/api/v1/browser/alice_ws/passkeys/register',
      {
        origin: 'https://attacker.co.uk',
        rpId: 'co.uk',
        userHandleBase64Url: toBase64Url(Buffer.from('bad', 'utf8')),
        userName: 'bad',
        challengeBase64Url: toBase64Url(crypto.randomBytes(32))
      },
      aliceToken
    );
    expect(pslAttack.status).toBe(400);
    expect(pslAttack.body.errors[0]).toContain('SecurityError:');

    // 3. Spoofed clientDataJSON origin rejected
    const spoofedClientData = toBase64Url(
      Buffer.from(
        JSON.stringify({
          type: 'webauthn.get',
          challenge: toBase64Url(crypto.randomBytes(32)),
          origin: 'https://x.com'
        }),
        'utf8'
      )
    );
    const spoofAttack = await httpJson(
      port,
      'POST',
      '/api/v1/browser/alice_ws/passkeys/authenticate',
      {
        origin: 'https://evil.com',
        rpId: 'evil.com',
        clientDataJSONBase64Url: spoofedClientData
      },
      aliceToken
    );
    expect(spoofAttack.status).toBe(404); // evil.com has no passkey (and cannot request x.com)

    // Spoofed clientDataJSON on matching rpId where clientDataJSON claims wrong origin
    const spoofClientDataOnX = toBase64Url(
      Buffer.from(
        JSON.stringify({
          type: 'webauthn.get',
          challenge: toBase64Url(crypto.randomBytes(32)),
          origin: 'https://evil.com'
        }),
        'utf8'
      )
    );
    const spoofOnX = await httpJson(
      port,
      'POST',
      '/api/v1/browser/alice_ws/passkeys/authenticate',
      {
        origin: 'https://x.com',
        rpId: 'x.com',
        clientDataJSONBase64Url: spoofClientDataOnX
      },
      aliceToken
    );
    expect(spoofOnX.status).toBe(400);
    expect(spoofOnX.body.errors[0]).toContain('SecurityError:');

    // 4. Cross-user isolation: Bob gets 403 trying to use Alice's passkeys
    const bobSteals = await httpJson(
      port,
      'POST',
      '/api/v1/browser/alice_ws/passkeys/authenticate',
      {
        origin: 'https://x.com',
        rpId: 'x.com',
        challengeBase64Url: toBase64Url(crypto.randomBytes(32))
      },
      bobToken
    );
    expect(bobSteals.status).toBe(403);

    // 5. Delete passkey and verify audit chain integrity
    const allBefore = await httpJson(
      port,
      'GET',
      '/api/v1/browser/alice_ws/passkeys',
      undefined,
      aliceToken
    );
    expect(allBefore.body.count).toBe(2);
    const ghPasskey = allBefore.body.passkeys.find((p: any) => p.rpId === 'github.com');
    const delRes = await httpJson(
      port,
      'DELETE',
      `/api/v1/browser/alice_ws/passkeys/${ghPasskey.id}`,
      undefined,
      aliceToken
    );
    expect(delRes.status).toBe(200);

    const allAfter = await httpJson(
      port,
      'GET',
      '/api/v1/browser/alice_ws/passkeys',
      undefined,
      aliceToken
    );
    expect(allAfter.body.count).toBe(1);

    const auditVerify = await httpJson(port, 'GET', '/api/v1/audit/verify');
    expect(auditVerify.body.valid).toBe(true);
  });

  it('supports RS256 (-257) RSA-only Relying Parties, WebAuthn Signal API sync, and rejects malformed Base64URL or cross-origin Signal calls (negative controls)', async () => {
    const rsaChallenge = toBase64Url(crypto.randomBytes(32));
    const rsaUserHandle = toBase64Url(Buffer.from('rsa_uid_999', 'utf8'));

    // 1. Register RSA-only (-257) passkey
    const regRsa = await httpJson(
      port,
      'POST',
      '/api/v1/browser/alice_ws/passkeys/register',
      {
        origin: 'https://enterprise.example.com',
        rpId: 'example.com',
        rpName: 'Enterprise Portal',
        userHandleBase64Url: rsaUserHandle,
        userName: 'alice@example.com',
        userDisplayName: 'Alice OldName',
        challengeBase64Url: rsaChallenge,
        pubKeyCredParams: [{ type: 'public-key', alg: -257 }]
      },
      aliceToken
    );
    expect(regRsa.status).toBe(201);
    expect(regRsa.body.credential.publicKeyAlgorithm).toBe(-257);

    // Verify RS256 assertion signature using exported SPKI public key
    const authChallenge = toBase64Url(crypto.randomBytes(32));
    const authRsa = await httpJson(
      port,
      'POST',
      '/api/v1/browser/alice_ws/passkeys/authenticate',
      {
        origin: 'https://login.example.com',
        rpId: 'example.com',
        credentialId: regRsa.body.credential.id,
        challengeBase64Url: authChallenge
      },
      aliceToken
    );
    expect(authRsa.status).toBe(200);

    const spkiKey = crypto.createPublicKey({
      key: fromBase64Url(regRsa.body.credential.publicKeySpkiBase64Url),
      format: 'der',
      type: 'spki'
    });
    const authData = fromBase64Url(authRsa.body.assertion.authenticatorDataBase64Url);
    const clientDataHash = crypto
      .createHash('sha256')
      .update(fromBase64Url(authRsa.body.assertion.clientDataJSONBase64Url))
      .digest();
    const isValidRsa = crypto.verify(
      'sha256',
      Buffer.concat([authData, clientDataHash]),
      spkiKey,
      fromBase64Url(authRsa.body.assertion.signatureBase64Url)
    );
    expect(isValidRsa).toBe(true);

    // 2. Negative control: Signal API rejects human-readable non-Base64URL IDs (`length % 4 === 1` or invalid chars)
    const badSignal = await httpJson(
      port,
      'POST',
      '/api/v1/browser/alice_ws/passkeys/signal',
      {
        signalType: 'unknownCredential',
        origin: 'https://login.example.com',
        rpId: 'example.com',
        credentialId: 'not:valid:base64url='
      },
      aliceToken
    );
    expect(badSignal.status).toBe(400);
    expect(badSignal.body.errors[0]).toContain('Invalid base64url');

    // 3. Negative control: Cross-origin Signal API spoof rejected
    const crossOriginSignal = await httpJson(
      port,
      'POST',
      '/api/v1/browser/alice_ws/passkeys/signal',
      {
        signalType: 'unknownCredential',
        origin: 'https://attacker.org',
        rpId: 'example.com',
        credentialId: regRsa.body.credential.id
      },
      aliceToken
    );
    expect(crossOriginSignal.status).toBe(400);
    expect(crossOriginSignal.body.errors[0]).toContain('SecurityError:');

    // 4. Positive Signal API: signalCurrentUserDetails updates userName/userDisplayName
    const updateDetails = await httpJson(
      port,
      'POST',
      '/api/v1/browser/alice_ws/passkeys/signal',
      {
        signalType: 'currentUserDetails',
        origin: 'https://accounts.example.com',
        rpId: 'example.com',
        userId: rsaUserHandle,
        name: 'alice.renamed@example.com',
        displayName: 'Alice Renamed'
      },
      aliceToken
    );
    expect(updateDetails.status).toBe(200);
    expect(updateDetails.body.updated).toBe(1);

    const listedAfterRename = await httpJson(
      port,
      'GET',
      '/api/v1/browser/alice_ws/passkeys?rpId=example.com',
      undefined,
      aliceToken
    );
    expect(listedAfterRename.body.passkeys[0].userName).toBe('alice.renamed@example.com');
    expect(listedAfterRename.body.passkeys[0].userDisplayName).toBe('Alice Renamed');

    // 5. Positive Signal API: signalUnknownCredential prunes orphaned passkey
    const pruneOrphan = await httpJson(
      port,
      'POST',
      '/api/v1/browser/alice_ws/passkeys/signal',
      {
        signalType: 'unknownCredential',
        origin: 'https://accounts.example.com',
        rpId: 'example.com',
        credentialId: regRsa.body.credential.id
      },
      aliceToken
    );
    expect(pruneOrphan.status).toBe(200);
    expect(pruneOrphan.body.deleted).toBe(1);
  });
});
