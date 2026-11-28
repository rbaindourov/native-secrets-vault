/**
 * src/browser/webauthnPasskey.ts
 * ──────────────────────────────────────────────────────────────────────────────
 * Zero-Dependency W3C WebAuthn Level 3 / FIDO2 CTAP2 Passkey Cryptographic Engine
 * for Native Secrets Vault.
 *
 * Design Lineage (Open-Source Reference Architecture):
 *   1. HashiCorp Vault Transit Engine (`transit/sign/:name`):
 *      Asymmetric signing keys (`ES256` P-256 / `EdDSA` Ed25519) are generated
 *      inside Vault, encrypted at rest with AES-256-GCM envelope encryption, and
 *      NEVER leave the Vault boundary in plaintext (`privateKeyPkcs8Base64` is
 *      strictly stripped from all summary/list/ceremony responses).
 *   2. 1Password `passkey-rs` (`passkey-authenticator` / `passkey-types`):
 *      - Multi-device synced passkey flags: `UP (0x01) | UV (0x04) | BE (0x08) | BS (0x10)`
 *        (`0x5d` with `AT=0x40` during registration; `0x1d` during assertion).
 *      - Wire `signCount = 0` (`0x00000000`) per WebAuthn L3 §6.1.2 for synced
 *        multi-workstation credentials so standby node hydration/failover never
 *        triggers false-positive hardware clone lockouts, while Vault tracks
 *        `usageCount` and `lastUsedAt` internally.
 *      - Supports `credProps` extension (`{ credProps: { rk: true } }`) and
 *        zero AAGUID (`00000000-0000-0000-0000-000000000000`) for `fmt: "none"`.
 *   3. Bitwarden `clients` (`apps/browser/src/autofill/fido2/`):
 *      Strict W3C §13.4.3 RP ID registrable-suffix validation against caller
 *      origin, `excludeCredentials` duplicate rejection (`InvalidStateError`),
 *      and `allowCredentials` filtering.
 */

import crypto from 'crypto';
import { URL } from 'url';

export type SupportedCoseAlg = -7 | -8 | -257; // -7 = ES256 (ECDSA P-256), -8 = EdDSA (Ed25519), -257 = RS256 (RSA-2048)

export interface StoredPasskeyRecord {
  id: string;
  credentialId: string; // base64url rawId
  label?: string;
  rpId: string;
  rpName: string;
  origin: string;
  registrableDomain: string;
  userHandleBase64Url: string;
  userName: string;
  userDisplayName: string;
  alg: SupportedCoseAlg;
  publicKeySpkiBase64Url: string;
  privateKeyPkcs8Base64: string; // Stored ONLY inside AES-256-GCM Vault KV; NEVER returned over HTTP
  cosePublicKeyBase64Url: string;
  aaguid: string;
  discoverable: boolean;
  transports: string[];
  usageCount: number;
  createdAt: string;
  updatedAt: string;
  lastUsedAt: string;
}

export type BrowserPasskeySummary = Omit<StoredPasskeyRecord, 'privateKeyPkcs8Base64'> & {
  matchType?: 'exact_rpid' | 'parent_rpid' | 'all';
};

export interface PasskeyRegisterRequest {
  origin: string;
  rpId?: string;
  rpName?: string;
  userHandleBase64Url: string;
  userName: string;
  userDisplayName?: string;
  challengeBase64Url?: string;
  clientDataJSONBase64Url?: string;
  pubKeyCredParams?: Array<{ type?: string; alg: number }>;
  excludeCredentialIds?: string[];
  credPropsRequested?: boolean;
  discoverable?: boolean;
}

export interface PasskeyRegisterResult {
  passkey: BrowserPasskeySummary;
  credential: {
    id: string;
    rawIdBase64Url: string;
    type: 'public-key';
    authenticatorAttachment: 'platform';
    clientDataJSONBase64Url: string;
    attestationObjectBase64Url: string;
    authenticatorDataBase64Url: string;
    publicKeySpkiBase64Url: string;
    publicKeyAlgorithm: SupportedCoseAlg;
    transports: string[];
    clientExtensionResults: Record<string, unknown>;
  };
}

export interface PasskeyAuthenticateRequest {
  origin: string;
  rpId?: string;
  credentialId?: string;
  allowCredentialIds?: string[];
  challengeBase64Url?: string;
  clientDataJSONBase64Url?: string;
}

export interface PasskeyAuthenticateResult {
  passkey: BrowserPasskeySummary;
  assertion: {
    id: string;
    rawIdBase64Url: string;
    type: 'public-key';
    authenticatorAttachment: 'platform';
    clientDataJSONBase64Url: string;
    authenticatorDataBase64Url: string;
    signatureBase64Url: string;
    userHandleBase64Url: string;
    clientExtensionResults: Record<string, unknown>;
  };
}

const MULTI_PART_PUBLIC_SUFFIXES = new Set([
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

// WebAuthn Authenticator Data Flag Bits (W3C WebAuthn L3 §6.1)
export const WEBAUTHN_FLAG_UP = 0x01; // User Present
export const WEBAUTHN_FLAG_UV = 0x04; // User Verified
export const WEBAUTHN_FLAG_BE = 0x08; // Backup Eligible (multi-workstation Vault sync)
export const WEBAUTHN_FLAG_BS = 0x10; // Backup State (actively backed up in Vault)
export const WEBAUTHN_FLAG_AT = 0x40; // Attested Credential Data included

export const FLAGS_ATTESTATION_SYNCED =
  WEBAUTHN_FLAG_UP | WEBAUTHN_FLAG_UV | WEBAUTHN_FLAG_BE | WEBAUTHN_FLAG_BS | WEBAUTHN_FLAG_AT; // 0x5d
export const FLAGS_ASSERTION_SYNCED =
  WEBAUTHN_FLAG_UP | WEBAUTHN_FLAG_UV | WEBAUTHN_FLAG_BE | WEBAUTHN_FLAG_BS; // 0x1d

export function toBase64Url(buf: Buffer | Uint8Array): string {
  return Buffer.from(buf)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

export function fromBase64Url(raw: string): Buffer {
  const clean = String(raw || '')
    .trim()
    .replace(/-/g, '+')
    .replace(/_/g, '/');
  if (!clean || !/^[A-Za-z0-9+/=]+$/.test(clean)) {
    throw new Error('Invalid base64url input');
  }
  const padLen = (4 - (clean.length % 4)) % 4;
  return Buffer.from(clean + '='.repeat(padLen), 'base64');
}

function encodeCborHead(majorType: number, lengthOrVal: number | bigint): Buffer {
  const mt = (majorType & 0x07) << 5;
  const v = BigInt(lengthOrVal);
  if (v < 24n) {
    return Buffer.from([mt | Number(v)]);
  }
  if (v <= 0xffn) {
    return Buffer.from([mt | 24, Number(v)]);
  }
  if (v <= 0xffffn) {
    const b = Buffer.alloc(3);
    b[0] = mt | 25;
    b.writeUInt16BE(Number(v), 1);
    return b;
  }
  if (v <= 0xffffffffn) {
    const b = Buffer.alloc(5);
    b[0] = mt | 26;
    b.writeUInt32BE(Number(v), 1);
    return b;
  }
  const b = Buffer.alloc(9);
  b[0] = mt | 27;
  b.writeBigUInt64BE(v, 1);
  return b;
}

/**
 * Deterministic RFC 8949 / CTAP2 canonical CBOR encoder supporting integers,
 * byte strings, UTF-8 strings, booleans, null, arrays, Maps, and plain objects.
 */
export function encodeCbor(value: unknown): Buffer {
  if (value === null || value === undefined) {
    return Buffer.from([0xf6]);
  }
  if (typeof value === 'boolean') {
    return Buffer.from([value ? 0xf5 : 0xf4]);
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) {
      throw new Error(`CBOR encoder supports safe integers only, got: ${value}`);
    }
    if (value >= 0) {
      return encodeCborHead(0, value);
    }
    return encodeCborHead(1, -1 - value);
  }
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value);
    return Buffer.concat([encodeCborHead(2, bytes.length), bytes]);
  }
  if (typeof value === 'string') {
    const utf8 = Buffer.from(value, 'utf8');
    return Buffer.concat([encodeCborHead(3, utf8.length), utf8]);
  }
  if (Array.isArray(value)) {
    const parts = value.map((item) => encodeCbor(item));
    return Buffer.concat([encodeCborHead(4, parts.length), ...parts]);
  }
  if (value instanceof Map || (typeof value === 'object' && value !== null)) {
    const rawEntries: Array<[unknown, unknown]> =
      value instanceof Map ? Array.from(value.entries()) : Object.entries(value as Record<string, unknown>);
    const encodedEntries = rawEntries.map(([k, v]) => ({
      keyBuf: encodeCbor(k),
      valBuf: encodeCbor(v)
    }));
    // Canonical CTAP2 / RFC 8949 ordering: shorter encoded key first, then bytewise lexicographic
    encodedEntries.sort(
      (a, b) => a.keyBuf.length - b.keyBuf.length || Buffer.compare(a.keyBuf, b.keyBuf)
    );
    const flat: Buffer[] = [encodeCborHead(5, encodedEntries.length)];
    for (const entry of encodedEntries) {
      flat.push(entry.keyBuf, entry.valBuf);
    }
    return Buffer.concat(flat);
  }
  throw new Error(`Unsupported CBOR value type: ${typeof value}`);
}

export function isLoopbackWebAuthnHost(hostname: string): boolean {
  return (
    hostname === 'localhost' ||
    hostname.endsWith('.localhost') ||
    hostname === '127.0.0.1' ||
    hostname === '[::1]'
  );
}

/**
 * Enforces W3C WebAuthn §13.4.3 Origin & Relying Party ID Security Rules:
 *   1. Origin must be `https://` (or `http://` strictly on `localhost` / `127.0.0.1`).
 *   2. Effective `rpId` defaults to origin's hostname when omitted.
 *   3. `rpId` cannot be a bare TLD / public suffix (`com`, `co.uk`, etc.).
 *   4. Origin hostname must equal `rpId` or be a subdomain (`*.rpId`).
 */
export function validateRpIdForOrigin(
  requestedRpId: string | undefined,
  rawOrigin: string
): { normalizedOrigin: string; originHostname: string; effectiveRpId: string } {
  const trimmedOrigin = String(rawOrigin || '').trim();
  if (!trimmedOrigin) {
    throw new Error('WebAuthn origin is required');
  }
  let parsed: URL;
  try {
    parsed = new URL(trimmedOrigin);
  } catch (_) {
    throw new Error(`Invalid WebAuthn origin URL: ${trimmedOrigin}`);
  }

  const protocol = parsed.protocol.toLowerCase();
  const originHostname = parsed.hostname.toLowerCase().replace(/\.+$/, '');
  const normalizedOrigin = parsed.origin.toLowerCase();

  if (protocol !== 'https:' && !(protocol === 'http:' && isLoopbackWebAuthnHost(originHostname))) {
    throw new Error(`WebAuthn requires an HTTPS origin (or loopback localhost), got: ${normalizedOrigin}`);
  }

  const effectiveRpId = requestedRpId
    ? String(requestedRpId).trim().toLowerCase().replace(/\.+$/, '')
    : originHostname;

  if (!effectiveRpId || /[/:?\s#\\]/.test(effectiveRpId)) {
    throw new Error(`Invalid WebAuthn rpId: "${requestedRpId}"`);
  }

  if (!isLoopbackWebAuthnHost(effectiveRpId)) {
    const labels = effectiveRpId.split('.');
    if (labels.length < 2 || labels.some((l) => !l)) {
      throw new Error(`SecurityError: rpId "${effectiveRpId}" is not a registrable domain`);
    }
    if (MULTI_PART_PUBLIC_SUFFIXES.has(effectiveRpId)) {
      throw new Error(`SecurityError: rpId "${effectiveRpId}" is a public suffix`);
    }
  }

  const isExact = originHostname === effectiveRpId;
  const isSubdomain = originHostname.endsWith(`.${effectiveRpId}`);
  if (!isExact && !isSubdomain) {
    throw new Error(
      `SecurityError: rpId "${effectiveRpId}" is not valid for origin "${normalizedOrigin}"`
    );
  }

  return { normalizedOrigin, originHostname, effectiveRpId };
}

export function selectCoseAlgorithm(
  pubKeyCredParams?: Array<{ type?: string; alg: number }>
): SupportedCoseAlg {
  if (!Array.isArray(pubKeyCredParams) || pubKeyCredParams.length === 0) {
    return -7; // Default ES256
  }
  for (const param of pubKeyCredParams) {
    if (param && (!param.type || param.type === 'public-key')) {
      if (param.alg === -7 || param.alg === -8 || param.alg === -257) {
        return param.alg;
      }
    }
  }
  throw new Error(
    `NotSupportedError: None of the requested pubKeyCredParams algorithms (${pubKeyCredParams
      .map((p) => p?.alg)
      .join(', ')}) are supported (supported: -7 ES256, -8 EdDSA, -257 RS256)`
  );
}

export function resolveAndVerifyClientDataJson(options: {
  expectedType: 'webauthn.create' | 'webauthn.get';
  normalizedOrigin: string;
  clientDataJSONBase64Url?: string;
  challengeBase64Url?: string;
}): { clientDataBytes: Buffer; clientDataJSONBase64Url: string } {
  if (options.clientDataJSONBase64Url) {
    const clientDataBytes = fromBase64Url(options.clientDataJSONBase64Url);
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(clientDataBytes.toString('utf8'));
    } catch (_) {
      throw new Error('Invalid clientDataJSON UTF-8 payload');
    }
    if (parsed.type !== options.expectedType) {
      throw new Error(
        `clientDataJSON type mismatch: expected "${options.expectedType}", got "${String(parsed.type)}"`
      );
    }
    if (String(parsed.origin || '').toLowerCase() !== options.normalizedOrigin) {
      throw new Error(
        `SecurityError: clientDataJSON origin "${String(parsed.origin)}" does not match verified origin "${options.normalizedOrigin}"`
      );
    }
    if (typeof parsed.challenge !== 'string' || !parsed.challenge.trim()) {
      throw new Error('clientDataJSON is missing a valid base64url challenge');
    }
    return {
      clientDataBytes,
      clientDataJSONBase64Url: toBase64Url(clientDataBytes)
    };
  }

  const challenge = String(options.challengeBase64Url || '').trim();
  if (!challenge) {
    throw new Error('Either clientDataJSONBase64Url or challengeBase64Url is required');
  }
  // Validate challenge decodes cleanly
  fromBase64Url(challenge);
  const canonicalJson = JSON.stringify({
    type: options.expectedType,
    challenge,
    origin: options.normalizedOrigin,
    crossOrigin: false
  });
  const clientDataBytes = Buffer.from(canonicalJson, 'utf8');
  return {
    clientDataBytes,
    clientDataJSONBase64Url: toBase64Url(clientDataBytes)
  };
}

function padCoord32(buf: Buffer, label: string): Buffer {
  if (buf.length === 32) return buf;
  if (buf.length < 32) {
    const out = Buffer.alloc(32, 0);
    buf.copy(out, 32 - buf.length);
    return out;
  }
  throw new Error(`Unexpected ${label} coordinate byte length: ${buf.length}`);
}

function generateWebAuthnKeyMaterial(alg: SupportedCoseAlg): {
  privateKeyPkcs8Base64: string;
  publicKeySpkiBase64Url: string;
  cosePublicKey: Buffer;
} {
  if (alg === -7) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1'
    });
    const pkcs8Der = privateKey.export({ type: 'pkcs8', format: 'der' }) as Buffer;
    const spkiDer = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
    const jwk = publicKey.export({ format: 'jwk' }) as { x?: string; y?: string };
    if (!jwk.x || !jwk.y) {
      throw new Error('Failed to export P-256 JWK coordinates');
    }
    const xBuf = padCoord32(fromBase64Url(jwk.x), 'EC P-256 x');
    const yBuf = padCoord32(fromBase64Url(jwk.y), 'EC P-256 y');

    // RFC 9052 / 9053 COSE_Key for EC2 ES256 (P-256)
    const coseMap = new Map<number, unknown>([
      [1, 2], // kty: EC2
      [3, -7], // alg: ES256
      [-1, 1], // crv: P-256
      [-2, xBuf],
      [-3, yBuf]
    ]);
    return {
      privateKeyPkcs8Base64: pkcs8Der.toString('base64'),
      publicKeySpkiBase64Url: toBase64Url(spkiDer),
      cosePublicKey: encodeCbor(coseMap)
    };
  }

  if (alg === -8) {
    // EdDSA / Ed25519
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const pkcs8Der = privateKey.export({ type: 'pkcs8', format: 'der' }) as Buffer;
    const spkiDer = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
    const jwk = publicKey.export({ format: 'jwk' }) as { x?: string };
    if (!jwk.x) {
      throw new Error('Failed to export Ed25519 JWK public key');
    }
    const xBuf = padCoord32(fromBase64Url(jwk.x), 'Ed25519 x');
    const coseMap = new Map<number, unknown>([
      [1, 1], // kty: OKP
      [3, -8], // alg: EdDSA
      [-1, 6], // crv: Ed25519
      [-2, xBuf]
    ]);
    return {
      privateKeyPkcs8Base64: pkcs8Der.toString('base64'),
      publicKeySpkiBase64Url: toBase64Url(spkiDer),
      cosePublicKey: encodeCbor(coseMap)
    };
  }

  // alg === -257 (RS256 / RSASSA-PKCS1-v1_5 with SHA-256, 2048-bit RSA)
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicExponent: 0x10001
  });
  const pkcs8Der = privateKey.export({ type: 'pkcs8', format: 'der' }) as Buffer;
  const spkiDer = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
  const jwk = publicKey.export({ format: 'jwk' }) as { n?: string; e?: string };
  if (!jwk.n || !jwk.e) {
    throw new Error('Failed to export RSA-2048 JWK modulus/exponent');
  }
  const nBuf = fromBase64Url(jwk.n);
  const eBuf = fromBase64Url(jwk.e);
  const coseMap = new Map<number, unknown>([
    [1, 3], // kty: RSA (RFC 8230)
    [3, -257], // alg: RS256 (RFC 8812)
    [-1, nBuf], // n: modulus
    [-2, eBuf] // e: public exponent
  ]);
  return {
    privateKeyPkcs8Base64: pkcs8Der.toString('base64'),
    publicKeySpkiBase64Url: toBase64Url(spkiDer),
    cosePublicKey: encodeCbor(coseMap)
  };
}

export function sanitizePasskeySummary(
  record: StoredPasskeyRecord,
  matchType?: BrowserPasskeySummary['matchType']
): BrowserPasskeySummary {
  const { privateKeyPkcs8Base64: _redacted, ...rest } = record;
  return matchType ? { ...rest, matchType } : rest;
}

export function buildPasskeyRegistration(
  req: PasskeyRegisterRequest,
  registrableDomain: string,
  nowIso: string
): { storedRecord: StoredPasskeyRecord; response: PasskeyRegisterResult } {
  const { normalizedOrigin, effectiveRpId } = validateRpIdForOrigin(req.rpId, req.origin);
  const userName = String(req.userName || '').trim();
  if (!userName) {
    throw new Error('Passkey userName is required');
  }
  const userHandleBytes = fromBase64Url(req.userHandleBase64Url);
  if (userHandleBytes.length === 0 || userHandleBytes.length > 64) {
    throw new Error('Passkey user.id (userHandle) must be 1..64 bytes per WebAuthn specification');
  }

  const { clientDataJSONBase64Url } = resolveAndVerifyClientDataJson({
    expectedType: 'webauthn.create',
    normalizedOrigin,
    clientDataJSONBase64Url: req.clientDataJSONBase64Url,
    challengeBase64Url: req.challengeBase64Url
  });

  const alg = selectCoseAlgorithm(req.pubKeyCredParams);
  const credentialIdBytes = crypto.randomBytes(16);
  const credentialId = toBase64Url(credentialIdBytes);
  const vaultRecordId = `pk_${credentialIdBytes.toString('hex')}`;

  const keyMat = generateWebAuthnKeyMaterial(alg);

  // Build AuthenticatorData: rpIdHash(32) || flags(1: 0x5d) || signCount(4: 0) || aaguid(16: 0) || credIdLen(2) || credId(16) || cosePubKey
  const rpIdHash = crypto.createHash('sha256').update(effectiveRpId, 'utf8').digest();
  const flagsBuf = Buffer.from([FLAGS_ATTESTATION_SYNCED]);
  const signCountBuf = Buffer.alloc(4, 0); // 0 for multi-workstation synced passkeys (1Password passkey-rs standard)
  const aaguidBuf = Buffer.alloc(16, 0); // 00000000-0000-0000-0000-000000000000 for fmt: "none"
  const credIdLenBuf = Buffer.alloc(2);
  credIdLenBuf.writeUInt16BE(credentialIdBytes.length, 0);

  const authData = Buffer.concat([
    rpIdHash,
    flagsBuf,
    signCountBuf,
    aaguidBuf,
    credIdLenBuf,
    credentialIdBytes,
    keyMat.cosePublicKey
  ]);

  const attestationObject = encodeCbor(
    new Map<string, unknown>([
      ['fmt', 'none'],
      ['attStmt', new Map()],
      ['authData', authData]
    ])
  );

  const discoverable = req.discoverable !== false;
  const transports = ['internal', 'hybrid'];
  const storedRecord: StoredPasskeyRecord = {
    id: vaultRecordId,
    credentialId,
    rpId: effectiveRpId,
    rpName: String(req.rpName || effectiveRpId).trim() || effectiveRpId,
    origin: normalizedOrigin,
    registrableDomain,
    userHandleBase64Url: toBase64Url(userHandleBytes),
    userName,
    userDisplayName: String(req.userDisplayName || userName).trim() || userName,
    alg,
    publicKeySpkiBase64Url: keyMat.publicKeySpkiBase64Url,
    privateKeyPkcs8Base64: keyMat.privateKeyPkcs8Base64,
    cosePublicKeyBase64Url: toBase64Url(keyMat.cosePublicKey),
    aaguid: '00000000-0000-0000-0000-000000000000',
    discoverable,
    transports,
    usageCount: 0,
    createdAt: nowIso,
    updatedAt: nowIso,
    lastUsedAt: nowIso
  };

  const clientExtensionResults: Record<string, unknown> = {};
  if (req.credPropsRequested) {
    clientExtensionResults.credProps = { rk: discoverable };
  }

  return {
    storedRecord,
    response: {
      passkey: sanitizePasskeySummary(storedRecord),
      credential: {
        id: credentialId,
        rawIdBase64Url: credentialId,
        type: 'public-key',
        authenticatorAttachment: 'platform',
        clientDataJSONBase64Url,
        attestationObjectBase64Url: toBase64Url(attestationObject),
        authenticatorDataBase64Url: toBase64Url(authData),
        publicKeySpkiBase64Url: keyMat.publicKeySpkiBase64Url,
        publicKeyAlgorithm: alg,
        transports,
        clientExtensionResults
      }
    }
  };
}

export function buildPasskeyAssertion(
  record: StoredPasskeyRecord,
  req: PasskeyAuthenticateRequest
): { authenticatorDataBase64Url: string; signatureBase64Url: string; clientDataJSONBase64Url: string } {
  const { normalizedOrigin, effectiveRpId } = validateRpIdForOrigin(req.rpId || record.rpId, req.origin);
  if (effectiveRpId !== record.rpId.toLowerCase()) {
    throw new Error(
      `SecurityError: Stored passkey rpId "${record.rpId}" does not match requested rpId "${effectiveRpId}"`
    );
  }

  const { clientDataBytes, clientDataJSONBase64Url } = resolveAndVerifyClientDataJson({
    expectedType: 'webauthn.get',
    normalizedOrigin,
    clientDataJSONBase64Url: req.clientDataJSONBase64Url,
    challengeBase64Url: req.challengeBase64Url
  });

  // AuthenticatorData: rpIdHash(32) || flags(1: 0x1d) || signCount(4: 0)
  const rpIdHash = crypto.createHash('sha256').update(record.rpId.toLowerCase(), 'utf8').digest();
  const flagsBuf = Buffer.from([FLAGS_ASSERTION_SYNCED]);
  const signCountBuf = Buffer.alloc(4, 0);
  const authData = Buffer.concat([rpIdHash, flagsBuf, signCountBuf]);

  const clientDataHash = crypto.createHash('sha256').update(clientDataBytes).digest();
  const signedPayload = Buffer.concat([authData, clientDataHash]);

  const privateKey = crypto.createPrivateKey({
    key: Buffer.from(record.privateKeyPkcs8Base64, 'base64'),
    format: 'der',
    type: 'pkcs8'
  });

  const signature =
    record.alg === -8
      ? crypto.sign(null, signedPayload, privateKey)
      : record.alg === -257
      ? crypto.sign('sha256', signedPayload, privateKey)
      : crypto.sign('sha256', signedPayload, { key: privateKey, dsaEncoding: 'der' });

  return {
    authenticatorDataBase64Url: toBase64Url(authData),
    signatureBase64Url: toBase64Url(signature),
    clientDataJSONBase64Url
  };
}
