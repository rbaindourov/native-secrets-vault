/**
 * src/crypto/envelope.ts
 * ──────────────────────────────────────────────────────────────────────────────
 * Envelope Encryption Engine using AES-256-GCM + HKDF-SHA256.
 *
 * Hierarchy:
 *   1. Master Unseal Key (256-bit, split via Shamir GF(256) shares)
 *   2. Root Data Encryption Key (DEK, 256-bit, wrapped at rest by Master Key)
 *   3. Per-Secret-Version Key (derived via HKDF-SHA256 from DEK + path + version)
 *   4. Ciphertext authenticated with AES-256-GCM + AAD bound to `path:v<version>`
 */

import crypto from 'crypto';

export interface EncryptedBlob {
  alg: 'AES-256-GCM';
  iv: string;      // base64 (12 bytes)
  tag: string;     // base64 (16 bytes)
  salt: string;    // base64 (16 bytes)
  aad: string;     // utf8 binding context
  ciphertext: string; // base64
}

/**
 * Derives a 256-bit subkey from a parent key using HKDF-SHA256.
 */
export function deriveSubkey(parentKey: Buffer, salt: Buffer, info: string): Buffer {
  if (parentKey.length !== 32) {
    throw new Error(`Expected 32-byte key, got ${parentKey.length}`);
  }
  const derived = crypto.hkdfSync('sha256', parentKey, salt, Buffer.from(info, 'utf8'), 32);
  return Buffer.from(derived);
}

/**
 * Encrypts plaintext bytes or UTF-8 string using AES-256-GCM with HKDF subkey
 * derivation and Additional Authenticated Data (AAD) context binding.
 */
export function encryptWithContext(
  rootKey: Buffer,
  plaintext: string | Buffer,
  aadContext: string
): EncryptedBlob {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const subkey = deriveSubkey(rootKey, salt, `nsv-envelope-v1:${aadContext}`);

  const cipher = crypto.createCipheriv('aes-256-gcm', subkey, iv);
  cipher.setAAD(Buffer.from(aadContext, 'utf8'));

  const inputBuf = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, 'utf8');
  const encrypted = Buffer.concat([cipher.update(inputBuf), cipher.final()]);
  const tag = cipher.getAuthTag();

  // Zero out transient subkey
  subkey.fill(0);

  return {
    alg: 'AES-256-GCM',
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    salt: salt.toString('base64'),
    aad: aadContext,
    ciphertext: encrypted.toString('base64')
  };
}

/**
 * Decrypts an EncryptedBlob using the root key and verifies the expected AAD
 * context. Throws if the ciphertext, tag, or AAD context has been tampered with.
 */
export function decryptWithContext(
  rootKey: Buffer,
  blob: EncryptedBlob,
  expectedAadContext: string
): Buffer {
  if (!blob || blob.alg !== 'AES-256-GCM') {
    throw new Error('Unsupported or malformed encrypted blob');
  }
  if (blob.aad !== expectedAadContext) {
    throw new Error(`AAD context mismatch: expected "${expectedAadContext}", got "${blob.aad}"`);
  }

  const salt = Buffer.from(blob.salt, 'base64');
  const iv = Buffer.from(blob.iv, 'base64');
  const tag = Buffer.from(blob.tag, 'base64');
  const ciphertext = Buffer.from(blob.ciphertext, 'base64');

  const subkey = deriveSubkey(rootKey, salt, `nsv-envelope-v1:${expectedAadContext}`);
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', subkey, iv);
    decipher.setAAD(Buffer.from(expectedAadContext, 'utf8'));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } finally {
    subkey.fill(0);
  }
}

/**
 * Encrypts an off-host disaster-recovery snapshot using scrypt + AES-256-GCM.
 */
export function encryptSnapshotWithPassphrase(plaintextJson: string, passphrase: string): string {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.scryptSync(passphrase, salt, 32);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from('nsv-dr-snapshot-v1', 'utf8'));
  const ct = Buffer.concat([cipher.update(Buffer.from(plaintextJson, 'utf8')), cipher.final()]);
  const tag = cipher.getAuthTag();
  key.fill(0);

  return JSON.stringify({
    format: 'nsv-snapshot-v1',
    alg: 'scrypt-aes-256-gcm',
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ciphertext: ct.toString('base64'),
    createdAt: new Date().toISOString()
  });
}

/**
 * Decrypts an off-host disaster-recovery snapshot encrypted with `encryptSnapshotWithPassphrase`.
 */
export function decryptSnapshotWithPassphrase(encryptedPayload: string, passphrase: string): string {
  const parsed = JSON.parse(encryptedPayload);
  if (parsed.format !== 'nsv-snapshot-v1') {
    throw new Error('Invalid snapshot format');
  }
  const salt = Buffer.from(parsed.salt, 'base64');
  const iv = Buffer.from(parsed.iv, 'base64');
  const tag = Buffer.from(parsed.tag, 'base64');
  const ct = Buffer.from(parsed.ciphertext, 'base64');

  const key = crypto.scryptSync(passphrase, salt, 32);
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAAD(Buffer.from('nsv-dr-snapshot-v1', 'utf8'));
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(ct), decipher.final()]);
    return plain.toString('utf8');
  } finally {
    key.fill(0);
  }
}
