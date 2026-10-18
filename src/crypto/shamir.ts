/**
 * src/crypto/shamir.ts
 * ──────────────────────────────────────────────────────────────────────────────
 * Pure TypeScript implementation of Shamir's Secret Sharing over GF(2^8) using
 * the Rijndael irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11b).
 *
 * Splits an arbitrary byte buffer (e.g., a 256-bit Master Unseal Key) into N
 * shares where any K shares reconstruct the exact secret via Lagrange
 * interpolation, and K-1 shares reveal zero information.
 */

import crypto from 'crypto';

const EXP_TABLE = new Uint8Array(512);
const LOG_TABLE = new Uint8Array(256);

(function initGF256Tables() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP_TABLE[i] = x;
    EXP_TABLE[i + 255] = x;
    LOG_TABLE[x] = i;
    // Multiply by generator 0x03 in GF(2^8) with modulus 0x11b
    let x2 = x << 1;
    if (x & 0x80) {
      x2 ^= 0x1b;
    }
    x = (x2 ^ x) & 0xff;
  }
  LOG_TABLE[0] = 0;
})();

export function gfAdd(a: number, b: number): number {
  return (a ^ b) & 0xff;
}

export function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return EXP_TABLE[LOG_TABLE[a & 0xff] + LOG_TABLE[b & 0xff]];
}

export function gfDiv(a: number, b: number): number {
  if (b === 0) {
    throw new Error('GF(256) division by zero');
  }
  if (a === 0) return 0;
  return EXP_TABLE[LOG_TABLE[a & 0xff] + 255 - LOG_TABLE[b & 0xff]];
}

/**
 * Evaluates a polynomial with coefficients `coeffs` (where coeffs[0] is the
 * constant term / secret byte) at `x` in GF(256).
 */
function evalPoly(coeffs: Uint8Array, x: number): number {
  let result = 0;
  for (let i = coeffs.length - 1; i >= 0; i--) {
    result = gfAdd(gfMul(result, x), coeffs[i]);
  }
  return result;
}

/**
 * Splits a secret Buffer into `shares` hex-encoded shares requiring `threshold`
 * shares to reconstruct.
 * Each share is formatted as `<1-byte-x-index-hex><y-bytes-hex>`.
 */
export function splitSecret(secret: Buffer, shares: number, threshold: number): string[] {
  if (!Buffer.isBuffer(secret) || secret.length === 0) {
    throw new Error('Secret must be a non-empty Buffer');
  }
  if (!Number.isInteger(shares) || shares < 1 || shares > 255) {
    throw new Error('Shares count must be an integer between 1 and 255');
  }
  if (!Number.isInteger(threshold) || threshold < 1 || threshold > shares) {
    throw new Error('Threshold must be an integer between 1 and shares');
  }

  if (threshold === 1) {
    return Array.from({ length: shares }, (_, idx) => {
      const shareBuf = Buffer.alloc(secret.length + 1);
      shareBuf[0] = idx + 1;
      secret.copy(shareBuf, 1);
      return shareBuf.toString('hex');
    });
  }

  const shareBuffers = Array.from({ length: shares }, (_, idx) => {
    const buf = Buffer.alloc(secret.length + 1);
    buf[0] = idx + 1; // x coordinate in [1..255]
    return buf;
  });

  const coeffs = new Uint8Array(threshold);
  for (let byteIdx = 0; byteIdx < secret.length; byteIdx++) {
    coeffs[0] = secret[byteIdx];
    const randCoeffs = crypto.randomBytes(threshold - 1);
    for (let k = 1; k < threshold; k++) {
      // Ensure top coefficient is non-zero
      coeffs[k] = randCoeffs[k - 1] === 0 ? 1 : randCoeffs[k - 1];
    }

    for (let s = 0; s < shares; s++) {
      const x = s + 1;
      shareBuffers[s][byteIdx + 1] = evalPoly(coeffs, x);
    }
  }

  return shareBuffers.map((b) => b.toString('hex'));
}

/**
 * Combines `threshold` or more hex-encoded shares via Lagrange interpolation
 * at x = 0 over GF(2^8) to reconstruct the original secret Buffer.
 */
export function combineShares(hexShares: string[]): Buffer {
  if (!Array.isArray(hexShares) || hexShares.length === 0) {
    throw new Error('At least one share is required');
  }

  const parsedShares: { x: number; y: Buffer }[] = [];
  const seenX = new Set<number>();

  for (const raw of hexShares) {
    const clean = String(raw || '').trim();
    const buf = Buffer.from(clean, 'hex');
    if (buf.length < 2) {
      throw new Error('Invalid Shamir share format');
    }
    const x = buf[0];
    if (x === 0) {
      throw new Error('Invalid share x-coordinate 0');
    }
    if (seenX.has(x)) {
      continue; // Deduplicate identical shares
    }
    seenX.add(x);
    parsedShares.push({ x, y: buf.subarray(1) });
  }

  const secretLength = parsedShares[0].y.length;
  for (const s of parsedShares) {
    if (s.y.length !== secretLength) {
      throw new Error('Mismatched share lengths');
    }
  }

  if (parsedShares.length === 1) {
    return Buffer.from(parsedShares[0].y);
  }

  const secret = Buffer.alloc(secretLength);
  const k = parsedShares.length;

  for (let byteIdx = 0; byteIdx < secretLength; byteIdx++) {
    let val = 0;
    for (let i = 0; i < k; i++) {
      let num = 1;
      let den = 1;
      for (let j = 0; j < k; j++) {
        if (i === j) continue;
        num = gfMul(num, parsedShares[j].x);
        den = gfMul(den, gfAdd(parsedShares[i].x, parsedShares[j].x));
      }
      const basis = gfDiv(num, den);
      val = gfAdd(val, gfMul(parsedShares[i].y[byteIdx], basis));
    }
    secret[byteIdx] = val;
  }

  return secret;
}
