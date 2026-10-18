/**
 * src/storage/auditLog.ts
 * ──────────────────────────────────────────────────────────────────────────────
 * Tamper-evident SHA-256 hash-chained audit log for Native Secrets Vault.
 *
 * Every secret read, write, deletion, token creation, or seal state transition
 * appends a cryptographically linked record:
 *   hash_i = SHA256(prevHash_i || index || timestamp || actor || action || path || status)
 * Raw secret values are NEVER written to the audit log.
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

export interface AuditEntry {
  index: number;
  timestamp: string;
  actor: string;
  action: string;
  path: string;
  status: 'success' | 'denied' | 'error';
  metadata?: Record<string, string | number | boolean>;
  prevHash: string;
  hash: string;
}

export interface AuditVerificationResult {
  valid: boolean;
  totalEntries: number;
  headHash: string;
  brokenAtIndex?: number;
}

const GENESIS_HASH = '0'.repeat(64);

function computeEntryHash(entry: Omit<AuditEntry, 'hash'>): string {
  const canonical = JSON.stringify({
    index: entry.index,
    timestamp: entry.timestamp,
    actor: entry.actor,
    action: entry.action,
    path: entry.path,
    status: entry.status,
    metadata: entry.metadata || {},
    prevHash: entry.prevHash
  });
  return crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
}

export class AuditLogger {
  private readonly logFilePath: string;
  private entries: AuditEntry[] = [];

  constructor(dataDir: string) {
    fs.mkdirSync(dataDir, { recursive: true });
    this.logFilePath = path.join(dataDir, 'audit.jsonl');
    this.loadFromDisk();
  }

  private loadFromDisk(): void {
    if (!fs.existsSync(this.logFilePath)) {
      this.entries = [];
      return;
    }
    const raw = fs.readFileSync(this.logFilePath, 'utf8').trim();
    if (!raw) {
      this.entries = [];
      return;
    }
    this.entries = raw
      .split('\n')
      .filter(Boolean)
      .map((line) => JSON.parse(line) as AuditEntry);
  }

  public append(params: {
    actor: string;
    action: string;
    path: string;
    status: 'success' | 'denied' | 'error';
    metadata?: Record<string, string | number | boolean>;
  }): AuditEntry {
    const index = this.entries.length;
    const prevHash = index === 0 ? GENESIS_HASH : this.entries[index - 1].hash;
    const partial: Omit<AuditEntry, 'hash'> = {
      index,
      timestamp: new Date().toISOString(),
      actor: params.actor || 'anonymous',
      action: params.action,
      path: params.path,
      status: params.status,
      metadata: params.metadata || {},
      prevHash
    };
    const hash = computeEntryHash(partial);
    const fullEntry: AuditEntry = { ...partial, hash };

    this.entries.push(fullEntry);
    fs.appendFileSync(this.logFilePath, JSON.stringify(fullEntry) + '\n', {
      encoding: 'utf8',
      mode: 0o600
    });
    return fullEntry;
  }

  public verifyChain(): AuditVerificationResult {
    let expectedPrev = GENESIS_HASH;
    for (let i = 0; i < this.entries.length; i++) {
      const e = this.entries[i];
      if (e.index !== i || e.prevHash !== expectedPrev) {
        return {
          valid: false,
          totalEntries: this.entries.length,
          headHash: this.entries[this.entries.length - 1]?.hash || GENESIS_HASH,
          brokenAtIndex: i
        };
      }
      const recomputed = computeEntryHash({
        index: e.index,
        timestamp: e.timestamp,
        actor: e.actor,
        action: e.action,
        path: e.path,
        status: e.status,
        metadata: e.metadata || {},
        prevHash: e.prevHash
      });
      if (recomputed !== e.hash) {
        return {
          valid: false,
          totalEntries: this.entries.length,
          headHash: this.entries[this.entries.length - 1]?.hash || GENESIS_HASH,
          brokenAtIndex: i
        };
      }
      expectedPrev = e.hash;
    }

    return {
      valid: true,
      totalEntries: this.entries.length,
      headHash:
        this.entries.length > 0
          ? this.entries[this.entries.length - 1].hash
          : GENESIS_HASH
    };
  }

  public listRecent(limit = 50): AuditEntry[] {
    return this.entries.slice(-limit).reverse();
  }

  public count(): number {
    return this.entries.length;
  }
}
