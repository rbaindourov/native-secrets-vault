/**
 * src/storage/auditLog.ts
 * ──────────────────────────────────────────────────────────────────────────────
 * Tamper-evident SHA-256 hash-chained audit log for Native Secrets Vault
 * with bounded active segments and cryptographic checkpoint rotation.
 *
 * Every secret read, write, deletion, token creation, or seal state transition
 * appends a cryptographically linked record:
 *   hash_i = SHA256(prevHash_i || index || timestamp || actor || action || path || status)
 * Raw secret values are NEVER written to the audit log.
 *
 * Active `audit.jsonl` segments rotate automatically at `maxSegmentEntries`
 * (default 25,000) or `maxSegmentBytes` (default 16 MiB — 32x below V8's
 * 512 MiB string limit), persisting `{ baseIndex, anchorHash }` in
 * `audit-checkpoint.json` so memory, startup I/O, and `/api/v1/audit/verify`
 * remain strictly O(1) bounded regardless of total lifetime operations.
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

export interface AuditLoggerOptions {
  maxSegmentEntries?: number;
  maxSegmentBytes?: number;
  maxArchivedSegments?: number;
}

interface AuditCheckpoint {
  baseIndex: number;
  anchorHash: string;
  rotatedAt: string;
}

const GENESIS_HASH = '0'.repeat(64);
const DEFAULT_MAX_SEGMENT_ENTRIES = 25_000;
const DEFAULT_MAX_SEGMENT_BYTES = 16 * 1024 * 1024; // 16 MiB
const DEFAULT_MAX_ARCHIVED_SEGMENTS = 5;
const TAIL_PROBE_BYTES = 64 * 1024; // 64 KiB tail window for oversized legacy logs

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
  private readonly dataDir: string;
  private readonly logFilePath: string;
  private readonly checkpointPath: string;
  private readonly snapshotsDir: string;
  private readonly maxSegmentEntries: number;
  private readonly maxSegmentBytes: number;
  private readonly maxArchivedSegments: number;

  private baseIndex = 0;
  private anchorHash = GENESIS_HASH;
  private currentFileBytes = 0;
  private entries: AuditEntry[] = [];

  constructor(dataDir: string, options: AuditLoggerOptions = {}) {
    this.dataDir = dataDir;
    fs.mkdirSync(dataDir, { recursive: true });
    this.logFilePath = path.join(dataDir, 'audit.jsonl');
    this.checkpointPath = path.join(dataDir, 'audit-checkpoint.json');
    this.snapshotsDir = path.join(dataDir, 'snapshots');
    this.maxSegmentEntries = options.maxSegmentEntries ?? DEFAULT_MAX_SEGMENT_ENTRIES;
    this.maxSegmentBytes = options.maxSegmentBytes ?? DEFAULT_MAX_SEGMENT_BYTES;
    this.maxArchivedSegments = options.maxArchivedSegments ?? DEFAULT_MAX_ARCHIVED_SEGMENTS;
    this.loadFromDisk();
  }

  private loadCheckpoint(): void {
    if (!fs.existsSync(this.checkpointPath)) {
      this.baseIndex = 0;
      this.anchorHash = GENESIS_HASH;
      return;
    }
    try {
      const raw = fs.readFileSync(this.checkpointPath, 'utf8');
      const parsed = JSON.parse(raw) as Partial<AuditCheckpoint>;
      if (
        typeof parsed.baseIndex === 'number' &&
        parsed.baseIndex >= 0 &&
        typeof parsed.anchorHash === 'string' &&
        parsed.anchorHash.length === 64
      ) {
        this.baseIndex = parsed.baseIndex;
        this.anchorHash = parsed.anchorHash;
      }
    } catch (_) {
      this.baseIndex = 0;
      this.anchorHash = GENESIS_HASH;
    }
  }

  private saveCheckpoint(checkpoint: AuditCheckpoint): void {
    const tmpPath = `${this.checkpointPath}.tmp.${process.pid}`;
    fs.writeFileSync(tmpPath, JSON.stringify(checkpoint, null, 2) + '\n', {
      encoding: 'utf8',
      mode: 0o600
    });
    fs.renameSync(tmpPath, this.checkpointPath);
  }

  private readLastEntryFromTail(fileSize: number): AuditEntry | null {
    const readLen = Math.min(fileSize, TAIL_PROBE_BYTES);
    const offset = Math.max(0, fileSize - readLen);
    const buf = Buffer.alloc(readLen);
    const fd = fs.openSync(this.logFilePath, 'r');
    try {
      fs.readSync(fd, buf, 0, readLen, offset);
    } finally {
      fs.closeSync(fd);
    }
    const lines = buf.toString('utf8').split('\n');
    // Skip index 0 if we started mid-file to avoid partial JSON line
    const startIdx = offset > 0 ? 1 : 0;
    for (let i = lines.length - 1; i >= startIdx; i--) {
      const trimmed = lines[i].trim();
      if (!trimmed) continue;
      try {
        const parsed = JSON.parse(trimmed) as AuditEntry;
        if (typeof parsed.index === 'number' && typeof parsed.hash === 'string') {
          return parsed;
        }
      } catch (_) {
        // Ignore truncated trailing line
      }
    }
    return null;
  }

  private pruneArchivedSegments(): void {
    if (!fs.existsSync(this.snapshotsDir)) return;
    try {
      const rotated = fs
        .readdirSync(this.snapshotsDir)
        .filter((f) => f.startsWith('audit-rotated-') && f.endsWith('.jsonl'))
        .sort();
      while (rotated.length > this.maxArchivedSegments) {
        const oldest = rotated.shift()!;
        try {
          fs.unlinkSync(path.join(this.snapshotsDir, oldest));
        } catch (_) {}
      }
    } catch (_) {}
  }

  private rotateActiveSegment(lastEntry: AuditEntry | null): void {
    fs.mkdirSync(this.snapshotsDir, { recursive: true });
    const suffix = lastEntry ? `${lastEntry.index}` : 'oversized';
    const archiveName = `audit-rotated-${Date.now()}-${suffix}.jsonl`;
    const archivePath = path.join(this.snapshotsDir, archiveName);

    if (fs.existsSync(this.logFilePath)) {
      fs.renameSync(this.logFilePath, archivePath);
    }

    if (lastEntry) {
      this.baseIndex = lastEntry.index + 1;
      this.anchorHash = lastEntry.hash;
      this.saveCheckpoint({
        baseIndex: this.baseIndex,
        anchorHash: this.anchorHash,
        rotatedAt: new Date().toISOString()
      });
    }

    this.entries = [];
    this.currentFileBytes = 0;
    this.pruneArchivedSegments();
  }

  private loadFromDisk(): void {
    this.loadCheckpoint();

    if (!fs.existsSync(this.logFilePath)) {
      this.entries = [];
      this.currentFileBytes = 0;
      return;
    }

    const stat = fs.statSync(this.logFilePath);
    if (stat.size === 0) {
      this.entries = [];
      this.currentFileBytes = 0;
      return;
    }

    // Never call fs.readFileSync on an oversized file (prevents V8 ERR_STRING_TOO_LONG & OOM)
    if (stat.size > this.maxSegmentBytes) {
      const tailEntry = this.readLastEntryFromTail(stat.size);
      this.rotateActiveSegment(tailEntry);
      return;
    }

    const raw = fs.readFileSync(this.logFilePath, 'utf8').trim();
    if (!raw) {
      this.entries = [];
      this.currentFileBytes = 0;
      return;
    }

    const loaded: AuditEntry[] = [];
    for (const line of raw.split('\n')) {
      if (!line.trim()) continue;
      loaded.push(JSON.parse(line) as AuditEntry);
    }
    this.entries = loaded;
    this.currentFileBytes = stat.size;

    if (this.entries.length > 0 && this.baseIndex === 0 && this.entries[0].index > 0) {
      this.baseIndex = this.entries[0].index;
      this.anchorHash = this.entries[0].prevHash;
    }

    if (this.entries.length >= this.maxSegmentEntries) {
      this.rotateActiveSegment(this.entries[this.entries.length - 1]);
    }
  }

  public append(params: {
    actor: string;
    action: string;
    path: string;
    status: 'success' | 'denied' | 'error';
    metadata?: Record<string, string | number | boolean>;
  }): AuditEntry {
    const index = this.baseIndex + this.entries.length;
    const prevHash =
      this.entries.length === 0
        ? this.anchorHash
        : this.entries[this.entries.length - 1].hash;

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

    const serialized = JSON.stringify(fullEntry) + '\n';
    fs.appendFileSync(this.logFilePath, serialized, {
      encoding: 'utf8',
      mode: 0o600
    });
    this.entries.push(fullEntry);
    this.currentFileBytes += Buffer.byteLength(serialized, 'utf8');

    if (
      this.entries.length >= this.maxSegmentEntries ||
      this.currentFileBytes >= this.maxSegmentBytes
    ) {
      this.rotateActiveSegment(fullEntry);
    }

    return fullEntry;
  }

  public verifyChain(): AuditVerificationResult {
    let expectedPrev = this.anchorHash;
    const totalEntries = this.count();

    for (let i = 0; i < this.entries.length; i++) {
      const e = this.entries[i];
      const expectedIndex = this.baseIndex + i;
      if (e.index !== expectedIndex || e.prevHash !== expectedPrev) {
        return {
          valid: false,
          totalEntries,
          headHash:
            this.entries[this.entries.length - 1]?.hash || this.anchorHash,
          brokenAtIndex: expectedIndex
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
          totalEntries,
          headHash:
            this.entries[this.entries.length - 1]?.hash || this.anchorHash,
          brokenAtIndex: expectedIndex
        };
      }
      expectedPrev = e.hash;
    }

    return {
      valid: true,
      totalEntries,
      headHash:
        this.entries.length > 0
          ? this.entries[this.entries.length - 1].hash
          : this.anchorHash
    };
  }

  public listRecent(limit = 50): AuditEntry[] {
    return this.entries.slice(-limit).reverse();
  }

  public count(): number {
    return this.baseIndex + this.entries.length;
  }
}
