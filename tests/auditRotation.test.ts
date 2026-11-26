import fs from 'fs';
import os from 'os';
import path from 'path';
import { AuditLogger } from '../src/storage/auditLog';

describe('AuditLogger bounded rotation & oversized log recovery', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nsv-audit-rot-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('rotates active segments at maxSegmentEntries while preserving hash-chain continuity across restarts', () => {
    const logger = new AuditLogger(tmpDir, {
      maxSegmentEntries: 10,
      maxArchivedSegments: 2
    });

    for (let i = 0; i < 25; i++) {
      logger.append({
        actor: 'winome-user:test',
        action: 'kv.read',
        path: `winome/test/cred_${i}`,
        status: 'success'
      });
    }

    expect(logger.count()).toBe(25);
    expect(logger.listRecent(50).length).toBe(5); // 20 rotated (2x10), 5 in active segment
    const check1 = logger.verifyChain();
    expect(check1.valid).toBe(true);
    expect(check1.totalEntries).toBe(25);

    // Reload from disk and append more entries
    const reloaded = new AuditLogger(tmpDir, {
      maxSegmentEntries: 10,
      maxArchivedSegments: 2
    });
    expect(reloaded.count()).toBe(25);
    expect(reloaded.verifyChain().valid).toBe(true);

    reloaded.append({
      actor: 'root',
      action: 'kv.write',
      path: 'cms/prod',
      status: 'success'
    });
    expect(reloaded.count()).toBe(26);
    expect(reloaded.verifyChain().valid).toBe(true);

    const archived = fs
      .readdirSync(path.join(tmpDir, 'snapshots'))
      .filter((f) => f.startsWith('audit-rotated-'));
    expect(archived.length).toBeLessThanOrEqual(2);
  });

  it('recovers cleanly on startup if an existing audit.jsonl exceeds maxSegmentBytes without full-file read', () => {
    // Seed a valid multi-entry log with high limit, then reopen with tiny maxSegmentBytes
    const seed = new AuditLogger(tmpDir, { maxSegmentEntries: 1000, maxSegmentBytes: 10 * 1024 * 1024 });
    let lastHash = '';
    for (let i = 0; i < 30; i++) {
      lastHash = seed.append({
        actor: 'bulk-sync',
        action: 'kv.read',
        path: `winome/u1/item_${i}`,
        status: 'success'
      }).hash;
    }

    const reopened = new AuditLogger(tmpDir, { maxSegmentBytes: 1024 });
    expect(reopened.count()).toBe(30);
    const check = reopened.verifyChain();
    expect(check.valid).toBe(true);
    expect(check.headHash).toBe(lastHash);

    const next = reopened.append({
      actor: 'bulk-sync',
      action: 'kv.read',
      path: 'winome/u1/item_30',
      status: 'success'
    });
    expect(next.index).toBe(30);
    expect(next.prevHash).toBe(lastHash);
    expect(reopened.verifyChain().valid).toBe(true);
  });
});
