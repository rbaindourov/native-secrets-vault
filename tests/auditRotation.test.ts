import fs from 'fs';
import os from 'os';
import path from 'path';
import { AuditLogger } from '../src/storage/auditLog';
import { NativeSecretsVaultEngine } from '../src/storage/vaultEngine';
import { BrowserVaultService } from '../src/browser/browserVaultService';

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

  it('BrowserVaultService batch-upserts in one flush and serves repeated origin lookups with zero N+1 audit writes', () => {
    const engine = new NativeSecretsVaultEngine(tmpDir);
    const init = engine.init({ secretShares: 3, secretThreshold: 2 });
    const svc = new BrowserVaultService(engine);
    const minted = engine.mintUserScopedToken(init.root_token, 'usr_chunk_test', 3600);

    const batch = Array.from({ length: 40 }, (_, idx) => ({
      origin: `https://site-${idx}.com`,
      username: `user${idx}@site-${idx}.com`,
      password: `pw_${idx}`
    }));

    const res = svc.upsertLoginsBatch(minted.token, 'usr_chunk_test', batch);
    expect(res.upserted).toBe(40);

    const countBefore = engine.verifyAuditChain().totalEntries;
    // 25 repeated origin autofill lookups across tabs/iframes must write 0 new kv.read lines
    for (let i = 0; i < 25; i++) {
      const hits = svc.listLogins(minted.token, 'usr_chunk_test', 'https://site-7.com');
      expect(hits.length).toBe(1);
      expect(hits[0].username).toBe('user7@site-7.com');
    }
    const countAfter = engine.verifyAuditChain().totalEntries;
    expect(countAfter).toBe(countBefore);
  });
});
