#!/usr/bin/env node
/**
 * bin/nsv.js
 * ──────────────────────────────────────────────────────────────────────────────
 * Official CLI for Native Secrets Vault (`nsv`).
 *
 * Commands:
 *   nsv status
 *   nsv init [--shares=3] [--threshold=2] [--save-file=.vault-data/unseal-init.json]
 *   nsv unseal <share-key>
 *   nsv seal
 *   nsv kv put <path> KEY=VALUE [KEY2=VALUE2 ...] [--from-json=file.json]
 *   nsv kv get <path> [--field=KEY] [--format=json|table|dotenv]
 *   nsv kv list [prefix]
 *   nsv sync-env <target-env-file> [--paths=cms/prod,oauth/prod] [--dry-run] [--overwrite]
 *   nsv audit verify
 *   nsv snapshot save <out-file.enc> --passphrase=<pass>
 */

'use strict';

const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const { URL } = require('url');
const { syncVaultSecretsToEnvFile, formatEnvValue } = require('../dist/sync/dotenvSync');

const VAULT_ADDR = process.env.VAULT_ADDR || process.env.NSV_ADDR || 'http://127.0.0.1:8200';

function resolveToken(explicitToken) {
  if (explicitToken) return explicitToken;
  if (process.env.VAULT_TOKEN) return process.env.VAULT_TOKEN;
  if (process.env.NSV_TOKEN) return process.env.NSV_TOKEN;
  const localInit = path.join(process.cwd(), '.vault-data/unseal-init.json');
  if (fs.existsSync(localInit)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(localInit, 'utf8'));
      if (parsed.root_token) return parsed.root_token;
    } catch (_) {}
  }
  return '';
}

function httpRequestJson(method, endpoint, bodyObj, token) {
  return new Promise((resolve, reject) => {
    const u = new URL(endpoint, VAULT_ADDR);
    const lib = u.protocol === 'https:' ? https : http;
    const payload = bodyObj ? JSON.stringify(bodyObj) : null;

    const headers = {
      Accept: 'application/json'
    };
    if (token) {
      headers['X-Vault-Token'] = token;
    }
    if (payload) {
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = Buffer.byteLength(payload);
    }

    const req = lib.request(
      u,
      {
        method,
        headers
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let parsed = text;
          try {
            parsed = JSON.parse(text);
          } catch (_) {}
          if (res.statusCode >= 400) {
            const errMsg =
              parsed && parsed.errors
                ? parsed.errors.join(', ')
                : `HTTP ${res.statusCode}: ${text}`;
            reject(new Error(errMsg));
            return;
          }
          resolve(parsed);
        });
      }
    );
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function main() {
  const args = process.argv.slice(2);
  const cmd = args[0] || 'status';
  const sub = args[1] || '';

  if (cmd === 'status') {
    const seal = await httpRequestJson('GET', '/v1/sys/seal-status');
    const st = await httpRequestJson('GET', '/api/v1/status');
    console.log(`=== Native Secrets Vault Status (${VAULT_ADDR}) ===`);
    console.log(`Cluster Name     : ${seal.cluster_name}`);
    console.log(`Initialized      : ${seal.initialized}`);
    console.log(`Sealed           : ${seal.sealed}`);
    console.log(`Shamir Threshold : ${seal.t} of ${seal.n} shares`);
    console.log(`Secret Paths     : ${st.secretPathsTotal} (${st.secretKeysTotal} keys across ${st.secretVersionsTotal} versions)`);
    console.log(`Audit Chain      : ${st.auditChainValid ? 'VERIFIED' : 'INVALID'} (${st.auditEntriesTotal} entries, head=${st.auditHeadHash.slice(0, 16)}...)`);
    return;
  }

  if (cmd === 'init') {
    let shares = 3;
    let threshold = 2;
    let saveFile = '';
    for (const a of args.slice(1)) {
      if (a.startsWith('--shares=')) shares = parseInt(a.split('=')[1], 10);
      if (a.startsWith('--threshold=')) threshold = parseInt(a.split('=')[1], 10);
      if (a.startsWith('--save-file=')) saveFile = a.split('=')[1];
    }
    const res = await httpRequestJson('POST', '/v1/sys/init', {
      secret_shares: shares,
      secret_threshold: threshold
    });
    if (saveFile) {
      fs.mkdirSync(path.dirname(path.resolve(saveFile)), { recursive: true });
      fs.writeFileSync(saveFile, JSON.stringify(res, null, 2), { encoding: 'utf8', mode: 0o600 });
      console.log(`✓ Saved unseal keys and root token to ${saveFile} (mode 0600)`);
    } else {
      console.log(JSON.stringify(res, null, 2));
    }
    return;
  }

  if (cmd === 'unseal') {
    const key = sub;
    if (!key) throw new Error('Usage: nsv unseal <share-key>');
    const res = await httpRequestJson('POST', '/v1/sys/unseal', { key });
    console.log(JSON.stringify(res, null, 2));
    return;
  }

  if (cmd === 'seal') {
    const token = resolveToken();
    const res = await httpRequestJson('POST', '/v1/sys/seal', {}, token);
    console.log(JSON.stringify(res, null, 2));
    return;
  }

  if (cmd === 'kv' && sub === 'put') {
    const targetPath = args[2];
    if (!targetPath) throw new Error('Usage: nsv kv put <path> KEY=VALUE ...');
    const token = resolveToken();
    let data = {};
    for (const arg of args.slice(3)) {
      if (arg.startsWith('--from-json=')) {
        const jsonFile = arg.split('=')[1];
        const parsed = JSON.parse(fs.readFileSync(jsonFile, 'utf8'));
        data = { ...data, ...(parsed.data || parsed) };
      } else if (arg.includes('=')) {
        const idx = arg.indexOf('=');
        const k = arg.slice(0, idx);
        const v = arg.slice(idx + 1);
        data[k] = v;
      }
    }
    const res = await httpRequestJson('POST', `/v1/secret/data/${targetPath}`, { data }, token);
    console.log(`✓ Wrote v${res.data.version} to secret/${targetPath} (${res.data.key_count} keys)`);
    return;
  }

  if (cmd === 'kv' && sub === 'get') {
    const targetPath = args[2];
    if (!targetPath) throw new Error('Usage: nsv kv get <path> [--field=KEY] [--format=json|dotenv]');
    const token = resolveToken();
    let field = '';
    let format = 'json';
    for (const arg of args.slice(3)) {
      if (arg.startsWith('--field=')) field = arg.split('=')[1];
      if (arg.startsWith('--format=')) format = arg.split('=')[1];
    }
    const res = await httpRequestJson('GET', `/v1/secret/data/${targetPath}`, null, token);
    const kv = res.data.data || {};
    if (field) {
      if (!Object.prototype.hasOwnProperty.call(kv, field)) {
        throw new Error(`Field "${field}" not found in secret/${targetPath}`);
      }
      process.stdout.write(String(kv[field]) + '\n');
      return;
    }
    if (format === 'dotenv') {
      for (const k of Object.keys(kv).sort()) {
        console.log(`${k}=${formatEnvValue(String(kv[k]))}`);
      }
      return;
    }
    console.log(JSON.stringify(res.data, null, 2));
    return;
  }

  if (cmd === 'kv' && sub === 'list') {
    const prefix = args[2] || '';
    const token = resolveToken();
    const res = await httpRequestJson(
      'GET',
      `/api/v1/paths${prefix ? `?prefix=${encodeURIComponent(prefix)}` : ''}`,
      null,
      token
    );
    for (const p of res.paths || []) {
      console.log(`  secret/${p.path.padEnd(26)} (v${p.currentVersion}, ${p.keyCount} keys, updated ${p.updatedTime})`);
    }
    return;
  }

  if (cmd === 'sync-env') {
    const envFilePath = args[1];
    if (!envFilePath) throw new Error('Usage: nsv sync-env <target-env-file> [--paths=cms/prod,...] [--dry-run] [--overwrite]');
    const token = resolveToken();
    let pathsParam = '';
    let dryRun = false;
    let overwriteExisting = false;
    for (const arg of args.slice(2)) {
      if (arg.startsWith('--paths=')) pathsParam = arg.split('=')[1];
      if (arg === '--dry-run') dryRun = true;
      if (arg === '--overwrite') overwriteExisting = true;
    }
    const endpoint = `/api/v1/export/json${pathsParam ? `?paths=${encodeURIComponent(pathsParam)}` : ''}`;
    const exported = await httpRequestJson('GET', endpoint, null, token);
    const res = syncVaultSecretsToEnvFile(path.resolve(envFilePath), exported.secrets || {}, {
      dryRun,
      overwriteExisting
    });
    console.log(`=== Lossless .env Sync (${dryRun ? 'DRY RUN' : 'APPLIED'}) ===`);
    console.log(`Target File    : ${path.resolve(envFilePath)}`);
    if (res.backupPath) console.log(`Backup Created : ${res.backupPath}`);
    console.log(`Added Keys     : ${res.addedKeys.length} (${res.addedKeys.join(', ') || 'none'})`);
    console.log(`Updated Keys   : ${res.updatedKeys.length} (${res.updatedKeys.join(', ') || 'none'})`);
    console.log(`Preserved Keys : ${res.preservedKeys.length}`);
    return;
  }

  if (cmd === 'audit' && sub === 'verify') {
    const res = await httpRequestJson('GET', '/api/v1/audit/verify');
    console.log(JSON.stringify(res, null, 2));
    if (!res.valid) process.exit(1);
    return;
  }

  if (cmd === 'snapshot' && sub === 'save') {
    const outFile = args[2];
    let passphrase = '';
    for (const arg of args.slice(3)) {
      if (arg.startsWith('--passphrase=')) passphrase = arg.split('=')[1];
    }
    if (!outFile || !passphrase) {
      throw new Error('Usage: nsv snapshot save <out-file.enc> --passphrase=<pass>');
    }
    const token = resolveToken();
    const res = await httpRequestJson('POST', '/api/v1/snapshot/export', { passphrase }, token);
    fs.writeFileSync(path.resolve(outFile), JSON.stringify(res, null, 2), { encoding: 'utf8', mode: 0o600 });
    console.log(`✓ Saved encrypted disaster-recovery snapshot to ${outFile}`);
    return;
  }

  console.log(`Usage: nsv <status|init|unseal|seal|kv|sync-env|audit|snapshot>`);
}

main().catch((err) => {
  console.error(`[nsv error]: ${err.message}`);
  process.exit(1);
});
