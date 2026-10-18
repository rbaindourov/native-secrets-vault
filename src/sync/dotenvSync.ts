/**
 * src/sync/dotenvSync.ts
 * ──────────────────────────────────────────────────────────────────────────────
 * Lossless `.env` Synchronization Engine enforcing the Zero Secret Loss Invariant:
 *   1. Never deletes existing keys, comments, or blank lines in `.env`.
 *   2. Never overwrites a non-empty existing value with an empty/whitespace value.
 *   3. Preserves existing non-empty values by default unless `overwriteExisting: true`
 *      is explicitly passed.
 *   4. Creates a timestamped `.bak-<ISO>` backup before modifying any `.env` file.
 */

import fs from 'fs';

export interface ParsedEnvLine {
  type: 'blank' | 'comment' | 'pair';
  raw: string;
  key?: string;
  value?: string;
  exportPrefix?: string;
  inlineComment?: string;
}

export interface ParsedEnv {
  entries: Record<string, string>;
  lines: ParsedEnvLine[];
}

export interface MergeResult {
  mergedContent: string;
  mergedEntries: Record<string, string>;
  addedKeys: string[];
  updatedKeys: string[];
  preservedKeys: string[];
  skippedEmptyIncomingKeys: string[];
}

export function parseRawEnvValue(rawValue: string): {
  value: string;
  quoteChar: string | null;
  inlineComment: string;
} {
  const trimmed = rawValue.trim();
  if (!trimmed) {
    return { value: '', quoteChar: null, inlineComment: '' };
  }

  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"') && trimmed.length >= 2) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'") && trimmed.length >= 2)
  ) {
    const quoteChar = trimmed[0];
    const inner = trimmed.slice(1, -1);
    const unescaped =
      quoteChar === '"'
        ? inner.replace(/\\"/g, '"').replace(/\\n/g, '\n')
        : inner;
    return { value: unescaped, quoteChar, inlineComment: '' };
  }

  const commentMatch = rawValue.match(/^([^#]*?)\s+(#.*)$/);
  if (commentMatch) {
    return {
      value: commentMatch[1].trim(),
      quoteChar: null,
      inlineComment: commentMatch[2]
    };
  }

  return { value: trimmed, quoteChar: null, inlineComment: '' };
}

export function formatEnvValue(value: string): string {
  const str = String(value ?? '');
  if (str === '') return '';
  if (/[\s#"'\r\n]/.test(str)) {
    const escaped = str
      .replace(/\\/g, '\\\\')
      .replace(/"/g, '\\"')
      .replace(/\n/g, '\\n');
    return `"${escaped}"`;
  }
  return str;
}

export function parseEnvContent(content: string): ParsedEnv {
  const safeContent = typeof content === 'string' ? content : '';
  const entries: Record<string, string> = {};
  const lines: ParsedEnvLine[] = [];

  if (safeContent.length === 0) {
    return { entries, lines };
  }

  const rawLines = safeContent.replace(/\r\n/g, '\n').split('\n');
  const hasTrailingNewline = safeContent.endsWith('\n');
  const effectiveLines = hasTrailingNewline ? rawLines.slice(0, -1) : rawLines;

  for (const rawLine of effectiveLines) {
    const trimmed = rawLine.trim();
    if (trimmed === '') {
      lines.push({ type: 'blank', raw: rawLine });
      continue;
    }
    if (trimmed.startsWith('#')) {
      lines.push({ type: 'comment', raw: rawLine });
      continue;
    }

    const match = rawLine.match(/^(\s*(?:export\s+)?)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (!match) {
      lines.push({ type: 'comment', raw: rawLine });
      continue;
    }

    const exportPrefix = match[1] || '';
    const key = match[2];
    const rawVal = match[3] || '';
    const { value, inlineComment } = parseRawEnvValue(rawVal);

    entries[key] = value;
    lines.push({
      type: 'pair',
      raw: rawLine,
      key,
      value,
      exportPrefix,
      inlineComment
    });
  }

  return { entries, lines };
}

export function mergeEnvLossless(
  existingContent: string,
  incomingSecrets: Record<string, unknown>,
  options: { overwriteExisting?: boolean } = {}
): MergeResult {
  const overwriteExisting = Boolean(options.overwriteExisting);
  const parsed = parseEnvContent(existingContent);
  const mergedEntries: Record<string, string> = { ...parsed.entries };

  const addedKeys: string[] = [];
  const updatedKeys: string[] = [];
  const preservedKeys: string[] = [];
  const skippedEmptyIncomingKeys: string[] = [];

  const handledIncomingKeys = new Set<string>();
  const outputLines: string[] = [];

  for (const line of parsed.lines) {
    if (line.type !== 'pair' || !line.key) {
      outputLines.push(line.raw);
      continue;
    }

    const key = line.key;
    const currentVal = line.value ?? '';

    if (!Object.prototype.hasOwnProperty.call(incomingSecrets, key)) {
      preservedKeys.push(key);
      outputLines.push(line.raw);
      continue;
    }

    handledIncomingKeys.add(key);
    const rawIncoming = incomingSecrets[key];
    const incomingStr =
      rawIncoming === null || rawIncoming === undefined
        ? ''
        : String(rawIncoming);

    if (incomingStr.trim() === '') {
      if (currentVal.trim() !== '') {
        skippedEmptyIncomingKeys.push(key);
        preservedKeys.push(key);
      }
      outputLines.push(line.raw);
      continue;
    }

    if (currentVal.trim() !== '' && !overwriteExisting) {
      preservedKeys.push(key);
      outputLines.push(line.raw);
      continue;
    }

    if (currentVal === incomingStr) {
      preservedKeys.push(key);
      outputLines.push(line.raw);
      continue;
    }

    updatedKeys.push(key);
    mergedEntries[key] = incomingStr;
    const commentSuffix = line.inlineComment ? ` ${line.inlineComment}` : '';
    outputLines.push(
      `${line.exportPrefix || ''}${key}=${formatEnvValue(incomingStr)}${commentSuffix}`
    );
  }

  for (const [key, rawVal] of Object.entries(incomingSecrets)) {
    if (handledIncomingKeys.has(key)) continue;
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;

    const incomingStr =
      rawVal === null || rawVal === undefined ? '' : String(rawVal);
    if (incomingStr.trim() === '') {
      skippedEmptyIncomingKeys.push(key);
      continue;
    }

    addedKeys.push(key);
    mergedEntries[key] = incomingStr;
    outputLines.push(`${key}=${formatEnvValue(incomingStr)}`);
  }

  const mergedContent =
    outputLines.length > 0 ? outputLines.join('\n') + '\n' : '';

  return {
    mergedContent,
    mergedEntries,
    addedKeys,
    updatedKeys,
    preservedKeys,
    skippedEmptyIncomingKeys
  };
}

export function syncVaultSecretsToEnvFile(
  envFilePath: string,
  incomingSecrets: Record<string, unknown>,
  options: { overwriteExisting?: boolean; dryRun?: boolean } = {}
): MergeResult & { backupPath: string | null } {
  const exists = fs.existsSync(envFilePath);
  const existingContent = exists ? fs.readFileSync(envFilePath, 'utf8') : '';
  const result = mergeEnvLossless(existingContent, incomingSecrets, {
    overwriteExisting: options.overwriteExisting
  });

  let backupPath: string | null = null;
  if (!options.dryRun) {
    if (exists) {
      const stamp = new Date().toISOString().replace(/[:.]/g, '-');
      backupPath = `${envFilePath}.bak-${stamp}`;
      fs.copyFileSync(envFilePath, backupPath);
      fs.chmodSync(backupPath, 0o600);
    }
    fs.writeFileSync(envFilePath, result.mergedContent, {
      encoding: 'utf8',
      mode: 0o600
    });
  }

  return { ...result, backupPath };
}
