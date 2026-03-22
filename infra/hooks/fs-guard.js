/**
 * fs-guard.js — PreToolUse hook
 *
 * Enforces filesystem boundary: agent tools can only access workspace.
 * Defense against: path traversal, config tampering, secret exfiltration via
 * read/edit/write/glob/grep tools.
 *
 * This is a SECOND line of defense. The sandbox-exec profile is the first.
 * Both must be bypassed for an attack to succeed.
 */

'use strict';

const path = require('path');

const OPENCLAW_HOME = process.env.OPENCLAW_HOME
  || path.resolve(__dirname, '..', '..');

const WORKSPACE = process.env.OPENCLAW_WORKSPACE
  || path.join(OPENCLAW_HOME, 'workspace');

const ALLOWED_ROOTS = [
  path.resolve(WORKSPACE),
];

const DENIED_LITERALS = [
  path.resolve(OPENCLAW_HOME, '.env'),
  path.resolve(OPENCLAW_HOME, '.env.enc'),
  path.resolve(OPENCLAW_HOME, 'openclaw.json'),
  path.resolve(OPENCLAW_HOME, 'openclaw.json.bak'),
  path.resolve(OPENCLAW_HOME, 'openclaw.json.bak.1'),
];

const DENIED_SUBTREES = [
  path.resolve(OPENCLAW_HOME, 'identity'),
  path.resolve(OPENCLAW_HOME, 'devices'),
  path.resolve(OPENCLAW_HOME, 'infra'),
  path.resolve(OPENCLAW_HOME, 'logs'),
  '/Volumes/openclaw-secrets',
  path.join(process.env.HOME || '/Users/leka', '.ssh'),
  path.join(process.env.HOME || '/Users/leka', '.gnupg'),
  path.join(process.env.HOME || '/Users/leka', '.aws'),
  path.join(process.env.HOME || '/Users/leka', '.config', 'sops'),
  '/etc',
  '/private/etc',
];

const GUARDED_TOOLS = new Set([
  'read', 'edit', 'write', 'glob', 'grep',
  'file.read', 'file.edit', 'file.write',
  'file.glob', 'file.grep',
  'fs.read', 'fs.write', 'fs.edit',
]);

function extractPaths(args) {
  if (!args || typeof args !== 'object') return [];
  const candidates = [];
  for (const key of ['path', 'target', 'directory', 'glob_root', 'file', 'filePath', 'targetPath']) {
    if (typeof args[key] === 'string') candidates.push(args[key]);
  }
  if (Array.isArray(args.paths)) {
    for (const p of args.paths) {
      if (typeof p === 'string') candidates.push(p);
    }
  }
  return candidates;
}

function isUnderAny(resolved, prefixes) {
  return prefixes.some(prefix =>
    resolved === prefix || resolved.startsWith(prefix + path.sep)
  );
}

module.exports = function fsGuard({ tool, args }) {
  if (!GUARDED_TOOLS.has(tool)) return { allow: true };

  const paths = extractPaths(args);
  if (paths.length === 0) return { allow: true };

  for (const raw of paths) {
    const resolved = path.resolve(raw);

    if (DENIED_LITERALS.includes(resolved)) {
      return {
        allow: false,
        reason: `[fs-guard] BLOCKED: ${tool} tried to access restricted file: ${resolved}`,
      };
    }

    if (isUnderAny(resolved, DENIED_SUBTREES)) {
      return {
        allow: false,
        reason: `[fs-guard] BLOCKED: ${tool} tried to access restricted subtree: ${resolved}`,
      };
    }

    if (!isUnderAny(resolved, ALLOWED_ROOTS)) {
      return {
        allow: false,
        reason: `[fs-guard] BLOCKED: ${tool} path outside workspace: ${resolved}`,
      };
    }
  }

  return { allow: true };
};
