/**
 * dlp-output.js — PostToolUse / output DLP hook
 *
 * Scans agent output for leaked secrets before delivery to user channels.
 * Defense against: prompt injection causing the agent to echo secrets,
 * accidental secret inclusion in responses, exfiltration via tool output.
 *
 * This catches secrets that somehow made it past fs-guard and sandbox.
 */

'use strict';

const SECRET_PATTERNS = [
  { name: 'anthropic-api-key',   re: /sk-ant-[a-zA-Z0-9_-]{20,}/ },
  { name: 'openai-api-key',      re: /sk-[a-zA-Z0-9]{32,}/ },
  { name: 'google-api-key',      re: /AIzaSy[a-zA-Z0-9_-]{33}/ },
  { name: 'telegram-bot-token',  re: /[0-9]{8,10}:[A-Za-z0-9_-]{35}/ },
  { name: 'github-pat',          re: /ghp_[a-zA-Z0-9]{36}/ },
  { name: 'github-fine-grained', re: /github_pat_[a-zA-Z0-9_]{22,}/ },
  { name: 'aws-access-key',      re: /AKIA[0-9A-Z]{16}/ },
  { name: 'aws-secret-key',      re: /(?:aws_secret|secret_key)[\s=:]+[A-Za-z0-9/+=]{40}/ },
  { name: 'private-key-pem',     re: /-----BEGIN\s(?:RSA\s|EC\s|OPENSSH\s)?PRIVATE\sKEY-----/ },
  { name: 'bearer-token',        re: /Bearer\s+[A-Za-z0-9_-]{20,}/ },
  { name: 'basic-auth',          re: /Basic\s+[A-Za-z0-9+/=]{20,}/ },
  { name: 'age-secret-key',      re: /AGE-SECRET-KEY-[A-Z0-9]{59}/ },
  { name: 'sops-age-key',        re: /age1[a-z0-9]{58}/ },
  { name: 'generic-secret-assignment', re: /(?:password|secret|token|api_key|apikey|api-key)\s*[:=]\s*["']?[^\s"']{16,}/i },
];

const ENV_FILE_PATTERN = /^[A-Z_]+=\S+/m;

function scanForSecrets(text) {
  if (typeof text !== 'string' || text.length === 0) return null;

  for (const { name, re } of SECRET_PATTERNS) {
    if (re.test(text)) {
      return { pattern: name, match: text.match(re)[0].substring(0, 12) + '...' };
    }
  }

  const lines = text.split('\n');
  const envLikeLines = lines.filter(l => ENV_FILE_PATTERN.test(l));
  if (envLikeLines.length >= 2) {
    return { pattern: 'env-file-dump', match: '(multiple KEY=VALUE lines)' };
  }

  return null;
}

function redactSecrets(text) {
  let redacted = text;
  for (const { re } of SECRET_PATTERNS) {
    redacted = redacted.replace(new RegExp(re.source, re.flags + 'g'), '[REDACTED]');
  }
  return redacted;
}

module.exports = function dlpOutput({ tool, output, content, message }) {
  const text = output || content || message || '';

  const finding = scanForSecrets(text);
  if (finding) {
    return {
      allow: false,
      reason: `[dlp] BLOCKED: detected ${finding.pattern} in ${tool || 'output'} — ${finding.match}`,
      redacted: redactSecrets(text),
    };
  }

  return { allow: true };
};
