#!/usr/bin/env node
/**
 * sops-resolver.js — OpenClaw exec secrets provider
 *
 * Implements the OpenClaw exec provider protocol (protocolVersion: 1).
 * Decrypts .env.enc via SOPS+age and returns requested secret values.
 *
 * Configured in openclaw.json under secrets.providers.sops
 */

const { execFileSync } = require('child_process');
const path = require('path');
const os = require('os');

const OPENCLAW_HOME = process.env.OPENCLAW_HOME
  || path.join(os.homedir(), '.openclaw');
const ENCRYPTED = path.join(OPENCLAW_HOME, '.env.enc');

const AGE_KEY_LOCATIONS = [
  path.join(os.homedir(), 'Library', 'Application Support', 'sops', 'age', 'keys.txt'),
  path.join(os.homedir(), '.config', 'sops', 'age', 'keys.txt'),
];

function findAgeKey() {
  const fs = require('fs');
  for (const loc of AGE_KEY_LOCATIONS) {
    if (fs.existsSync(loc)) return loc;
  }
  return AGE_KEY_LOCATIONS[0];
}

function decryptEnv() {
  const env = {
    ...process.env,
    SOPS_AGE_KEY_FILE: findAgeKey(),
  };

  const stdout = execFileSync('/usr/local/bin/sops', [
    '--decrypt',
    '--input-type', 'dotenv',
    '--output-type', 'dotenv',
    ENCRYPTED,
  ], { env, encoding: 'utf8', timeout: 10000 });

  const result = {};
  for (const line of stdout.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const idx = trimmed.indexOf('=');
    if (idx > 0) {
      result[trimmed.substring(0, idx)] = trimmed.substring(idx + 1);
    }
  }
  return result;
}

function handleRequest(request) {
  const ids = request.ids || [];
  const secrets = decryptEnv();

  const values = {};
  const errors = {};
  for (const id of ids) {
    if (id in secrets) {
      values[id] = secrets[id];
    } else {
      errors[id] = { message: `key "${id}" not found in ${ENCRYPTED}` };
    }
  }

  const response = { protocolVersion: 1, values };
  if (Object.keys(errors).length > 0) response.errors = errors;
  process.stdout.write(JSON.stringify(response));
}

let input = '';
let responded = false;

process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => {
  input += chunk;
  if (responded) return;
  try {
    const request = JSON.parse(input);
    handleRequest(request);
    responded = true;
  } catch {
    // Wait for more chunks if JSON is incomplete.
  }
});

process.stdin.on('end', () => {
  if (responded) return;
  try {
    const request = JSON.parse(input);
    handleRequest(request);
  } catch (err) {
    process.stderr.write(`sops-resolver error: ${err.message}\n`);
    process.exit(1);
  }
});
