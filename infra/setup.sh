#!/usr/bin/env bash
# setup.sh — one-time setup for OpenClaw security hardening
#
# What it does:
#   1. Installs dependencies (sops, age, fswatch) via Homebrew
#   2. Generates age encryption key pair
#   3. Encrypts .env secrets (shreds plaintext)
#   4. Makes scripts executable
#   5. Initializes watchdog baselines
#   6. Installs log rotation config
#   7. Prints activation checklist
#
# Run once. Then use start-secure.sh / stop-secure.sh for daily operation.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPENCLAW_HOME="$(dirname "$SCRIPT_DIR")"

export OPENCLAW_HOME

echo "╔══════════════════════════════════════════════════════╗"
echo "║  OpenClaw Security Hardening — Setup                ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "OPENCLAW_HOME: $OPENCLAW_HOME"
echo ""

# ── Step 1: Dependencies ──────────────────────────────────────────────

echo "── [1/7] Installing dependencies ──"

if ! command -v brew &>/dev/null; then
    echo "ERROR: Homebrew not found. Install from https://brew.sh" >&2
    exit 1
fi

DEPS=(sops age fswatch)
for dep in "${DEPS[@]}"; do
    if command -v "$dep" &>/dev/null; then
        echo "  ✓ $dep (already installed)"
    else
        echo "  installing $dep..."
        brew install "$dep"
    fi
done

# Verify
for dep in "${DEPS[@]}"; do
    if ! command -v "$dep" &>/dev/null; then
        echo "ERROR: $dep not found after install" >&2
        exit 1
    fi
done
echo ""

# ── Step 2: Age key ──────────────────────────────────────────────────

echo "── [2/7] Age encryption key ──"
"${SCRIPT_DIR}/vault/encrypt-env.sh" 2>&1 | grep '\[vault\]' || true
# encrypt-env.sh handles key generation + encryption + shredding
echo ""

# Note: if .env is already encrypted (re-running setup), encrypt-env.sh
# will error because .env doesn't exist. That's fine.
if [ -f "${OPENCLAW_HOME}/.env" ]; then
    "${SCRIPT_DIR}/vault/encrypt-env.sh"
elif [ -f "${OPENCLAW_HOME}/.env.enc" ]; then
    echo "  ✓ .env already encrypted"
else
    echo "  WARNING: no .env or .env.enc found"
fi
echo ""

# ── Step 3: Make scripts executable ───────────────────────────────────

echo "── [3/7] Setting permissions ──"
chmod +x "${SCRIPT_DIR}/sandbox/exec-wrapper.sh"
chmod +x "${SCRIPT_DIR}/vault/ramdisk.sh"
chmod +x "${SCRIPT_DIR}/vault/encrypt-env.sh"
chmod +x "${SCRIPT_DIR}/watchdog/config-watchdog.sh"
chmod +x "${SCRIPT_DIR}/egress/apply-egress.sh"
chmod +x "${SCRIPT_DIR}/start-secure.sh" 2>/dev/null || true
chmod +x "${SCRIPT_DIR}/stop-secure.sh" 2>/dev/null || true
chmod +x "${SCRIPT_DIR}/restart-secure.sh" 2>/dev/null || true
chmod +x "${SCRIPT_DIR}/ops/restart-webhook.py" 2>/dev/null || true
chmod +x "${SCRIPT_DIR}/ops/telegram-webhook.sh" 2>/dev/null || true
chmod +x "${SCRIPT_DIR}/ops/run-restart-webhook.sh" 2>/dev/null || true
chmod +x "${SCRIPT_DIR}/ops/install-restart-webhook-launchd.sh" 2>/dev/null || true
echo "  ✓ all scripts executable"
echo ""

# ── Step 4: Initialize watchdog baselines ─────────────────────────────

echo "── [4/7] Initializing watchdog baselines ──"
"${SCRIPT_DIR}/watchdog/config-watchdog.sh" init
echo ""

# ── Step 5: Log rotation ─────────────────────────────────────────────

echo "── [5/7] Log rotation ──"
NEWSYSLOG_CONF="/etc/newsyslog.d/openclaw.conf"
if [ -f "$NEWSYSLOG_CONF" ]; then
    echo "  ✓ newsyslog config already installed"
else
    echo "  installing newsyslog config (requires sudo)..."
    sudo mkdir -p /etc/newsyslog.d
    sudo cp "${SCRIPT_DIR}/logrotate/openclaw-newsyslog.conf" "$NEWSYSLOG_CONF"
    echo "  ✓ installed"
fi
echo ""

# ── Step 6: Watchdog launchd service ──────────────────────────────────

echo "── [6/7] Watchdog service ──"
PLIST_SRC="${SCRIPT_DIR}/watchdog/com.openclaw.config-watchdog.plist"
PLIST_DST="${HOME}/Library/LaunchAgents/com.oc.config-watchdog.plist"
mkdir -p "${HOME}/Library/LaunchAgents"
if [ -f "$PLIST_DST" ]; then
    launchctl unload "$PLIST_DST" 2>/dev/null || true
fi
cp "$PLIST_SRC" "$PLIST_DST"
launchctl load "$PLIST_DST"
echo "  ✓ watchdog service installed and started"
echo ""

# ── Step 7: Summary ──────────────────────────────────────────────────

echo "── [7/7] Setup complete ──"
echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  ACTIVATION CHECKLIST                               ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║                                                     ║"
echo "║  1. Update openclaw.json with hook config           ║"
echo "║     (see infra/README.md for exact JSON)            ║"
echo "║                                                     ║"
echo "║  2. Start with secure wrapper:                      ║"
echo "║     ./infra/start-secure.sh                         ║"
echo "║                                                     ║"
echo "║  3. (Optional) Enable egress filtering:             ║"
echo "║     sudo ./infra/egress/apply-egress.sh enable      ║"
echo "║                                                     ║"
echo "║  4. ROTATE ALL API KEYS — they were in plaintext!   ║"
echo "║     - Anthropic: console.anthropic.com              ║"
echo "║     - Telegram: @BotFather                          ║"
echo "║     - Gemini: console.cloud.google.com              ║"
echo "║                                                     ║"
echo "║  5. After rotating, re-encrypt:                     ║"
echo "║     echo "NEW_KEYS" > .env                          ║"
echo "║     ./infra/vault/encrypt-env.sh                    ║"
echo "║                                                     ║"
echo "╚══════════════════════════════════════════════════════╝"
