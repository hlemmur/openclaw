#!/usr/bin/env bash
# stop-secure.sh — secure shutdown for OpenClaw
#
# Flow:
#   1. Stop OpenClaw gateway
#   2. Destroy RAM disk (wipes decrypted secrets)
#   3. Disable egress filtering if active
#   4. Verify cleanup
#
# Usage: ./infra/stop-secure.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPENCLAW_HOME="$(dirname "$SCRIPT_DIR")"

export OPENCLAW_HOME

echo "╔══════════════════════════════════════════════════════╗"
echo "║  OpenClaw — Secure Shutdown                         ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ── Step 1: Stop OpenClaw ─────────────────────────────────────────────

echo "── [1/4] Stopping OpenClaw ──"
if pgrep -f "openclaw.*gateway" > /dev/null 2>&1; then
    openclaw gateway stop 2>/dev/null || pkill -f "openclaw.*gateway" || true
    sleep 2
    echo "  ✓ stopped"
else
    echo "  (not running)"
fi
echo ""

# ── Step 2: Destroy RAM disk ─────────────────────────────────────────

echo "── [2/4] Destroying secrets ramdisk ──"
"${SCRIPT_DIR}/vault/ramdisk.sh" destroy
echo ""

# ── Step 3: Disable egress ───────────────────────────────────────────

echo "── [3/4] Egress filtering ──"
if pfctl -s Anchors 2>/dev/null | grep -q openclaw; then
    echo "  removing pf rules (requires sudo)..."
    sudo "${SCRIPT_DIR}/egress/apply-egress.sh" disable
else
    echo "  (not active)"
fi
echo ""

# ── Step 4: Verify ───────────────────────────────────────────────────

echo "── [4/4] Verification ──"

CLEAN=true

if mount | grep -q "openclaw-secrets"; then
    echo "  WARNING: ramdisk still mounted!" >&2
    CLEAN=false
else
    echo "  ✓ ramdisk destroyed"
fi

if [ -f "/Volumes/openclaw-secrets/.env" ]; then
    echo "  WARNING: decrypted secrets still on disk!" >&2
    CLEAN=false
else
    echo "  ✓ no decrypted secrets on disk"
fi

if pgrep -f "openclaw.*gateway" > /dev/null 2>&1; then
    echo "  WARNING: openclaw process still running!" >&2
    CLEAN=false
else
    echo "  ✓ openclaw process stopped"
fi

echo ""
if [ "$CLEAN" = true ]; then
    echo "  ✓ clean shutdown — all secrets wiped from volatile memory"
else
    echo "  ✗ INCOMPLETE — check warnings above"
fi
