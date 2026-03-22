#!/usr/bin/env bash
# start-secure.sh — secure startup for OpenClaw
#
# Flow:
#   1. Create RAM disk for secrets
#   2. Decrypt .env.enc to RAM disk
#   3. Source secrets into environment
#   4. Start OpenClaw gateway
#   5. Start watchdog (if not already running via launchd)
#
# Usage: ./infra/start-secure.sh [--egress] [--net]
#   --egress   also enable pf egress filtering (requires sudo)
#   --net      allow network in exec sandbox (default: no network)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPENCLAW_HOME="$(dirname "$SCRIPT_DIR")"

export OPENCLAW_HOME
export OPENCLAW_WORKSPACE="${OPENCLAW_HOME}/workspace"

RAMDISK="/Volumes/openclaw-secrets"
ENABLE_EGRESS=false
EXEC_NET="no"

for arg in "$@"; do
    case "$arg" in
        --egress) ENABLE_EGRESS=true ;;
        --net)    EXEC_NET="yes" ;;
    esac
done

export OPENCLAW_EXEC_NET="$EXEC_NET"

echo "╔══════════════════════════════════════════════════════╗"
echo "║  OpenClaw — Secure Start                            ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ── Step 1: RAM disk ──────────────────────────────────────────────────

echo "── [1/5] Creating secrets ramdisk ──"
"${SCRIPT_DIR}/vault/ramdisk.sh" create
echo ""

# ── Step 2: Decrypt secrets ───────────────────────────────────────────

echo "── [2/5] Decrypting secrets to ramdisk ──"
"${SCRIPT_DIR}/vault/encrypt-env.sh" decrypt
echo ""

# ── Step 3: Source secrets ────────────────────────────────────────────

echo "── [3/5] Loading secrets into environment ──"
if [ -f "${RAMDISK}/.env" ]; then
    set -a
    source "${RAMDISK}/.env"
    set +a
    echo "  ✓ secrets loaded (${RAMDISK}/.env)"
else
    echo "  ERROR: decrypted secrets not found at ${RAMDISK}/.env" >&2
    exit 1
fi
echo ""

# ── Step 4: Egress filtering (optional) ──────────────────────────────

if [ "$ENABLE_EGRESS" = true ]; then
    echo "── [4/5] Enabling egress filtering ──"
    sudo "${SCRIPT_DIR}/egress/apply-egress.sh" enable
else
    echo "── [4/5] Egress filtering: skipped (use --egress to enable) ──"
fi
echo ""

# ── Step 5: Start OpenClaw ────────────────────────────────────────────

echo "── [5/5] Starting OpenClaw gateway ──"

if pgrep -f "openclaw.*gateway" > /dev/null 2>&1; then
    echo "  OpenClaw gateway is already running; skipping start."
    echo "  use './infra/stop-secure.sh' before starting again."
    openclaw gateway status 2>/dev/null || true
    exit 0
fi

CONFIG_FILE="${OPENCLAW_HOME}/openclaw.json"
if [ -f "${CONFIG_FILE}" ]; then
    SANDBOX_MODE="$(python3 -c 'import json,sys; c=json.load(open(sys.argv[1])); print(c.get("agents",{}).get("defaults",{}).get("sandbox",{}).get("mode","off"))' "${CONFIG_FILE}" 2>/dev/null || echo "off")"
    HOOKS_INTERNAL="$(python3 -c 'import json,sys; c=json.load(open(sys.argv[1])); print(str(c.get("hooks",{}).get("internal",{}).get("enabled",False)).lower())' "${CONFIG_FILE}" 2>/dev/null || echo "false")"
    SECRETS_PROVIDER="$(python3 -c 'import json,sys; c=json.load(open(sys.argv[1])); print(c.get("secrets",{}).get("providers",{}).get("sops",{}).get("source","not-configured"))' "${CONFIG_FILE}" 2>/dev/null || echo "not-configured")"
else
    SANDBOX_MODE="off"
    HOOKS_INTERNAL="false"
    SECRETS_PROVIDER="not-configured"
fi

echo "  exec sandbox: $([ "$EXEC_NET" = "yes" ] && echo "network allowed" || echo "no network")"
echo "  secrets: ramdisk (volatile RAM)"
echo "  openclaw sandbox mode: ${SANDBOX_MODE}"
echo "  hooks.internal enabled: ${HOOKS_INTERNAL}"
echo "  secrets provider (sops): ${SECRETS_PROVIDER}"
WATCHDOG_TARGET="gui/$(id -u)/com.oc.config-watchdog"
if launchctl print "${WATCHDOG_TARGET}" 2>/dev/null | grep -q "state = running"; then
    WATCHDOG_STATUS="active (launchd)"
elif launchctl print "${WATCHDOG_TARGET}" >/dev/null 2>&1; then
    WATCHDOG_STATUS="loaded (not running)"
else
    WATCHDOG_STATUS="inactive"
fi
echo "  watchdog: ${WATCHDOG_STATUS}"
echo ""

# Service-mode only: bootstrap launchd service and wait for runtime readiness.
SERVICE_LABEL="ai.openclaw.gateway"
SERVICE_PLIST="${HOME}/Library/LaunchAgents/${SERVICE_LABEL}.plist"
LAUNCHD_TARGET="gui/$(id -u)/${SERVICE_LABEL}"

if [ ! -f "${SERVICE_PLIST}" ]; then
    echo "  gateway service plist not found: ${SERVICE_PLIST}"
    echo "  run once: openclaw gateway install"
    exit 1
fi

# Start via OpenClaw CLI first (works when service already loaded).
START_OUTPUT="$(openclaw gateway start 2>&1 || true)"

# If still not loaded, bootstrap launchd manually.
if ! launchctl list | grep -q "${SERVICE_LABEL}"; then
    echo "  launchd service not loaded; bootstrapping..."
    launchctl bootstrap "gui/$(id -u)" "${SERVICE_PLIST}" 2>/dev/null || true
fi

# Force restart/start of the launchd job.
launchctl kickstart -k "${LAUNCHD_TARGET}" 2>/dev/null || true

# Wait for gateway runtime readiness.
for i in 1 2 3 4 5 6 7 8 9 10; do
    if openclaw gateway status 2>&1 | grep -q "Runtime: running"; then
        echo "  gateway runtime is running."
        exit 0
    fi
    sleep 1
done

echo "  ERROR: gateway did not reach running state."
echo "${START_OUTPUT}"
echo "  check: openclaw gateway status"
echo "  if needed: launchctl print ${LAUNCHD_TARGET}"
exit 1
