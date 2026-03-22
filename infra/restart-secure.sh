#!/usr/bin/env bash
# restart-secure.sh — secure restart for OpenClaw
#
# Flow:
#   1. Securely stop gateway and wipe volatile secrets
#   2. Securely start gateway and reload secrets
#
# Usage: ./infra/restart-secure.sh [start-secure args]
# Examples:
#   ./infra/restart-secure.sh
#   ./infra/restart-secure.sh --egress
#   ./infra/restart-secure.sh --net --egress

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "╔══════════════════════════════════════════════════════╗"
echo "║  OpenClaw — Secure Restart                          ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

echo "── [1/2] Running secure shutdown ──"
"${SCRIPT_DIR}/stop-secure.sh"
echo ""

echo "── [2/2] Running secure startup ──"
"${SCRIPT_DIR}/start-secure.sh" "$@"
