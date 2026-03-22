#!/usr/bin/env bash
set -euo pipefail

OPENCLAW_HOME="${OPENCLAW_HOME:-$HOME/.openclaw}"
POLICY_FILE="${OPENCLAW_HOME}/infra/exec-approvals-fallback.json"

usage() {
  cat <<'EOF'
Usage: ./infra/approvals-fallback.sh <apply|status|disable>

Commands:
  apply    Apply fallback allowlist+approval policy to local + gateway
  status   Show current approvals snapshot (gateway + local)
  disable  Set approvals security=deny (emergency lock-down)
EOF
}

if [[ $# -lt 1 ]]; then
  usage
  exit 2
fi

cmd="$1"

case "$cmd" in
  apply)
    if [[ ! -f "${POLICY_FILE}" ]]; then
      echo "ERROR: policy file not found: ${POLICY_FILE}" >&2
      exit 1
    fi
    echo "[approvals] applying local..."
    openclaw approvals set --file "${POLICY_FILE}"
    echo "[approvals] applying gateway..."
    openclaw approvals set --gateway --file "${POLICY_FILE}"
    echo "[approvals] done."
    ;;

  status)
    echo "[approvals] local:"
    openclaw approvals get
    echo
    echo "[approvals] gateway:"
    openclaw approvals get --gateway
    ;;

  disable)
    tmp="$(mktemp)"
    cat > "${tmp}" <<'JSON'
{
  "version": 1,
  "defaults": {
    "security": "deny",
    "ask": "off",
    "askFallback": "deny",
    "autoAllowSkills": false
  },
  "agents": {
    "*": {
      "security": "deny",
      "ask": "off",
      "askFallback": "deny",
      "autoAllowSkills": false,
      "allowlist": []
    }
  }
}
JSON
    echo "[approvals] setting DENY policy (local + gateway)..."
    openclaw approvals set --file "${tmp}"
    openclaw approvals set --gateway --file "${tmp}"
    rm -f "${tmp}"
    echo "[approvals] emergency deny policy active."
    ;;

  *)
    usage
    exit 2
    ;;
esac
