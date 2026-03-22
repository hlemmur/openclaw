#!/usr/bin/env bash
set -euo pipefail

OPENCLAW_HOME="${OPENCLAW_HOME:-$HOME/.openclaw}"
CONFIG="${OPENCLAW_HOME}/openclaw.json"

usage() {
  cat <<'EOF'
Usage: ./infra/sandbox-main-switch.sh <on|off|status> [--restart]

Modes:
  on      sandbox main too    -> agents.defaults.sandbox.mode = "all"
  off     keep main on host   -> agents.defaults.sandbox.mode = "non-main"
  status  print current mode

Options:
  --restart  restart gateway after applying change
EOF
}

if [[ $# -lt 1 ]]; then
  usage
  exit 2
fi

ACTION="$1"
RESTART=0
if [[ "${2:-}" == "--restart" || "${1:-}" == "--restart" ]]; then
  RESTART=1
fi

if [[ "${ACTION}" == "--restart" ]]; then
  usage
  exit 2
fi

if [[ ! -f "${CONFIG}" ]]; then
  echo "ERROR: config not found: ${CONFIG}" >&2
  exit 1
fi

current_mode() {
  python3 - "${CONFIG}" <<'PY'
import json,sys
c=json.load(open(sys.argv[1]))
print(c.get("agents",{}).get("defaults",{}).get("sandbox",{}).get("mode","off"))
PY
}

set_mode() {
  local mode="$1"
  python3 - "${CONFIG}" "${mode}" <<'PY'
import json,sys
p=sys.argv[1]
mode=sys.argv[2]
c=json.load(open(p))
c.setdefault("agents",{}).setdefault("defaults",{}).setdefault("sandbox",{})["mode"]=mode
with open(p,"w") as f:
    json.dump(c,f,indent=2)
    f.write("\n")
print(mode)
PY
}

case "${ACTION}" in
  status)
    echo "sandbox.mode=$(current_mode)"
    exit 0
    ;;
  on)
    new_mode="all"
    ;;
  off)
    new_mode="non-main"
    ;;
  *)
    usage
    exit 2
    ;;
esac

old_mode="$(current_mode)"
applied="$(set_mode "${new_mode}")"
echo "sandbox.mode: ${old_mode} -> ${applied}"

if ! openclaw config validate >/dev/null 2>&1; then
  echo "ERROR: config became invalid after change." >&2
  exit 1
fi

if [[ "${RESTART}" -eq 1 ]]; then
  echo "Restarting gateway..."
  openclaw gateway restart >/dev/null 2>&1 || true
  sleep 2
  /Users/leka/.openclaw/infra/status-clean.sh || true
else
  echo "Change applied. Restart gateway to take effect:"
  echo "  ./infra/stop-secure.sh && ./infra/start-secure.sh"
fi
