#!/usr/bin/env bash
set -euo pipefail

OPENCLAW_HOME="${OPENCLAW_HOME:-$HOME/.openclaw}"
FAILS=0
WARNS=0
STRICT=0

usage() {
  cat <<'EOF'
Usage: ./infra/security-smoke-test.sh [--strict]

Options:
  --strict   Treat WARN as FAIL (non-zero exit if any warnings)
  -h, --help Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --strict)
      STRICT=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 2
      ;;
  esac
done

pass() { printf "PASS  %-32s %s\n" "$1" "${2:-}"; }
warn() { printf "WARN  %-32s %s\n" "$1" "${2:-}"; WARNS=$((WARNS+1)); }
fail() { printf "FAIL  %-32s %s\n" "$1" "${2:-}"; FAILS=$((FAILS+1)); }

section() {
  echo
  echo "== $1 =="
}

json_get() {
  python3 - "$1" "$2" <<'PY'
import json,sys
doc=json.loads(sys.argv[1])
path=sys.argv[2].split(".")
cur=doc
for p in path:
    if not p:
        continue
    if isinstance(cur, dict) and p in cur:
        cur=cur[p]
    else:
        print("")
        sys.exit(0)
if isinstance(cur, bool):
    print("true" if cur else "false")
else:
    print(cur)
PY
}

section "Gateway Runtime"
GW_JSON="$(openclaw gateway status --json 2>/dev/null || true)"
if [[ -z "${GW_JSON}" ]]; then
  fail "gateway.status.json" "no JSON output"
else
  loaded="$(json_get "${GW_JSON}" "service.loaded")"
  runtime="$(json_get "${GW_JSON}" "service.runtime.status")"
  rpc_ok="$(json_get "${GW_JSON}" "rpc.ok")"
  bind_mode="$(json_get "${GW_JSON}" "gateway.bindMode")"
  bind_host="$(json_get "${GW_JSON}" "gateway.bindHost")"
  port="$(json_get "${GW_JSON}" "gateway.port")"

  [[ "${loaded}" == "true" ]] && pass "gateway.service.loaded" "" || fail "gateway.service.loaded" "loaded=${loaded}"
  [[ "${runtime}" == "running" ]] && pass "gateway.runtime" "running" || fail "gateway.runtime" "status=${runtime}"
  [[ "${rpc_ok}" == "true" ]] && pass "gateway.rpc" "ok" || fail "gateway.rpc" "rpc_ok=${rpc_ok}"
  [[ "${bind_mode}" == "loopback" ]] && pass "gateway.bind" "${bind_mode} (${bind_host}:${port})" || warn "gateway.bind" "${bind_mode} (${bind_host}:${port})"
fi

section "Watchdog"
if launchctl print "gui/$(id -u)/com.oc.config-watchdog" 2>/dev/null | grep -q "state = running"; then
  pass "watchdog.launchd" "running"
else
  fail "watchdog.launchd" "not running"
fi

section "Secrets At Rest"
if [[ -f "${OPENCLAW_HOME}/.env" ]]; then
  fail "secrets.plaintext.env" "${OPENCLAW_HOME}/.env exists"
else
  pass "secrets.plaintext.env" "absent"
fi

if [[ -f "${OPENCLAW_HOME}/.env.enc" ]]; then
  pass "secrets.encrypted.env" "present"
else
  fail "secrets.encrypted.env" "missing ${OPENCLAW_HOME}/.env.enc"
fi

section "Secrets Runtime"
if openclaw secrets reload >/dev/null 2>&1; then
  pass "secrets.reload" "ok"
else
  fail "secrets.reload" "failed"
fi

AUDIT_OUT="$(openclaw secrets audit 2>&1 || true)"
if echo "${AUDIT_OUT}" | grep -q "plaintext=0, unresolved=0"; then
  pass "secrets.audit" "clean"
else
  # Known edge: CLI command path may report unresolved exec:sops timeout
  # while runtime actively resolves gateway.auth.token.
  if echo "${AUDIT_OUT}" | grep -q "Exec provider \"sops\" produced no output for 5000ms"; then
    if grep -q "SECRETS_GATEWAY_AUTH_SURFACE.*gateway.auth.token is active" "${OPENCLAW_HOME}/logs/gateway.log" 2>/dev/null; then
      warn "secrets.audit" "CLI-path unresolved (exec timeout), runtime surface is active"
    else
      fail "secrets.audit" "unresolved refs and no runtime confirmation"
    fi
  else
    fail "secrets.audit" "$(echo "${AUDIT_OUT}" | tr '\n' ' ' | cut -c1-180)"
  fi
fi

section "Model Stack"
MAIN_JSON="$(openclaw models status --json 2>/dev/null || true)"
WORKER_JSON="$(openclaw models status --agent worker --json 2>/dev/null || true)"

if [[ -n "${MAIN_JSON}" ]]; then
  main_model="$(json_get "${MAIN_JSON}" "defaultModel")"
  main_fallbacks="$(json_get "${MAIN_JSON}" "fallbacks")"
  [[ "${main_model}" == "anthropic/claude-opus-4-6" ]] && pass "main.primary" "${main_model}" || warn "main.primary" "${main_model}"
  echo "${main_fallbacks}" | grep -q "anthropic/claude-sonnet-4-6" && pass "main.fallback" "sonnet" || warn "main.fallback" "${main_fallbacks}"
else
  fail "main.model.status" "no output"
fi

if [[ -n "${WORKER_JSON}" ]]; then
  worker_model="$(json_get "${WORKER_JSON}" "defaultModel")"
  worker_fallbacks="$(json_get "${WORKER_JSON}" "fallbacks")"
  missing_providers="$(json_get "${WORKER_JSON}" "auth.missingProvidersInUse")"
  [[ "${worker_model}" == "openai-codex/gpt-5.4" ]] && pass "worker.primary" "${worker_model}" || warn "worker.primary" "${worker_model}"
  echo "${worker_fallbacks}" | grep -q "anthropic/claude-sonnet-4-6" && pass "worker.fallback" "sonnet" || warn "worker.fallback" "${worker_fallbacks}"
  [[ "${missing_providers}" == "[]" ]] && pass "worker.auth" "providers present" || warn "worker.auth" "missing=${missing_providers}"
else
  fail "worker.model.status" "no output"
fi

section "Sandbox and Egress"
if [[ -f "${OPENCLAW_HOME}/openclaw.json" ]]; then
  sb_mode="$(python3 - "${OPENCLAW_HOME}/openclaw.json" <<'PY'
import json,sys
c=json.load(open(sys.argv[1]))
print(c.get("agents",{}).get("defaults",{}).get("sandbox",{}).get("mode","off"))
PY
)"
  [[ "${sb_mode}" == "non-main" || "${sb_mode}" == "all" ]] && pass "sandbox.mode" "${sb_mode}" || warn "sandbox.mode" "${sb_mode}"
else
  fail "sandbox.mode" "openclaw.json missing"
fi

if pfctl -s Anchors 2>/dev/null | grep -qi "openclaw"; then
  pass "egress.pf.anchor" "active"
else
  warn "egress.pf.anchor" "not active (expected unless enabled)"
fi

section "Exec Approvals Fallback"
APPROVALS_JSON="$(openclaw approvals get --gateway --json 2>/dev/null || true)"
if [[ -n "${APPROVALS_JSON}" ]]; then
  ap_security="$(json_get "${APPROVALS_JSON}" "file.defaults.security")"
  ap_ask="$(json_get "${APPROVALS_JSON}" "file.defaults.ask")"
  ap_fallback="$(json_get "${APPROVALS_JSON}" "file.defaults.askFallback")"
  ap_agents="$(json_get "${APPROVALS_JSON}" "file.agents")"

  [[ "${ap_security}" == "allowlist" ]] && pass "approvals.security" "${ap_security}" || warn "approvals.security" "${ap_security}"
  [[ "${ap_ask}" == "on-miss" ]] && pass "approvals.ask" "${ap_ask}" || warn "approvals.ask" "${ap_ask}"
  [[ "${ap_fallback}" == "deny" ]] && pass "approvals.askFallback" "${ap_fallback}" || warn "approvals.askFallback" "${ap_fallback}"
  echo "${ap_agents}" | grep -q "main" && pass "approvals.agent.main" "present" || warn "approvals.agent.main" "missing"
else
  warn "approvals.get" "no gateway approvals snapshot"
fi

echo
echo "== Summary =="
echo "FAIL=${FAILS} WARN=${WARNS} STRICT=${STRICT}"
if [[ "${FAILS}" -gt 0 ]]; then
  exit 1
fi
if [[ "${STRICT}" -eq 1 && "${WARNS}" -gt 0 ]]; then
  exit 1
fi
exit 0
