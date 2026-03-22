#!/usr/bin/env bash
#
# add-secret.sh — safely add/update a secret in ~/.openclaw/.env.enc
#
# Usage:
#   ./infra/add-secret.sh KEY_NAME "secret-value"
#   ./infra/add-secret.sh KEY_NAME                 # prompts securely
#   ./infra/add-secret.sh --no-reload KEY_NAME "secret-value"
#
# Safety properties:
# - never prints secret values
# - uses 0600 temp files only
# - atomic replace of .env.enc (write tmp + mv)
# - best-effort cleanup on exit
#
set -euo pipefail

OPENCLAW_HOME="${OPENCLAW_HOME:-$HOME/.openclaw}"
ENV_ENC="${OPENCLAW_HOME}/.env.enc"

AGE_KEY_MACOS="${HOME}/Library/Application Support/sops/age/keys.txt"
AGE_KEY_XDG="${HOME}/.config/sops/age/keys.txt"

RELOAD_AFTER=1
if [[ "${1:-}" == "--no-reload" ]]; then
  RELOAD_AFTER=0
  shift
fi

KEY="${1:-}"
VALUE="${2:-}"

if [[ -z "${KEY}" ]]; then
  echo "Usage: $0 [--no-reload] KEY_NAME [secret-value]" >&2
  exit 1
fi

if [[ ! "${KEY}" =~ ^[A-Z][A-Z0-9_]{0,127}$ ]]; then
  echo "ERROR: invalid key name '${KEY}'." >&2
  echo "Allowed format: ^[A-Z][A-Z0-9_]{0,127}$" >&2
  exit 1
fi

if [[ ! -f "${ENV_ENC}" ]]; then
  echo "ERROR: encrypted env file not found: ${ENV_ENC}" >&2
  exit 1
fi

if command -v sops >/dev/null 2>&1; then
  SOPS_BIN="$(command -v sops)"
else
  echo "ERROR: sops not found in PATH." >&2
  exit 1
fi

if [[ -f "${AGE_KEY_MACOS}" ]]; then
  SOPS_AGE_KEY_FILE="${AGE_KEY_MACOS}"
elif [[ -f "${AGE_KEY_XDG}" ]]; then
  SOPS_AGE_KEY_FILE="${AGE_KEY_XDG}"
else
  echo "ERROR: age key file not found." >&2
  echo "Expected one of:" >&2
  echo "  ${AGE_KEY_MACOS}" >&2
  echo "  ${AGE_KEY_XDG}" >&2
  exit 1
fi
export SOPS_AGE_KEY_FILE

if [[ -z "${VALUE}" ]]; then
  read -r -s -p "Enter value for ${KEY}: " VALUE
  echo
fi

if [[ -z "${VALUE}" ]]; then
  echo "ERROR: secret value is empty." >&2
  exit 1
fi

TMP_PLAIN="$(mktemp "${TMPDIR:-/tmp}/openclaw-plain.XXXXXX")"
TMP_NEXT="$(mktemp "${TMPDIR:-/tmp}/openclaw-next.XXXXXX")"
TMP_ENC="$(mktemp "${TMPDIR:-/tmp}/openclaw-enc.XXXXXX")"
chmod 600 "${TMP_PLAIN}" "${TMP_NEXT}" "${TMP_ENC}"

cleanup() {
  rm -f "${TMP_PLAIN}" "${TMP_NEXT}" "${TMP_ENC}" 2>/dev/null || true
}
trap cleanup EXIT

# Decrypt existing encrypted dotenv.
"${SOPS_BIN}" --decrypt --input-type dotenv --output-type dotenv \
  --output "${TMP_PLAIN}" "${ENV_ENC}"

# Replace key if present; otherwise append.
if grep -q "^${KEY}=" "${TMP_PLAIN}"; then
  awk -v k="${KEY}" -v v="${VALUE}" '
    BEGIN { FS=OFS="=" }
    $1 == k { print k, v; next }
    { print $0 }
  ' "${TMP_PLAIN}" > "${TMP_NEXT}"
else
  cp "${TMP_PLAIN}" "${TMP_NEXT}"
  printf "%s=%s\n" "${KEY}" "${VALUE}" >> "${TMP_NEXT}"
fi

# Prefer recipient from existing key file comment.
AGE_PUB="$(grep 'public key:' "${SOPS_AGE_KEY_FILE}" | awk '{print $NF}' || true)"
if [[ -z "${AGE_PUB}" ]]; then
  echo "ERROR: failed to read age public key from ${SOPS_AGE_KEY_FILE}" >&2
  exit 1
fi

# Re-encrypt and atomically replace.
"${SOPS_BIN}" --encrypt --input-type dotenv --output-type dotenv \
  --filename-override "${ENV_ENC}" \
  --age "${AGE_PUB}" --output "${TMP_ENC}" "${TMP_NEXT}"
mv "${TMP_ENC}" "${ENV_ENC}"

echo "Secret '${KEY}' added/updated in ${ENV_ENC}"

if [[ "${RELOAD_AFTER}" -eq 1 ]]; then
  if openclaw secrets reload >/dev/null 2>&1; then
    echo "OpenClaw secrets reloaded."
  else
    echo "WARNING: could not reload secrets automatically." >&2
    echo "Run manually: openclaw secrets reload" >&2
  fi
fi
