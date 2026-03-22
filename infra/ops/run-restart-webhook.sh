#!/usr/bin/env bash
# run-restart-webhook.sh — launch wrapper for restart webhook daemon

set -euo pipefail

OPENCLAW_HOME="${OPENCLAW_HOME:-${HOME}/.openclaw}"
ENV_FILE="${OPENCLAW_HOME}/infra/ops/restart-webhook.env"
PY_SCRIPT="${OPENCLAW_HOME}/infra/ops/restart-webhook.py"

if [ ! -f "${ENV_FILE}" ]; then
    echo "ERROR: env file not found: ${ENV_FILE}" >&2
    echo "Copy ${OPENCLAW_HOME}/infra/ops/restart-webhook.env.example first." >&2
    exit 1
fi

# shellcheck disable=SC1090
source "${ENV_FILE}"

exec /usr/bin/env python3 "${PY_SCRIPT}"
