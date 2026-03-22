#!/usr/bin/env bash
# telegram-webhook.sh — manage Telegram webhook for ops bot
#
# Usage:
#   TELEGRAM_OPS_BOT_TOKEN=... TELEGRAM_WEBHOOK_SECRET=... \
#   TELEGRAM_PUBLIC_WEBHOOK_URL="https://ops.example.com/telegram/restart-webhook" \
#   ./infra/ops/telegram-webhook.sh set
#
#   TELEGRAM_OPS_BOT_TOKEN=... ./infra/ops/telegram-webhook.sh info
#   TELEGRAM_OPS_BOT_TOKEN=... ./infra/ops/telegram-webhook.sh delete

set -euo pipefail

ACTION="${1:-}"
BOT_TOKEN="${TELEGRAM_OPS_BOT_TOKEN:-}"
WEBHOOK_URL="${TELEGRAM_PUBLIC_WEBHOOK_URL:-}"
WEBHOOK_SECRET="${TELEGRAM_WEBHOOK_SECRET:-}"

if [ -z "$ACTION" ]; then
    echo "Usage: $0 {set|info|delete}"
    exit 1
fi

if [ -z "$BOT_TOKEN" ]; then
    echo "ERROR: TELEGRAM_OPS_BOT_TOKEN is required"
    exit 1
fi

API_BASE="https://api.telegram.org/bot${BOT_TOKEN}"

case "$ACTION" in
    set)
        if [ -z "$WEBHOOK_URL" ]; then
            echo "ERROR: TELEGRAM_PUBLIC_WEBHOOK_URL is required for 'set'"
            exit 1
        fi
        if [ -z "$WEBHOOK_SECRET" ]; then
            echo "ERROR: TELEGRAM_WEBHOOK_SECRET is required for 'set'"
            exit 1
        fi
        curl -fsS -X POST "${API_BASE}/setWebhook" \
            -H "Content-Type: application/json" \
            -d "$(cat <<EOF
{
  "url": "${WEBHOOK_URL}",
  "secret_token": "${WEBHOOK_SECRET}",
  "allowed_updates": ["message", "edited_message"],
  "drop_pending_updates": false
}
EOF
)"
        echo
        ;;
    info)
        curl -fsS "${API_BASE}/getWebhookInfo"
        echo
        ;;
    delete)
        curl -fsS -X POST "${API_BASE}/deleteWebhook" \
            -H "Content-Type: application/json" \
            -d '{"drop_pending_updates":false}'
        echo
        ;;
    *)
        echo "Usage: $0 {set|info|delete}"
        exit 1
        ;;
esac
