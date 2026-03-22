#!/usr/bin/env bash
# install-restart-webhook-launchd.sh — install launchd service for webhook

set -euo pipefail

OPENCLAW_HOME="${OPENCLAW_HOME:-${HOME}/.openclaw}"
SCRIPT_DIR="${OPENCLAW_HOME}/infra/ops"
PLIST_LABEL="com.oc.telegram-restart-webhook"
PLIST_DST="${HOME}/Library/LaunchAgents/${PLIST_LABEL}.plist"
LOG_DIR="${OPENCLAW_HOME}/logs"

mkdir -p "${HOME}/Library/LaunchAgents"
mkdir -p "${LOG_DIR}"

cat > "${PLIST_DST}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${PLIST_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${SCRIPT_DIR}/run-restart-webhook.sh</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>${LOG_DIR}/telegram-restart-webhook.log</string>
  <key>StandardErrorPath</key>
  <string>${LOG_DIR}/telegram-restart-webhook.err.log</string>
</dict>
</plist>
EOF

launchctl unload "${PLIST_DST}" 2>/dev/null || true
launchctl load "${PLIST_DST}"

echo "Installed and started: ${PLIST_LABEL}"
echo "plist: ${PLIST_DST}"
echo "status: launchctl list | grep ${PLIST_LABEL}"
