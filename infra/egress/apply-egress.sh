#!/usr/bin/env bash
# apply-egress.sh — resolve whitelisted domains and load pf rules
#
# Defense: restricts network egress from sandboxed exec commands to
# known-good destinations only. Prevents exfiltration via DNS/HTTP.
#
# Usage:
#   sudo apply-egress.sh enable    — resolve domains, load pf rules
#   sudo apply-egress.sh disable   — remove openclaw pf anchor
#   sudo apply-egress.sh refresh   — re-resolve domains (IPs may change)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PF_CONF="${SCRIPT_DIR}/pf-openclaw.conf"
PF_ANCHOR="openclaw"
PF_ANCHOR_FILE="/etc/pf.anchors/${PF_ANCHOR}"

ALLOWED_DOMAINS=(
    "api.anthropic.com"
    "api.telegram.org"
    "generativelanguage.googleapis.com"
    "github.com"
    "api.github.com"
    "registry.npmjs.org"
    "objects.githubusercontent.com"
)

resolve_domains() {
    echo "[egress] resolving whitelisted domains..."
    local ips=()
    for domain in "${ALLOWED_DOMAINS[@]}"; do
        local resolved
        resolved=$(dig +short A "$domain" 2>/dev/null | grep -E '^[0-9]+\.' || true)
        if [ -n "$resolved" ]; then
            while IFS= read -r ip; do
                ips+=("$ip")
                echo "  ${domain} -> ${ip}"
            done <<< "$resolved"
        else
            echo "  WARNING: could not resolve ${domain}"
        fi
    done

    pfctl -t openclaw_allowed -T flush 2>/dev/null || true
    for ip in "${ips[@]}"; do
        pfctl -t openclaw_allowed -T add "$ip" 2>/dev/null
    done
    echo "[egress] loaded ${#ips[@]} IPs into table"
}

enable_egress() {
    if [ "$EUID" -ne 0 ]; then
        echo "ERROR: must run as root (sudo)" >&2
        exit 1
    fi

    echo "[egress] installing pf anchor..."
    cp "$PF_CONF" "$PF_ANCHOR_FILE"

    if ! grep -q "anchor \"${PF_ANCHOR}\"" /etc/pf.conf; then
        echo "[egress] adding anchor to /etc/pf.conf..."
        cp /etc/pf.conf /etc/pf.conf.bak.openclaw
        echo "anchor \"${PF_ANCHOR}\"" >> /etc/pf.conf
        echo "load anchor \"${PF_ANCHOR}\" from \"${PF_ANCHOR_FILE}\"" >> /etc/pf.conf
    fi

    resolve_domains
    pfctl -f /etc/pf.conf 2>/dev/null
    pfctl -e 2>/dev/null || true
    echo "[egress] pf rules active"
}

disable_egress() {
    if [ "$EUID" -ne 0 ]; then
        echo "ERROR: must run as root (sudo)" >&2
        exit 1
    fi

    echo "[egress] removing pf anchor..."
    if [ -f /etc/pf.conf.bak.openclaw ]; then
        cp /etc/pf.conf.bak.openclaw /etc/pf.conf
        pfctl -f /etc/pf.conf 2>/dev/null
    fi
    rm -f "$PF_ANCHOR_FILE"
    pfctl -t openclaw_allowed -T flush 2>/dev/null || true
    echo "[egress] pf rules removed"
}

case "${1:-}" in
    enable)  enable_egress ;;
    disable) disable_egress ;;
    refresh) resolve_domains ;;
    *)
        echo "Usage: sudo $0 {enable|disable|refresh}"
        exit 1
        ;;
esac
