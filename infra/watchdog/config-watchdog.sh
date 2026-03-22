#!/usr/bin/env bash
# config-watchdog.sh — monitors critical config files for unauthorized changes
#
# Defense: if an agent (via prompt injection) or malicious tool modifies
# openclaw.json, hooks config, or security scripts, this watchdog detects
# the change and auto-reverts from a known-good baseline.
#
# Uses fswatch (macOS) for real-time monitoring.
# Falls back to polling if fswatch is not available.

set -euo pipefail

OPENCLAW_HOME="${OPENCLAW_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
BASELINE_DIR="${OPENCLAW_HOME}/infra/watchdog/.baselines"
LOG_FILE="${OPENCLAW_HOME}/logs/config-audit.jsonl"

WATCHED_FILES=(
    "${OPENCLAW_HOME}/openclaw.json"
    "${OPENCLAW_HOME}/infra/hooks/fs-guard.js"
    "${OPENCLAW_HOME}/infra/hooks/dlp-output.js"
    "${OPENCLAW_HOME}/infra/sandbox/exec-wrapper.sh"
    "${OPENCLAW_HOME}/infra/sandbox/exec-sandbox.sb"
    "${OPENCLAW_HOME}/infra/sandbox/exec-sandbox-net.sb"
)

init_baselines() {
    mkdir -p "$BASELINE_DIR"
    for f in "${WATCHED_FILES[@]}"; do
        if [ -f "$f" ]; then
            local name
            name=$(echo "$f" | shasum -a 256 | cut -c1-16)
            cp "$f" "${BASELINE_DIR}/${name}"
            shasum -a 256 "$f" > "${BASELINE_DIR}/${name}.sha256"
        fi
    done
    echo "[watchdog] baselines initialized for ${#WATCHED_FILES[@]} files"
}

check_file() {
    local filepath="$1"
    local name
    name=$(echo "$filepath" | shasum -a 256 | cut -c1-16)
    local baseline="${BASELINE_DIR}/${name}"
    local hashfile="${BASELINE_DIR}/${name}.sha256"

    if [ ! -f "$hashfile" ]; then
        return 0
    fi

    local expected_hash current_hash
    expected_hash=$(cut -d' ' -f1 "$hashfile")
    current_hash=$(shasum -a 256 "$filepath" 2>/dev/null | cut -d' ' -f1)

    if [ "$expected_hash" != "$current_hash" ]; then
        local ts
        ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
        local entry="{\"ts\":\"${ts}\",\"event\":\"config.tamper\",\"file\":\"${filepath}\",\"expected\":\"${expected_hash}\",\"actual\":\"${current_hash}\",\"action\":\"revert\"}"
        echo "$entry" >> "$LOG_FILE"

        echo "[watchdog] ALERT: unauthorized change detected in ${filepath}"
        echo "[watchdog] reverting to baseline..."
        cp "$baseline" "$filepath"

        local new_hash
        new_hash=$(shasum -a 256 "$filepath" | cut -d' ' -f1)
        if [ "$new_hash" = "$expected_hash" ]; then
            echo "[watchdog] reverted successfully"
        else
            echo "[watchdog] ERROR: revert failed!" >&2
        fi
    fi
}

watch_fswatch() {
    echo "[watchdog] starting fswatch monitor..."
    local dirs=()
    for f in "${WATCHED_FILES[@]}"; do
        dirs+=("$f")
    done

    fswatch -0 "${dirs[@]}" | while IFS= read -r -d '' changed; do
        check_file "$changed"
    done
}

watch_poll() {
    local interval="${1:-30}"
    echo "[watchdog] fswatch not found, falling back to polling (${interval}s)..."
    while true; do
        for f in "${WATCHED_FILES[@]}"; do
            if [ -f "$f" ]; then
                check_file "$f"
            fi
        done
        sleep "$interval"
    done
}

case "${1:-}" in
    init)
        init_baselines
        ;;
    watch)
        if command -v fswatch &>/dev/null; then
            watch_fswatch
        else
            watch_poll 30
        fi
        ;;
    check)
        for f in "${WATCHED_FILES[@]}"; do
            if [ -f "$f" ]; then
                check_file "$f"
            fi
        done
        echo "[watchdog] check complete"
        ;;
    *)
        echo "Usage: $0 {init|watch|check}"
        exit 1
        ;;
esac
