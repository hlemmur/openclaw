#!/usr/bin/env bash
# encrypt-env.sh — encrypt .env with SOPS + age
#
# Defense: secrets encrypted at rest. Even if the filesystem is compromised
# (stolen laptop, backup leak, agent reads .env.enc), the attacker gets
# ciphertext, not keys. Decryption requires the age private key.
#
# Usage:
#   encrypt-env.sh              — encrypt .env -> .env.enc, shred .env
#   encrypt-env.sh decrypt      — decrypt .env.enc -> /Volumes/openclaw-secrets/.env
#   encrypt-env.sh rotate       — re-encrypt with new age key

set -euo pipefail

OPENCLAW_HOME="${OPENCLAW_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
ENV_PLAIN="${OPENCLAW_HOME}/.env"
ENV_ENCRYPTED="${OPENCLAW_HOME}/.env.enc"
RAMDISK="/Volumes/openclaw-secrets"
AGE_KEY_DIR_XDG="${HOME}/.config/sops/age"
AGE_KEY_DIR_MACOS="${HOME}/Library/Application Support/sops/age"
if [ -f "${AGE_KEY_DIR_MACOS}/keys.txt" ]; then
    AGE_KEY_DIR="${AGE_KEY_DIR_MACOS}"
elif [ -f "${AGE_KEY_DIR_XDG}/keys.txt" ]; then
    AGE_KEY_DIR="${AGE_KEY_DIR_XDG}"
else
    AGE_KEY_DIR="${AGE_KEY_DIR_MACOS}"
fi
AGE_KEY_FILE="${AGE_KEY_DIR}/keys.txt"
export SOPS_AGE_KEY_FILE="${AGE_KEY_FILE}"
SOPS_CONFIG="${OPENCLAW_HOME}/.sops.yaml"

ensure_age_key() {
    if [ -f "$AGE_KEY_FILE" ]; then
        echo "[vault] age key exists at $AGE_KEY_FILE"
        return
    fi

    echo "[vault] generating new age key pair..."
    mkdir -p "$AGE_KEY_DIR"
    mkdir -p "$AGE_KEY_DIR_XDG"
    mkdir -p "$AGE_KEY_DIR_MACOS"
    age-keygen -o "$AGE_KEY_FILE" 2>&1
    chmod 600 "$AGE_KEY_FILE"
    cp "$AGE_KEY_FILE" "${AGE_KEY_DIR_XDG}/keys.txt" 2>/dev/null || true
    cp "$AGE_KEY_FILE" "${AGE_KEY_DIR_MACOS}/keys.txt" 2>/dev/null || true
    chmod 600 "${AGE_KEY_DIR_XDG}/keys.txt" 2>/dev/null || true
    chmod 600 "${AGE_KEY_DIR_MACOS}/keys.txt" 2>/dev/null || true
    echo "[vault] key saved to $AGE_KEY_FILE"
    echo "[vault] BACK UP THIS KEY — if lost, secrets are unrecoverable"
}

get_age_public_key() {
    grep -o 'age1[a-z0-9]*' "$AGE_KEY_FILE" | head -1
}

create_sops_config() {
    local pubkey
    pubkey=$(get_age_public_key)

    cat > "$SOPS_CONFIG" << YAML
creation_rules:
  - path_regex: '\.env\.enc$'
    age: '${pubkey}'
  - path_regex: '\.env$'
    age: '${pubkey}'
YAML

    echo "[vault] wrote SOPS config to $SOPS_CONFIG"
}

encrypt() {
    if [ ! -f "$ENV_PLAIN" ]; then
        echo "[vault] ERROR: $ENV_PLAIN not found, nothing to encrypt"
        exit 1
    fi

    ensure_age_key
    create_sops_config

    echo "[vault] encrypting $ENV_PLAIN -> $ENV_ENCRYPTED"
    sops --encrypt --input-type dotenv --output-type dotenv \
         --output "$ENV_ENCRYPTED" \
         "$ENV_PLAIN"

    echo "[vault] verifying decryption works..."
    sops --decrypt --input-type dotenv --output-type dotenv \
         "$ENV_ENCRYPTED" > /dev/null

    echo "[vault] shredding plaintext .env..."
    if command -v gshred &>/dev/null; then
        gshred -u "$ENV_PLAIN"
    else
        dd if=/dev/urandom of="$ENV_PLAIN" bs=1k count=8 2>/dev/null
        rm -f "$ENV_PLAIN"
    fi

    echo "[vault] done — plaintext destroyed, encrypted at $ENV_ENCRYPTED"
    echo "[vault] WARNING: rotate all API keys NOW (they were in plaintext before)"
}

decrypt() {
    if [ ! -f "$ENV_ENCRYPTED" ]; then
        echo "[vault] ERROR: $ENV_ENCRYPTED not found"
        exit 1
    fi

    if [ ! -d "$RAMDISK" ]; then
        echo "[vault] ERROR: ramdisk not mounted at $RAMDISK"
        echo "[vault] run: ./infra/vault/ramdisk.sh create"
        exit 1
    fi

    echo "[vault] decrypting to ramdisk..."
    sops --decrypt --input-type dotenv --output-type dotenv \
         --output "${RAMDISK}/.env" \
         "$ENV_ENCRYPTED"

    chmod 600 "${RAMDISK}/.env"
    echo "[vault] secrets available at ${RAMDISK}/.env"
}

rotate() {
    echo "[vault] generating fresh age key..."
    local backup="${AGE_KEY_FILE}.bak.$(date +%s)"
    cp "$AGE_KEY_FILE" "$backup"

    age-keygen -o "$AGE_KEY_FILE" 2>&1
    chmod 600 "$AGE_KEY_FILE"

    create_sops_config

    if [ -f "$ENV_ENCRYPTED" ]; then
        echo "[vault] re-encrypting with new key..."
        local tmpfile
        tmpfile=$(mktemp)
        SOPS_AGE_KEY_FILE="$backup" sops --decrypt --input-type dotenv --output-type dotenv \
            --output "$tmpfile" "$ENV_ENCRYPTED"
        sops --encrypt --input-type dotenv --output-type dotenv \
            --output "$ENV_ENCRYPTED" "$tmpfile"
        rm -f "$tmpfile"
    fi

    echo "[vault] key rotated. old key backed up at $backup"
    echo "[vault] delete the backup after verifying: rm $backup"
}

case "${1:-}" in
    decrypt) decrypt ;;
    rotate)  rotate ;;
    "")      encrypt ;;
    *)
        echo "Usage: $0 [decrypt|rotate]"
        exit 1
        ;;
esac
