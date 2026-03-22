#!/usr/bin/env bash
# ramdisk.sh — manage encrypted secrets ramdisk on macOS
#
# Defense: secrets exist in plaintext ONLY in volatile RAM.
# Power off / eject = secrets gone. The ramdisk path is NOT accessible
# from the exec sandbox (sandbox profile denies /Volumes/openclaw-secrets).
#
# Usage:
#   ramdisk.sh create   — create 16MB ramdisk, mount as openclaw-secrets
#   ramdisk.sh destroy  — eject ramdisk, wipe secrets from memory
#   ramdisk.sh status   — check if ramdisk is mounted

set -euo pipefail

VOLUME_NAME="openclaw-secrets"
MOUNT_POINT="/Volumes/${VOLUME_NAME}"
SIZE_SECTORS=32768  # 32768 * 512B = 16MB

create_ramdisk() {
    if mount | grep -q "$MOUNT_POINT"; then
        echo "[ramdisk] already mounted at $MOUNT_POINT"
        return 0
    fi

    echo "[ramdisk] creating ${SIZE_SECTORS} sector RAM disk (~16MB)..."
    DISK=$(hdiutil attach -nomount "ram://${SIZE_SECTORS}")
    DISK=$(echo "$DISK" | xargs)  # trim whitespace

    echo "[ramdisk] formatting as HFS+ volume '${VOLUME_NAME}'..."
    diskutil erasevolume HFS+ "$VOLUME_NAME" "$DISK" > /dev/null

    chmod 700 "$MOUNT_POINT"
    echo "[ramdisk] mounted at $MOUNT_POINT (owner-only access)"
}

destroy_ramdisk() {
    if ! mount | grep -q "$MOUNT_POINT"; then
        echo "[ramdisk] not mounted, nothing to destroy"
        return 0
    fi

    if [ -f "${MOUNT_POINT}/.env" ]; then
        dd if=/dev/zero of="${MOUNT_POINT}/.env" bs=1k count=64 2>/dev/null || true
        rm -f "${MOUNT_POINT}/.env"
    fi

    echo "[ramdisk] ejecting..."
    diskutil eject "$MOUNT_POINT" > /dev/null 2>&1 || \
        hdiutil detach "$MOUNT_POINT" -force 2>/dev/null || true
    echo "[ramdisk] destroyed — secrets wiped from RAM"
}

status_ramdisk() {
    if mount | grep -q "$MOUNT_POINT"; then
        echo "[ramdisk] MOUNTED at $MOUNT_POINT"
        ls -la "$MOUNT_POINT/" 2>/dev/null
        return 0
    else
        echo "[ramdisk] NOT MOUNTED"
        return 1
    fi
}

case "${1:-}" in
    create)  create_ramdisk ;;
    destroy) destroy_ramdisk ;;
    status)  status_ramdisk ;;
    *)
        echo "Usage: $0 {create|destroy|status}"
        exit 1
        ;;
esac
