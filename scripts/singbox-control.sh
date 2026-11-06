#!/usr/bin/env bash
# ==============================================================================
# Root-Owned Singbox & TG-Proxy Control Helper
# Intended to be invoked via sudo by the incy-bot user for strictly audited operations
# Permissions: chown root:root /usr/local/bin/singbox-control && chmod 755
# ==============================================================================

set -euo pipefail

ACTION="${1:-}"

case "$ACTION" in
    check)
        TARGET="${2:-}"
        if [ -z "$TARGET" ]; then
            echo "ERROR: Missing target path for configuration check" >&2
            exit 1
        fi

        if [ ! -f "$TARGET" ]; then
            echo "ERROR: Target file '$TARGET' does not exist or is not a regular file" >&2
            exit 1
        fi

        # Canonicalize path to prevent directory traversal
        REAL_PATH=$(readlink -f "$TARGET" 2>/dev/null || realpath "$TARGET" 2>/dev/null || true)
        if [ -z "$REAL_PATH" ]; then
            echo "ERROR: Target path could not be resolved canonically" >&2
            exit 1
        fi

        # Enforce directory whitelist: only /etc/sing-box/* or /tmp/singbox_* (or /private/tmp on Darwin)
        if [[ "$REAL_PATH" != /etc/sing-box/* && "$REAL_PATH" != /tmp/singbox_* && "$REAL_PATH" != /private/tmp/singbox_* ]]; then
            echo "ERROR: Target path '$REAL_PATH' is outside allowed directories" >&2
            exit 1
        fi

        # Locate sing-box binary
        SINGBOX_BIN="${SINGBOX_BIN:-/usr/bin/sing-box}"
        if [ ! -x "$SINGBOX_BIN" ]; then
            SINGBOX_BIN="/usr/local/bin/sing-box"
        fi
        if [ ! -x "$SINGBOX_BIN" ]; then
            SINGBOX_BIN=$(command -v sing-box 2>/dev/null || true)
        fi

        if [ -n "$SINGBOX_BIN" ] && [ -x "$SINGBOX_BIN" ]; then
            exec "$SINGBOX_BIN" check -c "$REAL_PATH"
        else
            # Fallback syntax & structure validation when sing-box package is not in environment
            python3 -c "
import json, sys
try:
    with open(sys.argv[1], 'r', encoding='utf-8') as f:
        data = json.load(f)
    if not isinstance(data, dict) or 'inbounds' not in data:
        sys.exit(1)
    sys.exit(0)
except Exception:
    sys.exit(1)
" "$REAL_PATH" || { echo "ERROR: Configuration validation failed for '$REAL_PATH'" >&2; exit 1; }
            exit 0
        fi
        ;;

    reload)
        SYSTEMCTL_BIN="${SYSTEMCTL_BIN:-$(command -v systemctl 2>/dev/null || echo "/bin/systemctl")}"
        if [ -x "$SYSTEMCTL_BIN" ]; then
            exec "$SYSTEMCTL_BIN" reload sing-box.service
        else
            exit 0
        fi
        ;;

    status)
        SYSTEMCTL_BIN="${SYSTEMCTL_BIN:-$(command -v systemctl 2>/dev/null || echo "/bin/systemctl")}"
        if [ -x "$SYSTEMCTL_BIN" ]; then
            exec "$SYSTEMCTL_BIN" is-active sing-box.service
        else
            exit 0
        fi
        ;;

    rollback)
        BACKUP_FILE="${SINGBOX_BACKUP_FILE:-/etc/sing-box/config.json.bak}"
        CONFIG_FILE="${SINGBOX_CONFIG_FILE:-/etc/sing-box/config.json}"
        if [ ! -f "$BACKUP_FILE" ]; then
            echo "ERROR: Backup file '$BACKUP_FILE' does not exist" >&2
            exit 1
        fi
        cp -f "$BACKUP_FILE" "$CONFIG_FILE"
        chmod 660 "$CONFIG_FILE"
        SYSTEMCTL_BIN="${SYSTEMCTL_BIN:-$(command -v systemctl 2>/dev/null || echo "/bin/systemctl")}"
        if [ -x "$SYSTEMCTL_BIN" ]; then
            exec "$SYSTEMCTL_BIN" reload sing-box.service
        else
            exit 0
        fi
        ;;

    tgproxy-link)
        exec /usr/bin/docker exec tgweb-proxy show-link
        ;;

    xray-check)
        TARGET="${2:-}"
        if [ -z "$TARGET" ]; then
            echo "ERROR: Missing target path for xray configuration check" >&2
            exit 1
        fi

        if [ ! -f "$TARGET" ]; then
            echo "ERROR: Target file '$TARGET' does not exist or is not a regular file" >&2
            exit 1
        fi

        REAL_PATH=$(readlink -f "$TARGET" 2>/dev/null || realpath "$TARGET" 2>/dev/null || true)
        if [ -z "$REAL_PATH" ]; then
            echo "ERROR: Target path could not be resolved canonically" >&2
            exit 1
        fi

        # Whitelist: only /etc/xray/* or /tmp/xray_* (or /private/tmp/xray_* on Darwin)
        if [[ "$REAL_PATH" != /etc/xray/* && "$REAL_PATH" != /tmp/xray_* && "$REAL_PATH" != /private/tmp/xray_* ]]; then
            echo "ERROR: Target path '$REAL_PATH' is outside allowed directories" >&2
            exit 1
        fi

        XRAY_BIN="${XRAY_BIN:-$(command -v xray 2>/dev/null || echo "/usr/local/bin/xray")}"
        if [ -x "$XRAY_BIN" ]; then
            exec "$XRAY_BIN" run -test -c "$REAL_PATH"
        else
            python3 -c "
import json, sys
try:
    with open(sys.argv[1], 'r', encoding='utf-8') as f:
        data = json.load(f)
    if not isinstance(data, dict) or 'inbounds' not in data:
        sys.exit(1)
    sys.exit(0)
except Exception:
    sys.exit(1)
" "$REAL_PATH" || { echo "ERROR: Xray configuration validation failed for '$REAL_PATH'" >&2; exit 1; }
            exit 0
        fi
        ;;

    xray-reload)
        SYSTEMCTL_BIN="${SYSTEMCTL_BIN:-$(command -v systemctl 2>/dev/null || echo "/bin/systemctl")}"
        if [ -x "$SYSTEMCTL_BIN" ]; then
            exec "$SYSTEMCTL_BIN" reload xray.service 2>/dev/null || exec "$SYSTEMCTL_BIN" restart xray.service
        else
            exit 0
        fi
        ;;

    xray-status)
        SYSTEMCTL_BIN="${SYSTEMCTL_BIN:-$(command -v systemctl 2>/dev/null || echo "/bin/systemctl")}"
        if [ -x "$SYSTEMCTL_BIN" ]; then
            exec "$SYSTEMCTL_BIN" is-active xray.service
        else
            exit 0
        fi
        ;;

    xray-rollback)
        BACKUP_FILE="${XRAY_BACKUP_FILE:-/etc/xray/config.json.bak}"
        CONFIG_FILE="${XRAY_CONFIG_FILE:-/etc/xray/config.json}"
        if [ ! -f "$BACKUP_FILE" ]; then
            echo "ERROR: Backup file '$BACKUP_FILE' does not exist" >&2
            exit 1
        fi
        cp -f "$BACKUP_FILE" "$CONFIG_FILE"
        chmod 660 "$CONFIG_FILE"
        SYSTEMCTL_BIN="${SYSTEMCTL_BIN:-$(command -v systemctl 2>/dev/null || echo "/bin/systemctl")}"
        if [ -x "$SYSTEMCTL_BIN" ]; then
            exec "$SYSTEMCTL_BIN" restart xray.service
        else
            exit 0
        fi
        ;;

    *)
        echo "ERROR: Invalid action '${ACTION}'. Allowed actions: check, reload, status, rollback, tgproxy-link, xray-check, xray-reload, xray-status, xray-rollback" >&2
        exit 1
        ;;
esac
