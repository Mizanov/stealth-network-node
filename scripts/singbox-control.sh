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

        exec /usr/bin/sing-box check -c "$REAL_PATH"
        ;;

    reload)
        exec /usr/bin/systemctl reload sing-box.service
        ;;

    status)
        exec /usr/bin/systemctl is-active sing-box.service
        ;;

    tgproxy-link)
        exec /usr/bin/docker exec tgweb-proxy show-link
        ;;

    *)
        echo "ERROR: Invalid action '${ACTION}'. Allowed actions: check, reload, status, tgproxy-link" >&2
        exit 1
        ;;
esac
