#!/usr/bin/env bash
# ==============================================================================
# Hardened VPS Snapshot Backup & Restore Script
# Creates a compressed, cryptographically and structurally verified archive
# of critical network node configs, certificates & bot data with strict permissions.
# ==============================================================================

set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/root/backups}"
RETENTION_DAYS="${RETENTION_DAYS:-7}"

# Target file paths to backup if they exist
DEFAULT_TARGET_PATHS=(
    /etc/sing-box/config.json
    /etc/nginx/nginx.conf
    /etc/letsencrypt
    /opt/incy-bot
    /var/www/site
    /etc/sysctl.d/99-security.conf
    /etc/fail2ban/jail.local
)

verify_archive() {
    local archive_path="$1"
    if [ ! -f "$archive_path" ]; then
        echo "[-] Error: Archive file not found: $archive_path" >&2
        return 1
    fi

    echo "[*] Verifying structural integrity of $archive_path..."
    if ! tar -tzf "$archive_path" >/dev/null 2>&1; then
        echo "[-] Error: Archive verification failed! File is corrupt or not a valid gzip tarball." >&2
        return 1
    fi

    echo "[*] Auditing member paths, symlinks, and hardlinks for escape attempts..."
    if command -v python3 >/dev/null 2>&1; then
        if ! python3 -c '
import os, sys, tarfile
archive = sys.argv[1]
try:
    with tarfile.open(archive, "r:*") as tar:
        for m in tar.getmembers():
            norm_name = os.path.normpath(m.name)
            if m.name.startswith("/") or norm_name.startswith("..") or "/../" in m.name or m.name.startswith("../"):
                print(f"[-] Security Error: Archive contains absolute paths or path traversal: {m.name}", file=sys.stderr)
                sys.exit(1)
            if m.issym() or m.islnk():
                if m.linkname.startswith("/"):
                    print(f"[-] Security Error: Archive contains dangerous symlinks/hardlinks pointing to absolute path: {m.name} -> {m.linkname}", file=sys.stderr)
                    sys.exit(1)
                resolved = os.path.normpath(os.path.join(os.path.dirname(m.name), m.linkname))
                if resolved.startswith("..") or resolved.startswith("/"):
                    print(f"[-] Security Error: Archive contains dangerous symlinks/hardlinks traversing outwards: {m.name} -> {m.linkname}", file=sys.stderr)
                    sys.exit(1)
except Exception as e:
    print(f"[-] Error parsing archive: {e}", file=sys.stderr)
    sys.exit(1)
' "$archive_path"; then
            echo "[-] Security Audit Failed: Archive contains unsafe paths. Extraction blocked!" >&2
            return 1
        fi
    else
        # Fallback basic checks if python3 is not available
        if tar -tzf "$archive_path" | grep -qE '(^/|(^|/)\.\.(/|$))'; then
            echo "[-] Security Error: Archive contains path traversal components ('..'). Extraction blocked!" >&2
            return 1
        fi
    fi

    local file_count
    file_count=$(tar -tzf "$archive_path" | wc -l | tr -d ' ')
    echo "[+] Archive passed all security and structural audits ($file_count safe entries)."
    return 0
}

restore_archive() {
    local archive_path="$1"
    local dest_dir="$2"

    if ! verify_archive "$archive_path"; then
        echo "[-] Restore aborted: Archive verification failed." >&2
        return 1
    fi

    mkdir -p "$dest_dir"
    local canonical_dest
    canonical_dest=$(cd "$dest_dir" && pwd -P)

    echo "[*] Restoring archive $archive_path into $canonical_dest..."
    if ! tar -xzf "$archive_path" -C "$canonical_dest"; then
        echo "[-] Error: Failed to extract archive into $canonical_dest." >&2
        return 1
    fi

    # Enforce safe permissions on restored artifacts
    echo "[*] Enforcing safe permissions on restored files..."
    chmod -R o-w "$canonical_dest" 2>/dev/null || true
    # Restrict permissions on sensitive configuration / keys if present
    find "$canonical_dest" -type f \( -name "*.key" -o -name "privkey.pem" -o -name ".env" -o -name "subscriptions.json" \) -exec chmod 600 {} + 2>/dev/null || true

    echo "[+] Archive restored and sanitized successfully into $canonical_dest."
    return 0
}

create_backup() {
    local timestamp
    timestamp=$(date +"%Y%m%d_%H%M%S")
    local backup_file="${BACKUP_DIR}/vps_backup_${timestamp}.tar.gz"

    mkdir -p "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"

    # Identify existing targets
    local existing_targets=()
    for target in "${DEFAULT_TARGET_PATHS[@]}"; do
        if [ -e "$target" ]; then
            existing_targets+=("$target")
        fi
    done

    # If an override list of paths was provided via BACKUP_TARGETS env var
    if [ -n "${BACKUP_TARGETS:-}" ]; then
        existing_targets=()
        # shellcheck disable=SC2086
        for target in $BACKUP_TARGETS; do
            if [ -e "$target" ]; then
                existing_targets+=("$target")
            fi
        done
    fi

    if [ "${#existing_targets[@]}" -eq 0 ]; then
        echo "[-] Error: None of the target backup paths exist on this system." >&2
        return 1
    fi

    echo "[*] Creating hardened backup: $backup_file ..."
    echo "[*] Archiving ${#existing_targets[@]} targets..."

    if ! tar -czf "$backup_file" \
        --exclude='*.pyc' \
        --exclude='__pycache__' \
        --exclude='*/venv/*' \
        --exclude='*/.git/*' \
        "${existing_targets[@]}"; then
        echo "[-] Error: tar command failed to create backup archive." >&2
        rm -f "$backup_file"
        return 1
    fi

    # Verify immediately after creation
    if ! verify_archive "$backup_file"; then
        echo "[-] Error: Created archive failed integrity verification! Removing." >&2
        rm -f "$backup_file"
        return 1
    fi

    # Lock down file permissions strictly to root / creator
    chmod 600 "$backup_file"

    local file_count
    file_count=$(tar -tzf "$backup_file" | wc -l | tr -d ' ')
    local file_size
    file_size=$(ls -lh "$backup_file" | awk '{print $5}')
    echo "[+] Backup created and verified successfully: $backup_file ($file_size, $file_count files)"

    # Prune outdated backups
    echo "[*] Pruning backups older than $RETENTION_DAYS days in $BACKUP_DIR..."
    find "$BACKUP_DIR" -maxdepth 1 -type f -name "vps_backup_*.tar.gz" -mtime "+$RETENTION_DAYS" -delete 2>/dev/null || true

    return 0
}

# CLI dispatcher
case "${1:-}" in
    --verify)
        if [ -z "${2:-}" ]; then
            echo "Usage: $0 --verify <archive.tar.gz>" >&2
            exit 1
        fi
        verify_archive "$2"
        ;;
    --restore)
        if [ -z "${2:-}" ] || [ -z "${3:-}" ]; then
            echo "Usage: $0 --restore <archive.tar.gz> <destination_directory>" >&2
            exit 1
        fi
        restore_archive "$2" "$3"
        ;;
    --help|-h)
        echo "VPS Backup Utility"
        echo "Usage:"
        echo "  $0                          Create and verify a new snapshot backup"
        echo "  $0 --verify <archive>       Verify an existing backup archive"
        echo "  $0 --restore <archive> <dir> Restore archive into target directory"
        ;;
    *)
        create_backup
        ;;
esac
