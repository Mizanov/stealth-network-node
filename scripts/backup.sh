#!/usr/bin/env bash
# ==============================================================================
# Hardened VPS Snapshot Backup & Restore Script
# Creates a compressed, cryptographically and structurally verified archive
# of critical VPN configs, certificates & bot data with strict permissions.
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

    echo "[*] Verifying integrity of $archive_path..."
    if ! tar -tzf "$archive_path" >/dev/null 2>&1; then
        echo "[-] Error: Archive verification failed! File is corrupt or not a valid gzip tarball." >&2
        return 1
    fi

    local file_count
    file_count=$(tar -tzf "$archive_path" | wc -l | tr -d ' ')
    echo "[+] Archive is valid ($file_count entries)."
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
    echo "[*] Restoring archive $archive_path into $dest_dir..."
    if ! tar -xzf "$archive_path" -C "$dest_dir"; then
        echo "[-] Error: Failed to extract archive into $dest_dir." >&2
        return 1
    fi

    echo "[+] Archive restored successfully into $dest_dir."
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
