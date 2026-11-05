#!/usr/bin/env bash
# ==============================================================================
# Automated VPS Snapshot Backup Script
# Creates a compressed archive of critical VPN configs, certificates & bot data
# ==============================================================================

set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/root/backups}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/vps_backup_${TIMESTAMP}.tar.gz"

mkdir -p "$BACKUP_DIR"

echo "Creating backup: $BACKUP_FILE ..."

tar -czf "$BACKUP_FILE" \
    --exclude='*.pyc' \
    --exclude='__pycache__' \
    --exclude='/opt/incy-bot/venv' \
    /etc/sing-box/config.json \
    /etc/nginx/nginx.conf \
    /etc/letsencrypt \
    /opt/incy-bot \
    /var/www/site \
    /etc/sysctl.d/99-security.conf \
    /etc/fail2ban/jail.local \
    2>/dev/null || true

chmod 600 "$BACKUP_FILE"
echo "Backup created successfully: $(ls -lh "$BACKUP_FILE" | awk '{print $5, $9}')"

# Retain only the last 7 daily backups
find "$BACKUP_DIR" -type f -name "vps_backup_*.tar.gz" -mtime +7 -delete 2>/dev/null || true
