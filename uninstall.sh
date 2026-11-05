#!/usr/bin/env bash
# ==============================================================================
# Telegram Web Proxy & Sing-Box Universal Suite - Uninstaller
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR]${NC} Please run this script as root (sudo -i)"
    exit 1
fi

echo -e "${YELLOW}WARNING: This script will completely remove Sing-Box, Telegram Web Proxy, and the Telegram Bot.${NC}"
read -r -p "Are you sure you want to proceed? (yes/no): " confirm
if [ "$confirm" != "yes" ]; then
    echo "Aborted."
    exit 0
fi

echo -e "${CYAN}[INFO]${NC} Stopping and disabling services..."
systemctl stop incy-bot.service 2>/dev/null || true
systemctl disable incy-bot.service 2>/dev/null || true
rm -f /etc/systemd/system/incy-bot.service
systemctl daemon-reload

systemctl stop sing-box 2>/dev/null || true
systemctl disable sing-box 2>/dev/null || true

systemctl stop nginx 2>/dev/null || true
systemctl disable nginx 2>/dev/null || true

echo -e "${CYAN}[INFO]${NC} Removing Docker container tgweb-proxy..."
docker stop tgweb-proxy 2>/dev/null || true
docker rm tgweb-proxy 2>/dev/null || true
docker volume rm tgweb-data 2>/dev/null || true

echo -e "${CYAN}[INFO]${NC} Removing bot and configuration directories..."
rm -rf /opt/incy-bot
rm -rf /etc/sing-box

echo -e "${GREEN}[OK]${NC} Uninstallation complete."
