#!/usr/bin/env bash
set -euo pipefail

echo "Configuring UFW firewall..."
ufw default deny incoming
ufw default allow outgoing

# Allow essential ports only
ufw allow 22/tcp comment 'SSH'
ufw allow 80/tcp comment 'HTTP (Let'\''s Encrypt)'
ufw allow 443/tcp comment 'HTTPS (Sing-Box & Telegram Web Proxy)'
ufw allow 8443/tcp comment 'Xray REALITY Vision'
ufw allow 8444/tcp comment 'Xray REALITY XHTTP'

# Enable UFW non-interactively
ufw --force enable
ufw status verbose
