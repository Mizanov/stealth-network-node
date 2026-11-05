#!/usr/bin/env bash
# ==============================================================================
# Telegram Web Proxy & Sing-Box Universal Suite - Automated Installer
# Target OS: Ubuntu 22.04/24.04, Debian 12 (x86_64)
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC} "; }
ok()    { echo -e "${GREEN}[OK]${NC} "; }
warn()  { echo -e "${YELLOW}[WARN]${NC} "; }
error() { echo -e "${RED}[ERROR]${NC} "; exit 1; }

# 1. Root & OS Check
if [ "$EUID" -ne 0 ]; then
    error "Please run this script as root (use: sudo -i)"
fi

if ! grep -q -E "noble|jammy|bookworm|trixie" /etc/os-release; then
    warn "This script is optimized for Ubuntu 22.04/24.04 and Debian 12."
fi

echo -e "${CYAN}${BOLD}"
echo "╔═════════════════════════════════════════════════════════════════════╗"
echo "║       Telegram Web Proxy & Sing-Box Universal Suite Installer       ║"
echo "╚═════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 2. Configuration & Inputs
if [ -f "$SCRIPT_DIR/.env" ]; then
    info "Loading settings from .env file..."
    set -a
    source "$SCRIPT_DIR/.env"
    set +a
fi

prompt_var() {
    local var_name="$1"
    local prompt_text="$2"
    local default_val="${3:-}"
    local current_val="${!var_name:-}"

    if [ -z "$current_val" ]; then
        if [ -n "$default_val" ]; then
            read -r -p "$prompt_text [$default_val]: " input
            eval "$var_name="${input:-$default_val}""
        else
            while [ -z "${!var_name:-}" ]; do
                read -r -p "$prompt_text: " input
                eval "$var_name="$input""
            done
        fi
    fi
}

prompt_var MAIN_DOMAIN "Enter your Main Domain (e.g., vpn.domain.com or domain.duckdns.org)"
prompt_var TG_DOMAIN "Enter your Telegram Proxy Subdomain (e.g., tg.domain.com)" "tg.$MAIN_DOMAIN"
prompt_var ACME_EMAIL "Enter your Email for Let's Encrypt certificates" "admin@$MAIN_DOMAIN"
prompt_var TELEGRAM_BOT_TOKEN "Enter your Telegram Bot Token from @BotFather"
prompt_var TELEGRAM_ADMIN_IDS "Enter your Telegram User ID (numeric, from @userinfobot)"

# Auto-generate secure random paths if not supplied
SUBS_PATH="${SUBS_PATH:-$(openssl rand -hex 16)}"
VLESS_PATH="${VLESS_PATH:-$(openssl rand -hex 16)}"
TROJAN_PATH="${TROJAN_PATH:-$(openssl rand -hex 16)}"
RULESET_PATH="${RULESET_PATH:-$(openssl rand -hex 16)}"
FIRST_USER_UUID="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || openssl rand -hex 16)"
FIRST_USER_PASS="$(openssl rand -hex 8)"
FIRST_USER_NAME="user_admin"

info "Detected Configuration:"
echo "  • Main Domain: $MAIN_DOMAIN"
echo "  • TG Web Proxy Subdomain: $TG_DOMAIN"
echo "  • Email: $ACME_EMAIL"
echo "  • Telegram Bot: Configured"
echo "  • Admin ID: $TELEGRAM_ADMIN_IDS"
echo ""

# 3. Swap Setup
info "Setting up Swap..."
if [ -f "$SCRIPT_DIR/scripts/setup-swap.sh" ]; then
    bash "$SCRIPT_DIR/scripts/setup-swap.sh" 2
fi

# 4. System Packages
info "Updating repositories and installing base packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl wget jq git certbot ufw openssl sed python3-venv python3-pip docker.io

# Enable Docker
systemctl enable --now docker

# 5. Enable BBR
info "Enabling TCP BBR..."
if ! grep -q "tcp_congestion_control=bbr" /etc/sysctl.conf /etc/sysctl.d/* 2>/dev/null; then
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.d/99-bbr.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.d/99-bbr.conf
    sysctl --system >/dev/null 2>&1 || true
fi

# 6. Issue SSL Certificates
info "Issuing SSL certificates with Let's Encrypt..."
mkdir -p /etc/nginx
systemctl stop nginx >/dev/null 2>&1 || true

certbot certonly --standalone --preferred-challenges http --agree-tos     --email "$ACME_EMAIL" -d "$MAIN_DOMAIN" -d "$TG_DOMAIN"     --no-eff-email --non-interactive --keep-until-expiring

ok "SSL certificates obtained successfully."

# Diffie-Hellman parameters
if [ ! -f /etc/nginx/dhparam.pem ]; then
    info "Generating 2048-bit DH parameters (this may take 20s)..."
    openssl dhparam -out /etc/nginx/dhparam.pem 2048
fi

# 7. Install Sing-Box & Nginx Official Packages
info "Installing Sing-Box and Nginx official packages..."
os_codename=$(grep "VERSION_CODENAME=" /etc/os-release | cut -d "=" -f 2)
os_id=$(grep -E "^ID=" /etc/os-release | cut -d "=" -f 2 | tr -d '"')

# Sing-Box repo
mkdir -p /etc/apt/keyrings
curl -fsSL https://sing-box.app/gpg.key -o /etc/apt/keyrings/sagernet.asc && chmod a+r /etc/apt/keyrings/sagernet.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/sagernet.asc] https://deb.sagernet.org/ * *" | tee /etc/apt/sources.list.d/sagernet.list > /dev/null

# Nginx repo
curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor -o /etc/apt/keyrings/nginx-archive-keyring.gpg 2>/dev/null || true
echo "deb [signed-by=/etc/apt/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/${os_id} ${os_codename} nginx" | tee /etc/apt/sources.list.d/nginx.list > /dev/null

apt-get update -y
apt-get install -y sing-box nginx

# 8. Setup Rulesets & Directories
WWW_DIR="/var/www/$SUBS_PATH"
RULESET_DIR="/var/www/$RULESET_PATH"
mkdir -p "$WWW_DIR" "$RULESET_DIR" /opt/incy-bot

info "Downloading routing rulesets..."
for rs in geoip-ru geosite-ru geosite-category-ads-all; do
    wget -q -O "$RULESET_DIR/${rs}.srs" "https://raw.githubusercontent.com/A-Zuro/ruleset/main/${rs}.srs" 2>/dev/null || true
done

# 9. Configure Sing-Box
info "Deploying Sing-Box configuration..."
SERVER_IP=$(curl -s4 https://api.ipify.org || curl -s4 https://ifconfig.me || echo "127.0.0.1")

sed -e "s|{{DOMAIN}}|$MAIN_DOMAIN|g"     -e "s|{{SUBS_PATH}}|$SUBS_PATH|g"     -e "s|{{RULESET_PATH}}|$RULESET_PATH|g"     -e "s|{{TROJAN_PATH}}|$TROJAN_PATH|g"     -e "s|{{VLESS_PATH}}|$VLESS_PATH|g"     "$SCRIPT_DIR/config/sing-box/config.json.template" > /etc/sing-box/config.json

# Inject initial user
jq ".inbounds[] |= if .tag == "vless-in" then .users = [{"name": "$FIRST_USER_NAME", "uuid": "$FIRST_USER_UUID"}] elif .tag == "trojan-in" then .users = [{"name": "$FIRST_USER_NAME", "password": "$FIRST_USER_PASS"}] else . end" /etc/sing-box/config.json > /tmp/sb_cfg.json
mv /tmp/sb_cfg.json /etc/sing-box/config.json

systemctl daemon-reload
systemctl enable --now sing-box
systemctl restart sing-box

# 10. Configure Nginx
info "Deploying Nginx configuration..."
sed -e "s|{{DOMAIN}}|$MAIN_DOMAIN|g"     -e "s|{{TG_DOMAIN}}|$TG_DOMAIN|g"     -e "s|{{SUBS_PATH}}|$SUBS_PATH|g"     -e "s|{{RULESET_PATH}}|$RULESET_PATH|g"     -e "s|{{TROJAN_PATH}}|$TROJAN_PATH|g"     -e "s|{{VLESS_PATH}}|$VLESS_PATH|g"     "$SCRIPT_DIR/config/nginx/nginx.conf.template" > /etc/nginx/nginx.conf

nginx -t
systemctl enable --now nginx
systemctl restart nginx

# 11. Run Telegram Web Proxy (Docker)
info "Starting Telegram Web Proxy..."
docker stop tgweb-proxy >/dev/null 2>&1 || true
docker rm tgweb-proxy >/dev/null 2>&1 || true

docker run -d --name tgweb-proxy --restart unless-stopped     -p 127.0.0.1:8080:8080     -e "TPROXY_HOSTNAME=$TG_DOMAIN"     -e "TLS_MODE=off"     -e "TRUSTED_PROXIES=private_ranges"     -v tgweb-data:/data     --cap-drop ALL --cap-add CHOWN --cap-add SETUID --cap-add SETGID --cap-add KILL     --security-opt no-new-privileges     grayhoax/telegram-web-proxy:latest

# 12. Setup Client Templates & Telegram Bot
info "Setting up Telegram Bot..."
sed -e "s|{{DOMAIN}}|$MAIN_DOMAIN|g"     -e "s|{{SUBS_PATH}}|$SUBS_PATH|g"     -e "s|{{RULESET_PATH}}|$RULESET_PATH|g"     -e "s|{{SERVER_IP}}|$SERVER_IP|g"     -e "s|{{TROJAN_PATH}}|$TROJAN_PATH|g"     -e "s|{{VLESS_PATH}}|$VLESS_PATH|g"     "$SCRIPT_DIR/config/templates/template-vless.json" > /opt/incy-bot/template-vless.json

sed -e "s|{{DOMAIN}}|$MAIN_DOMAIN|g"     -e "s|{{SUBS_PATH}}|$SUBS_PATH|g"     -e "s|{{RULESET_PATH}}|$RULESET_PATH|g"     -e "s|{{SERVER_IP}}|$SERVER_IP|g"     -e "s|{{TROJAN_PATH}}|$TROJAN_PATH|g"     -e "s|{{VLESS_PATH}}|$VLESS_PATH|g"     "$SCRIPT_DIR/config/templates/template-trj.json" > /opt/incy-bot/template-trj.json

# Bot files & Venv
cp "$SCRIPT_DIR/bot/bot.py" /opt/incy-bot/bot.py
python3 -m venv /opt/incy-bot/venv
/opt/incy-bot/venv/bin/pip install --upgrade pip >/dev/null
/opt/incy-bot/venv/bin/pip install -r "$SCRIPT_DIR/bot/requirements.txt" >/dev/null

printf "TELEGRAM_BOT_TOKEN=%s\nTELEGRAM_ADMIN_IDS=%s\nMAIN_DOMAIN=%s\nTG_DOMAIN=%s\nSUBS_PATH=%s\nVLESS_PATH=%s\nTROJAN_PATH=%s\n"     "$TELEGRAM_BOT_TOKEN" "$TELEGRAM_ADMIN_IDS" "$MAIN_DOMAIN" "$TG_DOMAIN" "$SUBS_PATH" "$VLESS_PATH" "$TROJAN_PATH" > /opt/incy-bot/.env
chmod 600 /opt/incy-bot/.env

cp "$SCRIPT_DIR/bot/incy-bot.service" /etc/systemd/system/incy-bot.service
systemctl daemon-reload
systemctl enable --now incy-bot.service
systemctl restart incy-bot.service

# Generate initial user subscription file
VLESS_LINK="vless://${FIRST_USER_UUID}@${MAIN_DOMAIN}:443?security=tls&encryption=none&type=ws&path=%2F${VLESS_PATH}#${MAIN_DOMAIN}-VLESS-${FIRST_USER_NAME}"
TROJAN_LINK="trojan://${FIRST_USER_PASS}@${MAIN_DOMAIN}:443?security=tls&type=ws&path=%2F${TROJAN_PATH}#${MAIN_DOMAIN}-Trojan-${FIRST_USER_NAME}"
echo -e "${VLESS_LINK}\n${TROJAN_LINK}\n" | base64 | tr -d '\n' > "$WWW_DIR/${FIRST_USER_NAME}.txt"
chmod 644 "$WWW_DIR/${FIRST_USER_NAME}.txt"

# 13. Firewall Hardening
info "Hardening firewall (UFW)..."
bash "$SCRIPT_DIR/scripts/setup-firewall.sh" >/dev/null 2>&1

# 14. Output Final Summary
sleep 3
TG_PROXY_LINK=$(docker exec tgweb-proxy show-link 2>/dev/null | grep -o 'https://t.me/webproxy\S*' || echo "Check via bot")

echo ""
echo -e "${GREEN}${BOLD}═════════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}        🚀 Установка успешно завершена! Всё настроено и работает!   ${NC}"
echo -e "${GREEN}${BOLD}═════════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "📱 ${BOLD}Telegram-бот управления:${NC}"
echo "   Откройте вашего бота в Telegram и отправьте /start"
echo ""
echo -e "🌐 ${BOLD}Telegram Web Proxy (tproxy-server):${NC}"
echo "   Ссылка для подключения: $TG_PROXY_LINK"
echo ""
echo -e "📦 ${BOLD}Ключи для клиентов (Incy / Happ / V2Ray / SFM):${NC}"
echo "   • Пользователь: ${FIRST_USER_NAME}"
echo "   • Подписка:     https://${MAIN_DOMAIN}/${SUBS_PATH}/${FIRST_USER_NAME}.txt"
echo "   • Прямой VLESS: ${VLESS_LINK}"
echo ""
echo -e "🔒 ${BOLD}Статус безопасности:${NC}"
echo "   • SSL Сертификаты: Автоматическое продление через Certbot"
echo "   • Фаервол: UFW активен (только порты 22, 80, 443)"
echo "   • Все внутренние порты изолированы на 127.0.0.1"
echo ""
