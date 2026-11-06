#!/usr/bin/env bash
# ==============================================================================
# Incy-Bot & Sing-Box Automated Server Upgrade Script
# Safely upgrades production VPS to the latest hardened architecture:
# - Pre-flight backup creation & verification
# - Dedicated non-root user 'incy-bot' & privileged helper setup
# - Sudoers configuration with visudo syntax validation
# - Binary SRS ruleset download & magic bytes validation
# - Client templates and Sing-box permission configuration
# - Bot code update, venv sync, and systemd sandboxed service restart
# - Nginx privacy & timeout updates with 'nginx -t' pre-flight
# - Pinned Docker container update for Telegram Web Proxy
# - Automatic subscription migration for existing users
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC} $1"; }
ok()    { echo -e "${GREEN}[OK]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

if [ "$EUID" -ne 0 ]; then
    error "This upgrade script must be run as root."
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="/opt/incy-bot/.env"

echo ""
echo -e "${CYAN}${BOLD}═════════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}${BOLD}   🚀 Запуск обновления VPS: tgproxy-vpsvless-tgbot (Hardened)       ${NC}"
echo -e "${CYAN}${BOLD}═════════════════════════════════════════════════════════════════════${NC}"
echo ""

# 1. Pre-flight Checks & Environment Loading
if [ ! -f "$ENV_FILE" ]; then
    error "Файл конфигурации $ENV_FILE не найден! Убедитесь, что система была ранее установлена."
    exit 1
fi

info "Считывание текущей конфигурации из $ENV_FILE..."
# shellcheck disable=SC1090
source "$ENV_FILE"

MAIN_DOMAIN="${MAIN_DOMAIN:-}"
TG_DOMAIN="${TG_DOMAIN:-tg.$MAIN_DOMAIN}"
SUBS_PATH="${SUBS_PATH:-}"
VLESS_PATH="${VLESS_PATH:-}"
TROJAN_PATH="${TROJAN_PATH:-}"
RULESET_PATH="${RULESET_PATH:-}"

if [ -z "$MAIN_DOMAIN" ] || [ -z "$SUBS_PATH" ]; then
    error "Не удалось прочитать MAIN_DOMAIN или SUBS_PATH из $ENV_FILE."
    exit 1
fi

# Detect ruleset path if missing from .env
if [ -z "$RULESET_PATH" ]; then
    RULESET_PATH=$(grep -B 1 -E 'alias /var/www/' /etc/nginx/nginx.conf 2>/dev/null | grep 'location' | cut -d'/' -f2 || echo "")
    if [ -n "$RULESET_PATH" ]; then
        echo "RULESET_PATH=$RULESET_PATH" >> "$ENV_FILE"
    else
        RULESET_PATH="ruleset"
    fi
fi

WWW_DIR="/var/www/$SUBS_PATH"
RULESET_DIR="/var/www/$RULESET_PATH"

ok "Конфигурация подтверждена: Домен $MAIN_DOMAIN, подписки /$SUBS_PATH"

# 2. Automated Pre-Upgrade Snapshot Backup
info "Создание резервной копии перед обновлением..."
if [ -f "$SCRIPT_DIR/scripts/backup.sh" ]; then
    bash "$SCRIPT_DIR/scripts/backup.sh"
    ok "Резервная копия создана и верифицирована."
else
    warn "Скрипт scripts/backup.sh не найден, выполняется базовое архивирование..."
    mkdir -p /root/backups
    tar -czf "/root/backups/pre_upgrade_$(date +%s).tar.gz" /etc/sing-box /opt/incy-bot /etc/nginx/nginx.conf 2>/dev/null || true
fi

# 3. Create Dedicated Non-Root System User 'incy-bot'
if ! id -u incy-bot &>/dev/null; then
    info "Создание системного пользователя 'incy-bot'..."
    useradd -r -s /usr/sbin/nologin -d /opt/incy-bot -M incy-bot
    ok "Пользователь 'incy-bot' создан."
fi

# 4. Install Privileged Root Control Helper
info "Установка привилегированного хелпера /usr/local/bin/singbox-control..."
cp "$SCRIPT_DIR/scripts/singbox-control.sh" /usr/local/bin/singbox-control
chown root:root /usr/local/bin/singbox-control
chmod 755 /usr/local/bin/singbox-control
ok "Хелпер /usr/local/bin/singbox-control установлен."

# 5. Install & Validate Sudoers Rules
info "Обновление правил sudoers (/etc/sudoers.d/incy-bot)..."
cp "$SCRIPT_DIR/config/sudoers/incy-bot.sudoers" /etc/sudoers.d/incy-bot
chmod 440 /etc/sudoers.d/incy-bot
if command -v visudo >/dev/null 2>&1; then
    if ! visudo -cf /etc/sudoers.d/incy-bot >/dev/null; then
        error "Синтаксическая ошибка в sudoers! Откат изменений."
        rm -f /etc/sudoers.d/incy-bot
        exit 1
    fi
fi
ok "Правила sudoers валидированы и применены."

# 6. Update Sing-Box & Subscriptions Permissions
info "Настройка прав доступа к файлам Sing-Box и директории подписок..."
mkdir -p /etc/sing-box "$WWW_DIR" "$RULESET_DIR"
chown root:incy-bot /etc/sing-box
chmod 775 /etc/sing-box
chown sing-box:incy-bot /etc/sing-box/config.json 2>/dev/null || chown root:incy-bot /etc/sing-box/config.json 2>/dev/null || true
chmod 660 /etc/sing-box/config.json 2>/dev/null || true

chown -R incy-bot:www-data "$WWW_DIR"
chmod 770 "$WWW_DIR"
ok "Права на конфигурацию и директорию подписок настроены."

# 7. Update Binary SRS Rulesets
info "Загрузка и валидация бинарных правил маршрутизации Sing-Box (.srs)..."
if [ -f "$SCRIPT_DIR/scripts/download-rulesets.sh" ]; then
    bash "$SCRIPT_DIR/scripts/download-rulesets.sh" "$RULESET_DIR"
    chown -R www-data:www-data "$RULESET_DIR"
    chmod -R 755 "$RULESET_DIR"
    ok "Бинарные правила SRS успешно обновлены и проверены."
fi

# 8. Update Client Templates
info "Обновление шаблонов профилей клиентов..."
sed -e "s|{{DOMAIN}}|$MAIN_DOMAIN|g" \
    -e "s|{{SUBS_PATH}}|$SUBS_PATH|g" \
    -e "s|{{RULESET_PATH}}|$RULESET_PATH|g" \
    -e "s|{{VLESS_PATH}}|$VLESS_PATH|g" \
    "$SCRIPT_DIR/config/templates/template-vless.json" > /opt/incy-bot/template-vless.json

sed -e "s|{{DOMAIN}}|$MAIN_DOMAIN|g" \
    -e "s|{{SUBS_PATH}}|$SUBS_PATH|g" \
    -e "s|{{RULESET_PATH}}|$RULESET_PATH|g" \
    -e "s|{{TROJAN_PATH}}|$TROJAN_PATH|g" \
    "$SCRIPT_DIR/config/templates/template-trj.json" > /opt/incy-bot/template-trj.json

chown incy-bot:incy-bot /opt/incy-bot/template-*.json
chmod 644 /opt/incy-bot/template-*.json
ok "Шаблоны клиентов обновлены с учётом OR-маршрутизации."

# 9. Update Bot Code & Python Dependencies
info "Обновление кода Telegram-бота..."
cp "$SCRIPT_DIR/bot/bot.py" \
   "$SCRIPT_DIR/bot/auth.py" \
   "$SCRIPT_DIR/bot/config_manager.py" \
   "$SCRIPT_DIR/bot/subscription_manager.py" \
   /opt/incy-bot/

if [ -f /opt/incy-bot/venv/bin/pip ]; then
    info "Проверка и установка зависимостей Python..."
    /opt/incy-bot/venv/bin/pip install --upgrade pip >/dev/null 2>&1 || true
    /opt/incy-bot/venv/bin/pip install -r "$SCRIPT_DIR/bot/requirements.txt" >/dev/null 2>&1 || true
fi

# Ensure subscriptions.json registry exists
if [ ! -f /opt/incy-bot/subscriptions.json ]; then
    echo "{}" > /opt/incy-bot/subscriptions.json
fi

chown -R incy-bot:incy-bot /opt/incy-bot
chown root:incy-bot /opt/incy-bot/.env
chmod 640 /opt/incy-bot/.env
chmod 600 /opt/incy-bot/subscriptions.json

# 10. Update Systemd Unit & Restart Bot
info "Обновление сервиса systemd incy-bot..."
cp "$SCRIPT_DIR/bot/incy-bot.service" /etc/systemd/system/incy-bot.service
systemctl daemon-reload
systemctl restart incy-bot.service
sleep 2

if ! systemctl is-active --quiet incy-bot.service; then
    error "Сервис incy-bot не запустился! Проверьте: journalctl -u incy-bot -n 30"
    exit 1
fi
ok "Сервис incy-bot успешно перезапущен с изоляцией прав."

# 11. Update Nginx Configuration
info "Проверка и обновление настроек Nginx..."
if [ -f "$SCRIPT_DIR/config/nginx/nginx.conf.template" ]; then
    sed -e "s|{{DOMAIN}}|$MAIN_DOMAIN|g" \
        -e "s|{{TG_DOMAIN}}|$TG_DOMAIN|g" \
        -e "s|{{SUBS_PATH}}|$SUBS_PATH|g" \
        -e "s|{{RULESET_PATH}}|$RULESET_PATH|g" \
        -e "s|{{TROJAN_PATH}}|$TROJAN_PATH|g" \
        -e "s|{{VLESS_PATH}}|$VLESS_PATH|g" \
        "$SCRIPT_DIR/config/nginx/nginx.conf.template" > /etc/nginx/nginx.conf.new

    if nginx -t -c /etc/nginx/nginx.conf.new >/dev/null 2>&1; then
        mv /etc/nginx/nginx.conf.new /etc/nginx/nginx.conf
        systemctl reload nginx
        ok "Конфигурация Nginx обновлена (privacy_audit, persistent ws timeouts, so_keepalive)."
    else
        warn "Сгенерированный файл Nginx не прошёл проверку синтаксиса, рабочий конфиг оставлен без изменений."
        rm -f /etc/nginx/nginx.conf.new
    fi
fi

# 12. Update Docker Container for Telegram Web Proxy (Pinned Image)
if command -v docker >/dev/null 2>&1; then
    info "Обновление Telegram Web Proxy до зафиксированного digest..."
    PINNED_IMAGE="grayhoax/telegram-web-proxy:sha-959b1b5@sha256:5bb3a55cdee2959482f69e24e4c202d52b378968d85e18cd645c2095739ecb45"
    if docker ps -a --format '{{.Names}}' | grep -q "^tgweb-proxy$"; then
        docker pull "$PINNED_IMAGE" >/dev/null 2>&1 || true
        docker stop tgweb-proxy >/dev/null 2>&1 || true
        docker rm tgweb-proxy >/dev/null 2>&1 || true

        docker run -d --name tgweb-proxy --restart unless-stopped \
            -p 127.0.0.1:8080:8080 \
            -e "TPROXY_HOSTNAME=$TG_DOMAIN" \
            -e "TLS_MODE=off" \
            -e "TRUSTED_PROXIES=private_ranges" \
            -v tgweb-data:/data \
            --cap-drop ALL --cap-add CHOWN --cap-add SETUID --cap-add SETGID --cap-add KILL \
            --security-opt no-new-privileges \
            "$PINNED_IMAGE" >/dev/null

        sleep 2
        if [ -f "$SCRIPT_DIR/site/tg/index.html" ]; then
            docker cp "$SCRIPT_DIR/site/tg/index.html" tgweb-proxy:/run/tgweb/site/index.html 2>/dev/null || true
        fi
        ok "Telegram Web Proxy обновлён и запущен."
    fi
fi

# 13. Update Automated Backup Utility
info "Обновление утилиты резервного копирования /usr/local/bin/backup-vps..."
if [ -f "$SCRIPT_DIR/scripts/backup.sh" ]; then
    cp "$SCRIPT_DIR/scripts/backup.sh" /usr/local/bin/backup-vps
    chown root:root /usr/local/bin/backup-vps
    chmod 700 /usr/local/bin/backup-vps
    ok "Утилита /usr/local/bin/backup-vps обновлена (Path Traversal protection, verify, restore)."
fi

# 14. Verify Sing-Box Health
info "Проверка состояния ядра Sing-Box..."
if /usr/local/bin/singbox-control check /etc/sing-box/config.json >/dev/null 2>&1; then
    /usr/local/bin/singbox-control reload >/dev/null 2>&1 || true
    ok "Sing-Box проверен и активен."
else
    warn "Предупреждение: Проверьте конфигурацию Sing-Box: sing-box check -c /etc/sing-box/config.json"
fi

echo ""
echo -e "${GREEN}${BOLD}═════════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}    🎉 Обновление сервера успешно завершено!                         ${NC}"
echo -e "${GREEN}${BOLD}═════════════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Статус сервисов:"
echo "  • Telegram Bot (incy-bot): $(systemctl is-active incy-bot.service)"
echo "  • Sing-Box Core:           $(systemctl is-active sing-box.service)"
echo "  • Nginx Web Server:        $(systemctl is-active nginx.service)"
if command -v docker >/dev/null 2>&1; then
echo "  • Telegram Web Proxy:      $(docker inspect -f '{{.State.Status}}' tgweb-proxy 2>/dev/null || echo 'inactive')"
fi
echo ""
echo "Логи автоматической миграции пользователей:"
journalctl -u incy-bot -n 15 --no-pager | grep -iE '(migrat|token|start)' || true
echo ""
