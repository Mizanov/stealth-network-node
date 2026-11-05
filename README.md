<div align="center">

# 🚀 Telegram Web Proxy & Sing-Box Incy Suite

Готовое решение «под ключ» для развёртывания на чистом VPS: **Secret-Sing-Box** (VLESS / Trojan поверх WebSocket с TLS), официальный **Telegram Web Proxy** (`tproxy-server`) и персональный **Telegram-бот** для автоматической генерации ключей и подписок под клиент **Incy**.

[![Ubuntu 22.04+](https://img.shields.io/badge/Ubuntu-22.04%20%7C%2024.04-orange?logo=ubuntu)](https://ubuntu.com)
[![Debian 12](https://img.shields.io/badge/Debian-12-red?logo=debian)](https://debian.org)
[![Sing-Box](https://img.shields.io/badge/Sing--Box-Core-blue?logo=box)](https://sing-box.sagernet.org)
[![Docker](https://img.shields.io/badge/Docker-Enabled-2496ED?logo=docker)](https://docker.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

---

## 🌟 Ключевые возможности

* **Нативная поддержка клиента [Incy](https://incy.app)**:
  * Генерация универсальных **Base64-подписок** (`.txt`) с поддержкой заголовков `subscription-userinfo` (срок и трафик) и `profile-update-interval` (автообновление).
  * Поддержка однокликовых диплинков `incy://add/...`.
  * Прямые ссылки `vless://` и автоматическая генерация **QR-кодов** для сканирования камерой в приложении.
  * Полные `.json` профили для оригинального ядра Sing-Box с преднастроенными правилами обхода блокировок (AntiZapret, GeoIP, GeoSite).
* **Официальный Telegram Web Proxy ([tproxy-server](https://github.com/telegramdesktop/tproxy-server))**:
  * Новый стандарт веб-прокси Telegram от команды Telegram Desktop.
  * Трафик маскируется под легитимный HTTPS-сайт через WebSocket/HTTPS.
  * Автоматическая изоляция в Docker и проксирование через Nginx.
* **Умный Telegram-бот управления**:
  * Быстрая выдача ключей командой `/new <имя>` или кнопкой меню.
  * Управление списком пользователей (`/list`, `/del`).
  * Мониторинг состояния сервера (`/status` — Sing-Box, Nginx, Docker, CPU, RAM, диск).
  * Выдача ссылки на Telegram Web Proxy в 1 клик.
* **Высокий уровень безопасности и отказоустойчивости**:
  * **Автоматический фаервол UFW**: открыты строго порты `22`, `80`, `443`. Внутренние порты (10443, 11443, 8080, 2398) привязаны строго к `127.0.0.1`.
  * **Rate Limiting в Nginx**: защита пути подписок от сканирования и брутфорса (`limit_req_zone rate=60r/m`).
  * **Защита доступа к боту**: строгий whitelist по Telegram User ID (`TELEGRAM_ADMIN_IDS`).
  * **Изолированные шаблоны**: системные шаблоны защищены в `/opt/incy-bot/` — удаление всех пользователей не ломает возможность генерировать новые ключи.
  * **TCP BBR + 2GB Swap**: оптимизация сети и защита от нехватки памяти (OOM Killer).
  * **Let's Encrypt**: автоматический выпуск и автопродление TLS-сертификатов через Certbot.

---

## 📐 Архитектура системы

```text
                           ИНТЕРНЕТ
                              │
                  ┌───────────┴───────────┐
                  │ Порты 80, 443 (HTTPS) │
                  └───────────┬───────────┘
                              ▼
                      [ NGINX ФРОНТЕНД ]
           (SSL-сертификаты Let's Encrypt / HSTS / TLS 1.3)
                              │
     ┌────────────────────────┼────────────────────────┐
     │ SNI: vpn.domain.com    │ SNI: tg.domain.com     │ Любой другой хост
     ▼                        ▼                        ▼
[ Sing-Box Core ]       [ Docker: tgweb-proxy ]   [ 403 Forbidden ]
  ├─ :11443 VLESS (ws)    └─ :8080 Caddy/tproxy
  ├─ :10443 Trojan (ws)        └─ :2398 MTProxy
  └─ Подписки /var/www/        └─ Обложечный сайт
```

---

## 📋 Системные требования

* **ОС**: Ubuntu 22.04 LTS / 24.04 LTS или Debian 12 (архитектура `x86_64` / `amd64`).
* **Права**: `root` доступ.
* **Доменное имя**:
  * Настроенная DNS A-запись основного домена на IP сервера (например, `vpn.example.com`).
  * Настроенная DNS A-запись поддомена для Telegram Proxy (например, `tg.example.com`).
  * *Либо бесплатный домен DuckDNS с поддержкой wildcard (например, `yourname.duckdns.org` и `tg.yourname.duckdns.org`).*
* **Telegram Bot Token**:
  * Создайте бота через [@BotFather](https://t.me/BotFather) и скопируйте API Token.
* **Ваш Telegram ID**:
  * Узнайте ваш цифровой ID через [@userinfobot](https://t.me/userinfobot) (для авторизации в боте).

---

## 🚀 Быстрый старт (Установка)

### 1. Подключитесь к вашему серверу по SSH
```bash
ssh root@YOUR_SERVER_IP
```

### 2. Клонируйте репозиторий
```bash
git clone https://github.com/Mizanov/telegram-web-proxy.git /opt/telegram-web-proxy
cd /opt/telegram-web-proxy
```

### 3. Запустите автоматический установщик
```bash
chmod +x install.sh
./install.sh
```

Установщик интерактивно спросит:
1. **Main Domain**: ваш основной домен (например, `vpn.example.com` или `myname.duckdns.org`).
2. **Telegram Subdomain**: поддомен для Web Proxy (например, `tg.example.com` или `tg.myname.duckdns.org`).
3. **Email**: почта для выпуска SSL-сертификатов Let's Encrypt.
4. **Telegram Bot Token**: токен, полученный от `@BotFather`.
5. **Telegram Admin ID**: ваш цифровой ID от `@userinfobot`.

> 💡 **Автоматический режим без диалога:**
> Вы можете заранее скопировать `.env.example` в `.env`, заполнить все поля и запустить `./install.sh` — скрипт применит настройки без лишних вопросов.

---

## 📱 Использование

### 1. Управление через Telegram-бота

Откройте вашего бота в Telegram и отправьте `/start`. Вам будет доступно удобное кнопочное меню:

* **`➕ Создать ключ Incy`** или команда `/new <имя>`:
  * Бот мгновенно сгенерирует уникальный UUID и конфиг.
  * Пришлёт **QR-код** (для мгновенного сканирования камерой в Incy).
  * Ссылку на подписку Incy (`https://.../<user>.txt`).
  * Диплинк в один тап `incy://add/...`.
  * Прямую строку `vless://...`.
* **`👥 Список ключей`** или команда `/list`:
  * Список всех пользователей с кнопками информации и удаления.
* **`🌐 Telegram Web Proxy`** или команда `/proxy`:
  * Получение ссылки и кнопки для подключения Telegram Web Proxy в один клик.
* **`📊 Статус сервера`** или команда `/status`:
  * Мониторинг служб Sing-Box, Nginx, Docker-контейнера прокси, памяти и диска.

### 2. Подключение в приложении Incy

1. Установите **Incy** ([App Store](https://apps.apple.com) / [Google Play](https://play.google.com) / [GitHub](https://github.com)).
2. **Вариант А (самый быстрый):** Нажмите **«+» ➔ «Сканировать QR-код»** и наведите камеру на QR-код из сообщения бота. Сервер добавится мгновенно.
3. **Вариант Б (подписка с автообновлением):** Скопируйте ссылку на подписку (`.txt`) из бота, откройте Incy ➔ «Подписки» ➔ «Добавить» ➔ Вставьте ссылку. Узлы загрузятся и будут автоматически обновляться.

### 3. Подключение Telegram Web Proxy

1. Отправьте боту команду `/proxy` (или нажмите кнопку «🌐 Telegram Web Proxy»).
2. Нажмите на кнопку **«🚀 Подключить в Telegram»** (или перейдите по ссылке `https://t.me/webproxy?server=...&secret=...`).
3. В клиенте Telegram нажмите **«Включить прокси»**.

---

## 🛠 Обслуживание и команды

```bash
# Проверка статуса всех компонентов
systemctl status sing-box nginx incy-bot
docker ps

# Просмотр логов Telegram-бота
journalctl -u incy-bot.service -f

# Просмотр логов ядра Sing-Box
journalctl -u sing-box -f

# Получить текущую ссылку Telegram Web Proxy из консоли
docker exec tgweb-proxy show-link

# Перезапуск сервисов при необходимости
systemctl restart sing-box nginx incy-bot
docker restart tgweb-proxy
```

---

## 🗑 Удаление

Если вам потребуется полностью удалить все компоненты с сервера:

```bash
cd /opt/telegram-web-proxy
chmod +x uninstall.sh
./uninstall.sh
```

Скрипт корректно остановит и удалит контейнер `tgweb-proxy`, удалит службы `incy-bot` и Sing-Box, очистит файлы конфигураций и веб-директории.

---

## 📄 Лицензия

Проект распространяется под открытой лицензией [MIT](LICENSE).
