<div align="center">

# 🚀 tgproxy-vpsvless-tgbot

### Telegram Web Proxy & Sing-Box Universal Suite (Incy, Happ, V2Ray, SFM)

Готовое решение «под ключ» для развёртывания на чистом VPS: **Secret-Sing-Box** (VLESS / Trojan поверх WebSocket с TLS), официальный **Telegram Web Proxy** (`tproxy-server`) и персональный **Telegram-бот** для автоматической генерации ключей и универсальных подписок для **Incy, Happ, Sing-Box (SFM/SFI), v2rayN / v2rayNG, Streisand, Shadowrocket** и других современных клиентов.

[![Ubuntu 22.04+](https://img.shields.io/badge/Ubuntu-22.04%20%7C%2024.04-orange?logo=ubuntu)](https://ubuntu.com)
[![Debian 12](https://img.shields.io/badge/Debian-12-red?logo=debian)](https://debian.org)
[![Sing-Box](https://img.shields.io/badge/Sing--Box-Core-blue?logo=box)](https://sing-box.sagernet.org)
[![Docker](https://img.shields.io/badge/Docker-Enabled-2496ED?logo=docker)](https://docker.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

---

## 🌟 Ключевые возможности

* **Универсальные ключи и подписки для всех клиентов ([Incy](https://incy.app), [Happ](https://github.com), [Sing-Box](https://sing-box.sagernet.org), v2rayN/v2rayNG, Shadowrocket, Streisand)**:
  * Генерация универсальных **Base64-подписок** (`.txt`) с поддержкой заголовков `subscription-userinfo` (срок и трафик) и `profile-update-interval` (автообновление).
  * Прямые ссылки `vless://` и `trojan://` с возможностью быстрого копирования в один клик.
  * Автоматическая генерация **QR-кодов** для мгновенного сканирования камерой в любом мобильном приложении.
  * Чистые `.json` профили для оригинального ядра Sing-Box с преднастроенными правилами обхода блокировок (AntiZapret, GeoIP, GeoSite).
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
git clone https://github.com/Mizanov/tgproxy-vpsvless-tgbot.git /opt/tgproxy-vpsvless-tgbot
cd /opt/tgproxy-vpsvless-tgbot
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

* **`➕ Создать ключ`** или команда `/new <имя>`:
  * Бот мгновенно сгенерирует уникальный UUID и конфиг.
  * Пришлёт **QR-код** (для мгновенного сканирования камерой в любом мобильном клиенте).
  * Ссылку на универсальную подписку (`https://.../<user>.txt`).
  * Прямую строку `vless://...` (копируется в один клик).
  * Ссылку на полный `.json` профиль для Sing-Box.
* **`👥 Список ключей`** или команда `/list`:
  * Список всех пользователей с кнопками информации и удаления.
* **`🌐 Telegram Web Proxy`** или команда `/proxy`:
  * Получение ссылки и кнопки для подключения Telegram Web Proxy в один клик.
* **`📊 Статус сервера`** или команда `/status`:
  * Мониторинг служб Sing-Box, Nginx, Docker-контейнера прокси, памяти и диска.

### 2. Подключение в клиентских приложениях

Сгенерированные ботом ссылки и подписки поддерживаются всеми популярными клиентами:

* **Incy / Happ (iOS, Android)**:
  * **Вариант А (самый быстрый):** Нажмите **«+» ➔ «Сканировать QR-код»** и наведите камеру на QR-код из сообщения бота. Узел добавится мгновенно.
  * **Вариант Б (подписка с автообновлением):** Скопируйте ссылку на подписку (`.txt`) из бота, откройте приложение ➔ «Подписки» ➔ «Добавить» ➔ Вставьте ссылку. Узлы загрузятся и будут автоматически обновляться при изменениях на сервере.
* **Sing-Box / SFM / SFI (macOS, iOS, Windows, Android)**:
  * Импортируйте ссылку на подписку (`.txt`) через пункт «Profiles» / «Add Remote Profile» либо загрузите готовый `.json` файл.
* **v2rayN (Windows) / v2rayNG (Android)**:
  * Скопируйте `vless://` строку из сообщения бота ➔ нажмите «Импорт из буфера обмена» (Ctrl+V в v2rayN или значок «+» в v2rayNG), либо добавьте ссылку подписки.
* **Streisand / FoXray / Shadowrocket / Karing (iOS, macOS, Android)**:
  * Нажмите «+» ➔ добавьте ссылку подписки (тип: Base64 / V2Ray) или отсканируйте QR-код.

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
cd /opt/tgproxy-vpsvless-tgbot
chmod +x uninstall.sh
./uninstall.sh
```

Скрипт корректно остановит и удалит контейнер `tgweb-proxy`, удалит службы `incy-bot` и Sing-Box, очистит файлы конфигураций и веб-директории.

---

## 📄 Лицензия

Проект распространяется под открытой лицензией [MIT](LICENSE).
