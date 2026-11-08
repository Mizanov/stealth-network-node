<div align="center">

# 🚀 Multi-Transport Stealth VPN Node

### 🛡️ Xray REALITY Vision & XHTTP | Sing-Box Hysteria 2 Salamander & WS TLS | Dedicated Telegram Bot

Готовое решение «под ключ» для развёртывания на чистом VPS: легковесный (<120 МБ RAM, без Docker), мультитранспортный современный VPN на базе **Xray-Core** (высокоскоростной **VLESS + REALITY + Vision**, анти-DPI **VLESS + XHTTP + REALITY** с защитой **Self-SNI**), **Sing-Box** (скоростной **Hysteria 2** с обфускацией **Salamander** на порту **443 UDP**, legacy VLESS / Trojan WS + TLS), сайт-маскировка портфолио инженера (HTTP 200 OK) и персональный **Telegram-бот** для автоматической генерации ключей и универсальных подписок (5 в 1) для **Incy, Happ, Sing-Box, Shadowrocket, v2rayN / v2rayNG, Streisand, Surge, Hiddify, Nekobox** и других современных клиентов.

[![Ubuntu 22.04+](https://img.shields.io/badge/Ubuntu-22.04%20%7C%2024.04-orange?logo=ubuntu)](https://ubuntu.com)
[![Debian 12](https://img.shields.io/badge/Debian-12-red?logo=debian)](https://debian.org)
[![Sing-Box](https://img.shields.io/badge/Sing--Box-1.14%2B%20(Hy2)-blue?logo=box)](https://sing-box.sagernet.org)
[![Xray-Core](https://img.shields.io/badge/Xray--Core-REALITY%20Vision%20%26%20XHTTP-blueviolet?logo=x)](https://github.com/XTLS/Xray-core)
[![Hysteria 2](https://img.shields.io/badge/Hysteria%202-QUIC%20%2B%20Salamander-orange?logo=fastapi)](https://v2.hysteriago.com)
[![RAM](https://img.shields.io/badge/RAM_Usage-%3C120_MB-brightgreen)](#)
[![Design: AI Design Skills](https://img.shields.io/badge/Design-AI%20Design%20Skills-black?logo=figma)](https://github.com/elayadesign/ai-design-skills)
[![Design: Hallmark Anti-Slop](https://img.shields.io/badge/Design-Hallmark%20Anti--Slop-blue?logo=ghost)](https://github.com/Nutlope/hallmark)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> 💡 **Ищете NaiveProxy, Telegram Web Proxy и каскадный шлюз через сервер в РФ?**  
> Обратите внимание на наш второй репозиторий: **[stealth-proxy-cascade](https://github.com/Mizanov/stealth-proxy-cascade)** — специализированный узел с Caddy v2, NaiveProxy (Chromium stack), Telegram Web Proxy и Smart Russian Cascade.

</div>

---

## 🌟 Ключевые возможности

* **Мультитранспортная архитектура нового поколения (Xray-Core + Sing-Box)**:
  * ⚡ **Основной VPN — VLESS + REALITY + Vision (TCP) на порту 8443**: 0-RTT, минимальные накладные расходы, сверхвысокая скорость и минимальный расход батареи на смартфонах.
  * 🛡️ **Резервный VPN — VLESS + XHTTP + REALITY на порту 8444**: новейший потоковый транспорт Xray, эмулирующий стандартные HTTP-запросы для обхода агрессивных блокировок ТСПУ/DPI.
  * 🚀 **Скоростной Hysteria 2 (Hy2) с обфускацией Salamander на порту 443 (UDP)**: модифицированный протокол QUIC со встроенным контролем перегрузок Brutal CC и обфускацией заголовков `salamander`. Работает на стандартном порту 443/UDP (HTTP/3), обеспечивая рекордную скорость на нестабильных каналах и 100% защиту от блокировок нестандартных портов провайдерами.
  * 🔒 **Self-SNI маскировка (Защита от бана за чужой SNI)**: SNI указывает строго на **собственный домен сервера**, а fallback REALITY направляется на локальный Nginx (`127.0.0.1:443`). При проверках цензоров IP-адрес соединения на 100% совпадает с DNS A-записью домена, устраняя подозрения на SNI-спуфинг.
  * 🌐 **100% обратная совместимость (WS + TLS на порту 443 TCP)**: Sing-Box продолжает обслуживать VLESS WS и Trojan WS через Nginx для старых клиентов.
* **Универсальные ключи и подписки для всех клиентов ([Incy](https://incy.app), [Happ](https://github.com), [Sing-Box](https://sing-box.sagernet.org), Shadowrocket, Surge, v2rayN/v2rayNG, Streisand)**:
  * Единая **Base64-подписка** (`.txt`), содержащая сразу **5 профилей**:
    1. `⚡ [Основной] VLESS-REALITY-Vision` (8443/tcp, xtls-rprx-vision, Self-SNI)
    2. `🛡️ [Резерв] VLESS-XHTTP-REALITY` (8444/tcp, xhttp, Self-SNI)
    3. `🚀 [Hy2] Hysteria2-Salamander` (443/udp, QUIC, Salamander obfs, TLS 1.3)
    4. `🌐 [WS] VLESS-WS-TLS` (443/tcp, ws)
    5. `🔒 [WS] Trojan-WS-TLS` (443/tcp, ws)
  * Чистые `.json` профили для оригинального ядра Sing-Box с селектором outbounds (`vless-reality` по умолчанию) и правилами обхода блокировок (AntiZapret, GeoIP, GeoSite).
  * Готовый клиентский конфиг `*-hy2.json` для Sing-Box, Shadowrocket, Nekobox и других клиентов с поддержкой Hysteria 2.
* **Умный Telegram-бот управления**:
  * Быстрая выдача ключей командой `/new <имя>` или кнопкой меню.
  * Управление списком пользователей (`/list`, `/del`).
  * 📊 **Учёт сетевого трафика каждого пользователя (`/stats`)**: статистика скачивания (download) и отдачи (upload) в реальном времени, постоянное сохранение истории при перезагрузках VPS, быстрое обнуление трафика (`/rst`).
  * Мониторинг состояния сервера (`/status` — Sing-Box, Xray-Core, Nginx, CPU, RAM, диск и суммарный сетевой трафик).
* **Защита от активного зондирования РКН / ТСПУ (Anti-Probing & Self-SNI Stealth)**:
  * **Живой White-Site (Decoy Portfolio)**: корень домена отдаёт полноценный, эстетичный сайт системного инженера / облачного архитектора с кодом **200 OK** (с тёмной темой, интерактивными элементами, проектами, статьями, `robots.txt` и `sitemap.xml`).
  * **Стандарты [AI Design Skills](https://github.com/elayadesign/ai-design-skills)**: ультралёгкая архитектура без тяжелых JS-фреймворков (~35 КБ, отклик < 25 мс, 100/100 в Lighthouse) с премиальной типографикой (Manrope + Geist Mono) и матовыми поверхностями.
  * **Никаких дефолтных редиректов**: сканеры цензоров не видят редиректов на поисковики или ошибок 403/404 — сервер выглядит как обычный легитимный IT-проект.
  * **Полная изоляция секретных путей**: прокси-пути VLESS/Trojan и веб-подписки доступны только по строго секретным длинным хэш-ссылкам.
* **Сверхэффективное использование ресурсов**:
  * Исключение Docker позволило снизить фоновое потребление оперативной памяти до **<120 МБ**, что делает сервер идеальным для базовых VPS с 1 CPU и 1 GB RAM за 1.5–3 €/мес.
* **Комплексная безопасность Zero-Trust**:
  * Изолированный системный пользователь `incy-bot` без shell-доступа.
  * Автоматический фаервол UFW с закрытием всех внутренних портов.
  * Защита от брутфорса SSH через Fail2ban (бан на 24 часа).
  * Тюнинг сетевого стека Linux (BBR, SYN Cookies, защита от IP-спуфинга).
  * Автоматический ежедневный бэкап настроек и сертификатов в `/var/backups/vps/`.

---

## 📐 Архитектура системы

```text
                                         ИНТЕРНЕТ
                                            │
        ┌───────────────────┬───────────────┴───────────────┬───────────────────┐
        ▼                   ▼                               ▼                   ▼
[ Порт 8443 (TCP) ]   [ Порт 8444 (TCP) ]          [ Порт 443 (UDP) ]        [ Порты 80, 443 (TCP) ]
 Xray-Core: REALITY    Xray-Core: XHTTP             Sing-Box: Hysteria 2      NGINX СТЕЛС-ФРОНТЕНД
 ├─ VLESS Vision       ├─ VLESS + XHTTP             ├─ QUIC + Brutal CC       (SSL / HSTS / Drop 444)
 └─ Self-SNI -> 443    └─ Self-SNI -> 443           ├─ Salamander Obfuscation │
                                                    └─ Let's Encrypt TLS 1.3  ┌────────┴────────┐
                                                                              ▼                 ▼
                                                                      [ Sing-Box Core ] [ Decoy Website ]
                                                                      ├─ :11443 VLESS ws  (Portfolio 200 OK)
                                                                      ├─ :10443 Trojan ws
                                                                      └─ Подписки /var/www/
```


---

## 📋 Требования к серверу

* **ОС**: Ubuntu 22.04 LTS / Ubuntu 24.04 LTS или Debian 12 (чистая установка).
* **Характеристики**: 1 vCPU, 1 GB RAM (достаточно даже самого доступного VPS с 1 GB RAM), 10 GB диска.
* **Порты**: Открытые порты 22, 80, 443 (TCP и UDP), 8443, 8444 (TCP).
* **Домен**: Собственный домен (например, `vpn.yourdomain.com` или бесплатный от DuckDNS `yourname.duckdns.org`), направленный на IPv4 сервера.

---

## ⚡ Быстрая установка

Подключитесь к вашему VPS по SSH с правами `root`:

```bash
git clone https://github.com/Mizanov/stealth-vpn-node.git /opt/stealth-vpn-node
cd /opt/stealth-vpn-node
chmod +x install.sh
./install.sh
```

В процессе установки скрипт запросит:
1. **Main Domain**: Ваш основной домен (A-запись, направленная на IP вашего сервера).
2. **Email**: Email для выпуска бесплатных SSL-сертификатов Let's Encrypt.
3. **Telegram Bot Token**: Токен, полученный от бота [@BotFather](https://t.me/BotFather).
4. **Telegram Admin ID**: Ваш числовой Telegram ID (можно узнать через бота [@userinfobot](https://t.me/userinfobot)).

Скрипт автоматически настроит и запустит все компоненты за 2–3 минуты.

---

## 📱 Управление через Telegram-бота

### 1. Команды бота

* **`➕ Создать ключ`** или команда `/new <имя>`:
  * Бот мгновенно сгенерирует уникальный UUID и конфиг.
  * Пришлёт **QR-код** (для мгновенного сканирования камерой в любом мобильном клиенте).
  * Ссылку на универсальную подписку (`https://.../<user>.txt`).
  * Прямую строку `vless://...` (копируется в один клик).
  * Ссылку на полный `.json` профиль для Sing-Box.
  * Кнопку для получения скоростного конфига **Hysteria 2**.
* **`👥 Список ключей`** или команда `/list`:
  * Список всех пользователей с отображением объёма использованного трафика (скачано/отдано), кнопками полной информации и удаления.
* **`📊 Трафик пользователей`** или команда `/stats`:
  * Сводная статистика сетевого трафика по всему серверу и детализация по каждому пользователю с сортировкой по потреблению. В карточке пользователя доступен сброс счётчика трафика.
* **`📊 Статус сервера`** или команда `/status`:
  * Мониторинг служб Sing-Box, Xray-Core, Nginx, суммарного сетевого трафика VPN, свободной памяти и диска.

### 2. Подключение в клиентских приложениях

Сгенерированные ботом ссылки и подписки поддерживаются всеми популярными клиентами:

* **Incy / Happ (iOS, Android)**:
  * **Вариант А (самый быстрый):** Нажмите **«+» ➔ «Сканировать QR-код»** и наведите камеру на QR-код из сообщения бота. Узел добавится мгновенно.
  * **Вариант Б (подписка с автообновлением):** Скопируйте ссылку на подписку (`.txt`) из бота, откройте приложение ➔ «Подписки» ➔ «Добавить» ➔ Вставьте ссылку. Узлы загрузятся и будут автоматически обновляться при изменениях на сервере.
* **Sing-Box / SFM / SFI (macOS, iOS, Windows, Android)**:
  * Импортируйте ссылку на подписку (`.txt`) через пункт «Profiles» / «Add Remote Profile» либо загрузите готовый `.json` файл.
* **v2rayN (Windows) / v2rayNG (Android)**:
  * Скопируйте `vless://` строку из сообщения бота ➔ нажмите «Импорт из буфера обмена» (Ctrl+V в v2rayN или значок «+» в v2rayNG), либо добавьте ссылку подписки.
* **Streisand / FoXray / Karing (iOS, macOS, Android)**:
  * Нажмите «+» ➔ добавьте ссылку подписки (тип: Base64 / V2Ray) или отсканируйте QR-код.
* **Shadowrocket / Surge (iOS, macOS)**:
  * Нажмите «+» ➔ добавьте ссылку подписки (`.txt`) либо прямую URI-ссылку `hysteria2://` из сообщения бота для прямого подключения по протоколу **Hysteria 2** (443/UDP с обфускацией Salamander).
* **Nekobox / v2rayN / Sing-Box (Десктопные клиенты)**:
  * Нажмите кнопку **«🚀 Hysteria2 JSON»** в боте и импортируйте готовый JSON-конфиг для скоростного туннелирования.

---

## 🛠 Обслуживание и команды

```bash
# Проверка статуса всех компонентов
systemctl status xray sing-box nginx incy-bot

# Просмотр логов Telegram-бота
journalctl -u incy-bot.service -f

# Просмотр логов ядра Xray
journalctl -u xray -f

# Просмотр логов ядра Sing-Box
journalctl -u sing-box -f

# Проверка заблокированных IP в Fail2ban
fail2ban-client status sshd

# Просмотр правил фаервола UFW
ufw status verbose

# Проверка параметров безопасности ядра Linux
sysctl net.ipv4.tcp_congestion_control net.ipv4.tcp_syncookies net.ipv4.conf.all.rp_filter

# Быстрый аудит и наложение всех слоёв безопасности
bash scripts/setup-security.sh

# Создание резервной копии конфигураций и сертификатов
backup-vps

# Тест автопродления SSL-сертификатов (Zero-Downtime Webroot)
certbot renew --dry-run

# Перезапуск сервисов при необходимости
systemctl restart xray sing-box nginx incy-bot fail2ban
```

---

## 🔄 Обновление

Для обновления существующей системы выполните:

```bash
cd /opt/stealth-vpn-node
git pull
sudo bash update.sh
```

Скрипт выполнит атомарное обновление конфигураций без разрыва активных соединений пользователей.

---

## 🗑 Удаление

Если вам потребуется полностью удалить все компоненты с сервера:

```bash
cd /opt/stealth-vpn-node
chmod +x uninstall.sh
./uninstall.sh
```

---

## 📄 Лицензия

MIT License. Свободно для частного и коммерческого использования.
