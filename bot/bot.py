import os
import sys
import json
import uuid
import re
import io
import base64
import subprocess
import logging
from datetime import datetime, timezone
from typing import Optional, Set, Dict, Any, Tuple

import qrcode
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, ReplyKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ContextTypes,
    filters
)

from auth import (
    parse_admin_ids,
    is_admin as auth_is_admin,
    admin_required as auth_admin_required,
    AuthorizationConfigurationError
)
from config_manager import (
    validate_username,
    atomic_modify_singbox_config,
    add_user_to_config,
    delete_user_from_config,
    list_users_from_config,
    ensure_singbox_hy2_config,
    UserAlreadyExistsError,
    UserNotFoundError,
    InvalidUsernameError,
    ConfigValidationError,
    ConfigReloadError,
    ConfigManagerError
)
from subscription_manager import (
    create_or_update_subscription,
    get_subscription_info,
    rotate_subscription_token,
    revoke_subscription,
    sync_subscriptions_from_config,
    get_user_by_tg_id,
    get_all_users_meta,
    SubscriptionError
)
from xray_manager import (
    load_xray_config,
    list_users_from_xray,
    add_user_to_xray,
    delete_user_from_xray,
    atomic_modify_xray_config,
    ensure_xray_stats_config,
    remove_xray_masque_config,
    XrayConfigError
)
from stats_manager import (
    format_bytes,
    get_user_traffic,
    get_all_traffic_stats,
    sync_traffic_stats,
    reset_user_traffic,
    remove_user_traffic
)

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger("IncyBot")

# Load environment variables
def load_env_file(filepath: str = "/opt/incy-bot/.env"):
    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

load_env_file()

TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()

# Strict Fail-Closed Authorization Verification at Module Startup
try:
    ADMIN_IDS: Set[int] = parse_admin_ids(os.getenv("TELEGRAM_ADMIN_IDS"))
except AuthorizationConfigurationError as e:
    logger.critical("AUTHORIZATION FAILURE: %s", e)
    sys.exit(1)

def is_admin(user_id: Optional[int]) -> bool:
    """Strict fail-closed admin check."""
    return auth_is_admin(user_id, ADMIN_IDS)

# Decorator bound to validated ADMIN_IDS
admin_required = auth_admin_required(ADMIN_IDS)

DOMAIN = os.getenv("MAIN_DOMAIN", "localhost").strip()
SUBS_PATH = os.getenv("SUBS_PATH", "sub").strip()
VLESS_PATH = os.getenv("VLESS_PATH", "vless").strip()
TROJAN_PATH = os.getenv("TROJAN_PATH", "trojan").strip()

CONFIG_JSON = os.getenv("SINGBOX_CONFIG_JSON", "/etc/sing-box/config.json").strip()
WWW_DIR = os.getenv("SUBS_DIR", f"/var/www/{SUBS_PATH}").strip()
VLESS_TEMPLATE = os.getenv("VLESS_TEMPLATE", "/opt/incy-bot/template-vless.json").strip()
TROJAN_TEMPLATE = os.getenv("TROJAN_TEMPLATE", "/opt/incy-bot/template-trj.json").strip()
SINGBOX_CONTROL = os.getenv("SINGBOX_CONTROL_BIN", "/usr/local/bin/singbox-control").strip()

# Dual-transport modern node: Xray REALITY & XHTTP settings
REALITY_PORT = int(os.getenv("REALITY_PORT", "8443").strip())
XHTTP_PORT = int(os.getenv("XHTTP_PORT", "8444").strip())
HY2_PORT = int(os.getenv("HY2_PORT", "443").strip())
HY2_OBFS_PASSWORD = os.getenv("HY2_OBFS_PASSWORD", "sal_sec_84729472").strip()
REALITY_PUBLIC_KEY = os.getenv("REALITY_PUBLIC_KEY", "").strip()
REALITY_SHORT_ID = os.getenv("REALITY_SHORT_ID", "").strip()
REALITY_SNI = os.getenv("REALITY_SNI", "").strip() or DOMAIN
REALITY_DEST = os.getenv("REALITY_DEST", "127.0.0.1:443").strip()
XHTTP_PATH = os.getenv("XHTTP_PATH", "xhttp").strip()
HY2_TEMPLATE = os.getenv("HY2_TEMPLATE", "/opt/incy-bot/template-hy2.json").strip()
XRAY_CONFIG_JSON = os.getenv("XRAY_CONFIG_JSON", "/etc/xray/config.json").strip()

if not TOKEN:
    logger.error("FATAL: TELEGRAM_BOT_TOKEN environment variable is not set!")
    sys.exit(1)


def run_privileged_control(action: str, target: Optional[str] = None) -> subprocess.CompletedProcess:
    """
    Invoke strictly audited privileged action via root-owned helper script.
    Uses sudo if not running as root.
    """
    cmd = []
    if os.geteuid() != 0:
        cmd.append("sudo")

    cmd.extend([SINGBOX_CONTROL, action])
    if target:
        cmd.append(target)

    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=10,
        check=True
    )


def reload_singbox():
    """Reload sing-box via privileged root-owned helper."""
    run_privileged_control("reload")


def get_admin_keyboard():
    keyboard = [
        ["➕ Создать ключ", "👥 Список участников"],
        ["📊 Трафик пользователей", "📊 Статус сервера"]
    ]
    return ReplyKeyboardMarkup(keyboard, resize_keyboard=True)


def get_user_unregistered_keyboard():
    keyboard = [
        ["🚀 Запросить доступ", "📖 Инструкция"]
    ]
    return ReplyKeyboardMarkup(keyboard, resize_keyboard=True)


def get_user_registered_keyboard():
    keyboard = [
        ["📱 Мой профиль", "📊 Мой трафик"],
        ["📖 Инструкция"]
    ]
    return ReplyKeyboardMarkup(keyboard, resize_keyboard=True)


def get_keyboard():
    """Compatibility alias for admin keyboard."""
    return get_admin_keyboard()


def create_user_singbox(username: str, extra_meta: Optional[Dict[str, Any]] = None) -> Optional[dict]:
    try:
        valid_username = validate_username(username)
    except InvalidUsernameError as e:
        return {"error": str(e)}

    new_uuid = str(uuid.uuid4())
    new_pass = uuid.uuid4().hex[:16]

    try:
        add_user_to_config(
            username=valid_username,
            new_uuid=new_uuid,
            new_pass=new_pass,
            config_path=CONFIG_JSON,
            control_runner=run_privileged_control
        )
    except UserAlreadyExistsError:
        return {"error": f"Пользователь {valid_username} уже существует!"}
    except (ConfigValidationError, ConfigReloadError, ConfigManagerError) as e:
        logger.error(f"Configuration mutation failed: {e}")
        return {"error": f"Ошибка конфигурации Sing-box: {e}"}
    except Exception as e:
        logger.error(f"Unexpected error in create_user_singbox: {e}", exc_info=True)
        return {"error": str(e)}

    # Synchronize with Xray-core (VLESS REALITY + Vision / XHTTP)
    if os.path.exists(XRAY_CONFIG_JSON):
        try:
            atomic_modify_xray_config(
                mutation_fn=lambda cfg: add_user_to_xray(cfg, valid_username, new_uuid, user_pass=new_pass),
                config_path=XRAY_CONFIG_JSON,
                control_runner=run_privileged_control
            )
        except Exception as xe:
            logger.error(f"Failed to add user {valid_username} to Xray: {xe}")
            try:
                delete_user_from_config(
                    username=valid_username,
                    config_path=CONFIG_JSON,
                    control_runner=run_privileged_control
                )
            except Exception:
                pass
            return {"error": f"Ошибка конфигурации Xray: {xe}"}

    try:
        sub_info = create_or_update_subscription(
            username=valid_username,
            vless_uuid=new_uuid,
            trojan_pass=new_pass,
            domain=DOMAIN,
            subs_path=SUBS_PATH,
            vless_path=VLESS_PATH,
            trojan_path=TROJAN_PATH,
            www_dir=WWW_DIR,
            reality_port=REALITY_PORT,
            xhttp_port=XHTTP_PORT,
            hy2_port=HY2_PORT,
            hy2_obfs_password=HY2_OBFS_PASSWORD,
            reality_public_key=REALITY_PUBLIC_KEY,
            reality_short_id=REALITY_SHORT_ID,
            reality_sni=REALITY_SNI,
            xhttp_path=XHTTP_PATH,
            vless_template=VLESS_TEMPLATE,
            trojan_template=TROJAN_TEMPLATE,
            hy2_template=HY2_TEMPLATE,
            extra_meta=extra_meta
        )

        return {
            "username": valid_username,
            "uuid": new_uuid,
            "token": sub_info["token"],
            "incy_sub_url": sub_info["sub_url"],
            "singbox_json_url": sub_info["singbox_json_url"],
            "hy2_json_url": sub_info.get("hy2_json_url", ""),
            "incy_deeplink": sub_info["deeplink"],
            "vless_link": sub_info["vless_link"],
            "vless_reality_link": sub_info.get("vless_reality_link", ""),
            "vless_xhttp_link": sub_info.get("vless_xhttp_link", ""),
            "hy2_link": sub_info.get("hy2_link", ""),
            "vless_ws_link": sub_info.get("vless_ws_link", ""),
            "trojan_link": sub_info["trojan_link"]
        }
    except Exception as e:
        logger.error(f"Error generating client profiles for {valid_username}: {e}", exc_info=True)
        return {"error": f"Пользователь создан в ядре, но возникла ошибка при создании профилей: {e}"}


def delete_user_singbox(username: str) -> bool:
    try:
        valid_username = validate_username(username)
    except InvalidUsernameError:
        return False

    try:
        delete_user_from_config(
            username=valid_username,
            config_path=CONFIG_JSON,
            control_runner=run_privileged_control
        )
    except UserNotFoundError:
        return False
    except Exception as e:
        logger.error(f"Error deleting user {username}: {e}")
        return False

    # Synchronize deletion with Xray-core
    if os.path.exists(XRAY_CONFIG_JSON):
        try:
            atomic_modify_xray_config(
                mutation_fn=lambda cfg: delete_user_from_xray(cfg, valid_username),
                config_path=XRAY_CONFIG_JSON,
                control_runner=run_privileged_control
            )
        except Exception as xe:
            logger.error(f"Failed to delete user {valid_username} from Xray: {xe}")

    # Revoke secure subscription token and cleanup files
    revoke_subscription(valid_username, www_dir=WWW_DIR)

    # Clean up traffic statistics for deleted user
    try:
        remove_user_traffic(valid_username)
    except Exception as st_err:
        logger.debug(f"Could not remove traffic stats for {valid_username}: {st_err}")

    # Legacy cleanup if un-tokenized files existed
    for f_name in (f"{valid_username}.txt", f"{valid_username}-VLESS-CLIENT.json", f"{valid_username}-TRJ-CLIENT.json"):
        p = f"{WWW_DIR}/{f_name}"
        if os.path.exists(p):
            try:
                os.remove(p)
            except OSError:
                pass

    return True


def get_users_list() -> list:
    sb_users = set(list_users_from_config(config_path=CONFIG_JSON))
    xr_users = set(list_users_from_xray(config_path=XRAY_CONFIG_JSON)) if os.path.exists(XRAY_CONFIG_JSON) else set()
    return sorted(list(sb_users | xr_users))


def generate_qr(data: str) -> io.BytesIO:
    qr = qrcode.QRCode(version=1, box_size=8, border=2)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    bio = io.BytesIO()
    img.save(bio, format="PNG")
    bio.seek(0)
    return bio


async def start_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not user:
        return
    if is_admin(user.id):
        await send_admin_panel(update, context)
    else:
        await send_user_cabinet(update, context)


async def send_admin_panel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    msg = (
        f"👋 Здравствуйте, {user.first_name}!\n\n"
        "Панель управления **Multi-Transport Stealth Network Node**:\n"
        "• ⚡ **Xray-Core**: VLESS + REALITY Vision & XHTTP\n"
        "• 🚀 **Sing-Box**: Hysteria 2 Salamander UDP + VLESS/Trojan WS\n\n"
        "⚡ **Доступные команды администратора:**\n"
        "• `/new <имя>` — сгенерировать ключ и универсальную подписку\n"
        "• `/list` — список всех участников с привязкой к Telegram и трафиком\n"
        "• `/stats` — сводная статистика сетевого трафика\n"
        "• `/del <имя>` — удалить пользователя и аннулировать токен\n"
        "• `/status` — статус сервера и служб\n\n"
        "Или используйте кнопки внизу 👇"
    )
    target = update.callback_query.message if update.callback_query else update.message
    await target.reply_text(msg, reply_markup=get_admin_keyboard(), parse_mode="Markdown")


async def send_user_cabinet(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    existing = get_user_by_tg_id(user.id)

    target = update.callback_query.message if update.callback_query else update.message
    if existing:
        username, _ = existing
        msg = (
            f"👋 С возвращением, космический странник {user.first_name}! 🚀\n\n"
            f"Добро пожаловать в **Личный кабинет защищённого узла связи**.\n\n"
            f"👤 **Твой позывной:** `{username}`\n"
            f"🟢 **Статус соединения:** Турбины на максимуме, полёт отличный!\n\n"
            f"Здесь можно в один тап восстановить параметры подключения, показать QR-код новому гаджету или проверить, сколько гигабайт ты уже прокачал через сервер."
        )
        keyboard = [
            [InlineKeyboardButton("📱 Мой профиль и QR-код", callback_data="user_profile")],
            [
                InlineKeyboardButton("📊 Мой трафик", callback_data="user_traffic"),
                InlineKeyboardButton("📖 Инструкция", callback_data="user_guide")
            ]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await target.reply_text(msg, reply_markup=get_user_registered_keyboard(), parse_mode="Markdown")
        await target.reply_text("Выберите необходимое действие в меню:", reply_markup=reply_markup)
    else:
        msg = (
            f"👋 Привет, {user.first_name}! На связи персональный узел связи! 🚀\n\n"
            f"Да-да, тот самый сервер в Финляндии, про который ходят легенды. "
            f"Никакой рекламы казино, никаких падений посреди любимого сериала в пятницу вечером "
            f"и никаких зависающих картинок с котиками.\n\n"
            f"🛸 **Что здесь вообще происходит?**\n"
            f"Мы собрали на одном узле всё самое передовое, чтобы интернет летал со скоростью света:\n"
            f"• ⚡ **VLESS REALITY & Vision** — для провайдеров вы просто читаете сайт дизайн-студии, а сами на космической скорости смотрите 4K-видео.\n"
            f"• 🚀 **Hysteria 2 на протоколе UDP** — пробивает плохой Wi-Fi, мобильные помехи и даже соседскую дрель.\n"
            f"• 📱 **Универсальная подписка 5-в-1** — один волшебный ключ для смартфона, ноутбука, планшета и хоть умного холодильника.\n\n"
            f"🎫 **Правила нашего закрытого клуба:**\n"
            f"1. Нажмите кнопку **«🚀 Получить ключ в один клик»** внизу.\n"
            f"2. Бот мгновенно выдаст персональную ссылку и QR-код.\n"
            f"3. ⚠️ *Внимание:* ключ выдаётся **строго один раз на человека** (в одни руки, чтобы сервер не лопнул от перегрузки).\n\n"
            f"Жмите кнопку ниже — и приятного полёта! 🪐"
        )
        keyboard = [
            [InlineKeyboardButton("🚀 Получить ключ в один клик", callback_data="req_access")],
            [InlineKeyboardButton("📖 Инструкция по подключению", callback_data="user_guide")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await target.reply_text(msg, reply_markup=get_user_unregistered_keyboard(), parse_mode="Markdown")
        await target.reply_text("Нажмите для выпуска персонального ключа:", reply_markup=reply_markup)


async def deliver_user_credentials(
    target_msg,
    username: str,
    sub_info: dict,
    is_self_service: bool = False,
    reality_link: str = "",
    hy2_link: str = ""
):
    sub_url = sub_info.get("subscription_url") or sub_info.get("sub_url", "")
    sb_json = sub_info.get("singbox_json_url", "")
    hy2_json = sub_info.get("hy2_json_url", "")
    if not reality_link:
        reality_link = sub_info.get("vless_link") or sub_info.get("reality_link", "")
    if not hy2_link:
        hy2_link = sub_info.get("hy2_link", "")

    header = "🎉 **Поздравляем! Твой персональный ключ готов!** 🚀" if is_self_service else f"✅ **Ключ для `{username}` успешно создан!**"
    caption = (
        f"{header}\n\n"
        f"👤 **Позывной:** `{username}`\n"
        f"🟢 **Статус:** Активен на максимальной скорости\n\n"
        f"📋 **Универсальная ссылка подписки (5-в-1):**\n"
        f"`{sub_url}`\n\n"
        f"💡 *Отсканируйте QR-код в приложении или скопируйте ссылку подписки.*"
    )

    json_buttons = [InlineKeyboardButton("📦 Sing-Box JSON", url=sb_json)] if sb_json else []
    if hy2_json:
        json_buttons.append(InlineKeyboardButton("🚀 Hysteria2 JSON", url=hy2_json))

    keyboard = []
    if sub_url:
        keyboard.append([InlineKeyboardButton("🌐 Открыть подписку", url=sub_url)])
    if json_buttons:
        keyboard.append(json_buttons)
    keyboard.append([InlineKeyboardButton("📖 Инструкция", callback_data="user_guide")])
    reply_markup = InlineKeyboardMarkup(keyboard)

    qr_target = reality_link or sub_url
    qr_img = generate_qr(qr_target) if qr_target else None

    if qr_img:
        try:
            await target_msg.reply_photo(
                photo=qr_img,
                caption=caption[:1024],
                parse_mode="Markdown",
                reply_markup=reply_markup
            )
        except Exception as err:
            logger.warning(f"Failed to send QR photo: {err}")
            await target_msg.reply_text(
                caption,
                parse_mode="Markdown",
                reply_markup=reply_markup,
                disable_web_page_preview=True
            )
    else:
        await target_msg.reply_text(
            caption,
            parse_mode="Markdown",
            reply_markup=reply_markup,
            disable_web_page_preview=True
        )

    direct_msg = (
        f"⚡ **Прямые ссылки для ручного импорта (`{username}`):**\n\n"
        f"1️⃣ **VLESS + REALITY + Vision:**\n`{reality_link}`\n\n"
        f"2️⃣ **Hysteria 2 Salamander:**\n`{hy2_link}`"
    )
    kb = get_user_registered_keyboard() if is_self_service else get_admin_keyboard()
    await target_msg.reply_text(
        direct_msg,
        parse_mode="Markdown",
        reply_markup=kb,
        disable_web_page_preview=True
    )


async def request_access_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not user:
        return

    # Check if already registered (Single-issue self-service lock)
    existing = get_user_by_tg_id(user.id)
    if existing:
        username, _ = existing
        msg = f"⚠️ У вас уже активирован персональный доступ: `{username}`.\nПовторный выпуск ключа заблокирован."
        if update.callback_query:
            await update.callback_query.answer("Доступ уже предоставлен!", show_alert=True)
            await update.callback_query.message.reply_text(msg, parse_mode="Markdown", reply_markup=get_user_registered_keyboard())
        else:
            await update.message.reply_text(msg, parse_mode="Markdown", reply_markup=get_user_registered_keyboard())
        return

    # Derive unique sanitized username
    base_name = ""
    if user.username:
        clean_user = re.sub(r"[^a-zA-Z0-9_-]", "", user.username.lower())
        if len(clean_user) >= 3:
            base_name = f"tg_{clean_user[:20]}"
    if not base_name:
        base_name = f"user_{user.id}"

    existing_users = set(get_users_list())
    candidate_name = base_name
    counter = 1
    while candidate_name in existing_users:
        candidate_name = f"{base_name}_{counter}"
        counter += 1

    extra_meta = {
        "tg_id": user.id,
        "tg_username": user.username or "",
        "tg_first_name": user.first_name or "",
        "tg_last_name": user.last_name or "",
        "issued_at": datetime.now(timezone.utc).isoformat()
    }

    res = create_user_singbox(candidate_name, extra_meta=extra_meta)
    if not res or "error" in res:
        err_msg = res.get("error", "Неизвестная ошибка") if res else "Ошибка создания учетной записи"
        logger.error("Failed to self-register user %s (%s): %s", user.id, candidate_name, err_msg)
        fail_text = f"❌ Не удалось выпустить ключ: {err_msg}. Обратитесь к администратору."
        if update.callback_query:
            await update.callback_query.message.reply_text(fail_text)
        else:
            await update.message.reply_text(fail_text)
        return

    if update.callback_query:
        await update.callback_query.answer("Доступ успешно активирован!")

    target_msg = update.callback_query.message if update.callback_query else update.message
    await deliver_user_credentials(target_msg, candidate_name, res, is_self_service=True)

    # Notify admins about new user registration
    for admin_id in ADMIN_IDS:
        try:
            admin_notify = (
                "🔔 **Новый участник получил доступ:**\n\n"
                f"• Профиль: `{candidate_name}`\n"
                f"• Имя: {user.full_name}\n"
                f"• Telegram: @{user.username or '—'} (`{user.id}`)"
            )
            await context.bot.send_message(chat_id=admin_id, text=admin_notify, parse_mode="Markdown")
        except Exception as e:
            logger.debug("Failed to send admin notification to %s: %s", admin_id, e)


async def show_user_profile(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not user:
        return

    existing = get_user_by_tg_id(user.id)
    if not existing:
        await send_user_cabinet(update, context)
        return

    username, udata = existing
    sub_info = get_subscription_info(username, DOMAIN, SUBS_PATH)
    target = update.callback_query.message if update.callback_query else update.message

    if not sub_info:
        msg = f"⚠️ Профиль `{username}` найден, но файлы конфигурации подписки отсутствуют. Обратитесь к администратору."
        await target.reply_text(msg, parse_mode="Markdown")
        return

    vless_uuid = udata.get("vless_uuid", "")
    trojan_pass = udata.get("trojan_pass", "")
    reality_link = f"vless://{vless_uuid}@{DOMAIN}:{REALITY_PORT}?security=reality&encryption=none&pbk={REALITY_PUBLIC_KEY}&headerType=none&fp=chrome&spx=%2F&type=tcp&flow=xtls-rprx-vision&sni={REALITY_SNI}&sid={REALITY_SHORT_ID}#REALITY-Vision-{username}"
    hy2_link = f"hysteria2://{trojan_pass}@{DOMAIN}:{HY2_PORT}/?sni={DOMAIN}&insecure=0&obfs=salamander&obfs-password={HY2_OBFS_PASSWORD}#Hysteria2-{username}"

    if update.callback_query:
        await update.callback_query.answer()

    await deliver_user_credentials(
        target,
        username,
        sub_info,
        is_self_service=True,
        reality_link=reality_link,
        hy2_link=hy2_link
    )


async def show_user_traffic(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not user:
        return

    existing = get_user_by_tg_id(user.id)
    if not existing:
        await send_user_cabinet(update, context)
        return

    username, _ = existing
    u_stats = get_user_traffic(username, sync=True)

    msg = (
        f"📊 **Потребление сетевого трафика**\n\n"
        f"👤 **Профиль:** `{username}`\n"
        f"🟢 **Статус соединения:** Активно\n\n"
        f"• ⬇️ **Скачано (Download):** `{u_stats['formatted_downlink']}`\n"
        f"• ⬆️ **Загружено (Upload):** `{u_stats['formatted_uplink']}`\n"
        f"• 🔄 **Суммарный объём:** `{u_stats['formatted_total']}`\n\n"
        f"💡 *Статистика обновляется в реальном времени при передаче данных через протоколы узла.*"
    )
    keyboard = [
        [InlineKeyboardButton("🔄 Обновить", callback_data="user_traffic")],
        [InlineKeyboardButton("📱 Мой профиль", callback_data="user_profile")]
    ]
    target = update.callback_query.message if update.callback_query else update.message
    if update.callback_query:
        await update.callback_query.answer("Данные обновлены")
        try:
            await update.callback_query.edit_message_text(msg, parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(keyboard))
        except Exception:
            await target.reply_text(msg, parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(keyboard))
    else:
        await target.reply_text(msg, parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(keyboard))


async def show_user_guide(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "📖 **Инструкция по подключению к узлу**\n\n"
        "Для подключения используйте универсальную ссылку подписки или отсканируйте QR-код в приложении:\n\n"
        "🍏 **Apple (iOS / iPadOS / macOS):**\n"
        "1. Установите приложение: **FoXray**, **Streisand** или **Sing-box** из App Store.\n"
        "2. Скопируйте ссылку подписки из раздела «📱 Мой профиль» или отсканируйте QR-код.\n"
        "3. В приложении нажмите «+» ➔ «Импорт из буфера обмена» (или «Сканировать QR»).\n"
        "4. Нажмите кнопку подключения.\n\n"
        "🤖 **Android:**\n"
        "1. Установите приложение: **v2rayNG** или **NekoBox** (из Google Play или GitHub).\n"
        "2. Нажмите «+» в правом верхнем углу ➔ «Импорт из буфера обмена» или отсканируйте QR-код.\n"
        "3. Выберите появившийся профиль и нажмите кнопку включения.\n\n"
        "💻 **Windows:**\n"
        "1. Скачайте приложение **v2rayN** или **Hiddify**.\n"
        "2. Нажмите «Серверы» ➔ «Импортировать ссылку из буфера» (Ctrl+V).\n"
        "3. Активируйте режим системного прокси.\n\n"
        "💡 *При любых вопросах обращайтесь к администратору вашего узла.*"
    )
    target = update.callback_query.message if update.callback_query else update.message
    if update.callback_query:
        await update.callback_query.answer()
        await target.reply_text(msg, parse_mode="Markdown")
    else:
        await target.reply_text(msg, parse_mode="Markdown")


@admin_required
async def list_users_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    users = get_users_list()
    if not users:
        await update.message.reply_text("Список пользователей пуст.", reply_markup=get_admin_keyboard())
        return

    try:
        sync_traffic_stats()
    except Exception as e:
        logger.warning("Failed to sync traffic stats in list_users_command: %s", e)

    meta_registry = get_all_users_meta()

    msg = f"👥 **Список учетных записей ({len(users)}):**\n\n"
    keyboard = []
    for u in users:
        u_stats = get_user_traffic(u, sync=False)
        tot_str = u_stats["formatted_total"]
        dl_str = u_stats["formatted_downlink"]
        ul_str = u_stats["formatted_uplink"]

        user_entry = meta_registry.get(u, {})
        meta = user_entry.get("meta", {}) if isinstance(user_entry, dict) else {}
        tg_info = ""
        if meta and isinstance(meta, dict):
            parts = []
            if meta.get("tg_username"):
                parts.append(f"@{meta['tg_username']}")
            if meta.get("tg_first_name"):
                parts.append(meta["tg_first_name"])
            if meta.get("tg_id"):
                parts.append(f"ID:{meta['tg_id']}")
            if parts:
                tg_info = f" ({', '.join(parts)})"

        msg += f"• `{u}`{tg_info} — **{tot_str}** (↓ {dl_str} / ↑ {ul_str})\n"
        keyboard.append([
            InlineKeyboardButton(f"🔗 {u}", callback_data=f"info_{u}"),
            InlineKeyboardButton("🗑 Удалить", callback_data=f"del_{u}")
        ])

    keyboard.append([
        InlineKeyboardButton("📊 Полная статистика трафика", callback_data="show_stats")
    ])

    reply_markup = InlineKeyboardMarkup(keyboard) if keyboard else None
    await update.message.reply_text(msg, parse_mode="Markdown", reply_markup=reply_markup)


@admin_required
async def stats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    users = get_users_list()
    stats_data = get_all_traffic_stats(known_users=users, sync=True)
    srv = stats_data["server_total"]

    msg = (
        "📊 **Статистика сетевого трафика**\n\n"
        "🌐 **Общий трафик сервера:**\n"
        f"  • ⬇️ **Скачано (Download):** `{srv['formatted_downlink']}`\n"
        f"  • ⬆️ **Загружено (Upload):** `{srv['formatted_uplink']}`\n"
        f"  • 🔄 **Суммарно:** `{srv['formatted_total']}`\n\n"
        f"👥 **Пользователи ({len(stats_data['users'])}):**\n"
    )

    keyboard = []
    if not stats_data["users"]:
        msg += "  *Пользователи не найдены.*\n"
    else:
        for idx, u in enumerate(stats_data["users"], 1):
            uname = u["username"]
            msg += f"{idx}. `{uname}` — **{u['formatted_total']}** (⬇️ {u['formatted_downlink']} / ⬆️ {u['formatted_uplink']})\n"
            keyboard.append([
                InlineKeyboardButton(f"👤 {uname} ({u['formatted_total']})", callback_data=f"info_{uname}")
            ])

    msg += "\n💡 *Трафик учитывается через VLESS-REALITY (Vision и XHTTP) и сохраняется при перезагрузках.*"

    keyboard.append([
        InlineKeyboardButton("🔄 Обновить данные", callback_data="refresh_stats")
    ])

    reply_markup = InlineKeyboardMarkup(keyboard)
    if update.callback_query:
        try:
            await update.callback_query.edit_message_text(
                msg,
                parse_mode="Markdown",
                reply_markup=reply_markup
            )
        except Exception:
            await update.callback_query.message.reply_text(
                msg,
                parse_mode="Markdown",
                reply_markup=reply_markup
            )
    else:
        await update.message.reply_text(msg, parse_mode="Markdown", reply_markup=reply_markup)


async def process_new_user(update: Update, username: str):
    user_data = create_user_singbox(username)
    if not user_data or "error" in user_data:
        err = user_data.get("error", "Неизвестная ошибка") if user_data else "Ошибка создания"
        await update.message.reply_text(f"⚠️ Ошибка создания ключа `{username}`: {err}", parse_mode="Markdown")
        return

    await deliver_user_credentials(update.message, username, user_data, is_self_service=False)


@admin_required
async def new_user_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Использование: `/new <имя_пользователя>`", parse_mode="Markdown")
        return

    username = context.args[0].strip()
    await process_new_user(update, username)


@admin_required
async def del_user_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Использование: `/del <имя_пользователя>`", parse_mode="Markdown")
        return

    username = context.args[0].strip()
    if delete_user_singbox(username):
        await update.message.reply_text(f"🗑 Пользователь `{username}` удалён.", parse_mode="Markdown")
    else:
        await update.message.reply_text(f"⚠️ Пользователь `{username}` не найден.")


@admin_required
async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    def get_svc_status(svc: str) -> str:
        r = subprocess.run(["systemctl", "is-active", svc], capture_output=True, text=True)
        return "🟢 Active" if r.stdout.strip() == "active" else "🔴 Inactive"

    mem_r = subprocess.run(["free", "-m"], capture_output=True, text=True)
    df_r = subprocess.run(["df", "-h", "/"], capture_output=True, text=True)

    sb_st = get_svc_status("sing-box")
    xr_st = get_svc_status("xray")
    ng_st = get_svc_status("nginx")

    traffic_line = ""
    try:
        s_data = get_all_traffic_stats(sync=False)
        tot_traffic = s_data["server_total"]["formatted_total"]
        tot_dl = s_data["server_total"]["formatted_downlink"]
        tot_ul = s_data["server_total"]["formatted_uplink"]
        traffic_line = f"📊 **Суммарный сетевой трафик:** `{tot_traffic}` (⬇️ {tot_dl} / ⬆️ {tot_ul})\n\n"
    except Exception:
        pass

    msg = (
        "📊 **Статус сервера:**\n\n"
        f"📦 **Sing-Box (Hy2 / WS):** {sb_st}\n"
        f"⚡ **Xray-Core (REALITY/XHTTP):** {xr_st}\n"
        f"🌐 **Nginx:** {ng_st}\n\n"
        f"{traffic_line}"
        f"💾 **Диск:**\n```{df_r.stdout.strip()}```\n\n"
        f"🧠 **Память:**\n```{mem_r.stdout.strip()}```"
    )
    await update.message.reply_text(msg, parse_mode="Markdown")


async def callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    data = query.data
    user = update.effective_user

    # Public / Member Accessible Callbacks
    if data == "req_access":
        await request_access_handler(update, context)
        return
    elif data == "user_profile":
        await show_user_profile(update, context)
        return
    elif data == "user_traffic":
        await show_user_traffic(update, context)
        return
    elif data == "user_guide":
        await show_user_guide(update, context)
        return

    # Admin-only Callbacks
    if not is_admin(user.id if user else None):
        await query.answer("⛔ Доступ запрещён. Требуются права администратора.", show_alert=True)
        return

    if data.startswith("del_"):
        username = data[4:]
        if delete_user_singbox(username):
            await query.edit_message_caption(
                caption=f"🗑 Пользователь `{username}` был удалён.",
                parse_mode="Markdown"
            ) if query.message.caption else await query.edit_message_text(
                text=f"🗑 Пользователь `{username}` был удалён.",
                parse_mode="Markdown"
            )
        else:
            await query.message.reply_text(f"⚠️ Не удалось удалить пользователя {username}.")
    elif data.startswith("info_"):
        username = data[5:]
        u_stats = get_user_traffic(username, sync=True)
        sub_info = get_subscription_info(username, DOMAIN, SUBS_PATH)
        meta_registry = get_all_users_meta()
        user_entry = meta_registry.get(username, {})
        meta = user_entry.get("meta", {}) if isinstance(user_entry, dict) else {}

        tg_details = ""
        if meta and isinstance(meta, dict):
            tg_id = meta.get("tg_id", "—")
            tg_user = f"@{meta.get('tg_username')}" if meta.get("tg_username") else "—"
            tg_name = meta.get("tg_first_name", "")
            if meta.get("tg_last_name"):
                tg_name += f" {meta.get('tg_last_name')}"
            issued = meta.get("issued_at", meta.get("created_at", "—"))
            tg_details = (
                f"📱 **Telegram:** {tg_user}\n"
                f"👤 **Имя:** {tg_name or '—'}\n"
                f"🆔 **Telegram ID:** `{tg_id}`\n"
                f"📅 **Выдан:** `{issued}`\n\n"
            )

        if sub_info:
            sub_url = sub_info["sub_url"]
            sb_json = sub_info["singbox_json_url"]
            hy2_json = sub_info.get("hy2_json_url", "")
            token_preview = sub_info["token"][:6] + "..." + sub_info["token"][-4:]
            msg = (
                f"👤 **Пользователь:** `{username}`\n"
                f"{tg_details}"
                f"🔑 **Секретный токен:** `{token_preview}`\n\n"
                f"📊 **Использование трафика:**\n"
                f"  • ⬇️ **Скачано (Download):** `{u_stats['formatted_downlink']}`\n"
                f"  • ⬆️ **Загружено (Upload):** `{u_stats['formatted_uplink']}`\n"
                f"  • 🔄 **Всего:** `{u_stats['formatted_total']}`\n\n"
                f"📋 **Ссылка на подписку:**\n`{sub_url}`\n\n"
                f"📦 **Конфиг Sing-Box:**\n`{sb_json}`\n"
            )
            json_row = [InlineKeyboardButton("📦 Sing-Box JSON", url=sb_json)]
            if hy2_json:
                json_row.append(InlineKeyboardButton("🚀 Hysteria2 JSON", url=hy2_json))

            keyboard = [
                [InlineKeyboardButton("🌐 Открыть подписку", url=sub_url)],
                json_row,
                [InlineKeyboardButton("🔄 Ротировать токен", callback_data=f"rot_{username}")],
                [InlineKeyboardButton("🔄 Сбросить трафик", callback_data=f"rst_{username}")],
                [InlineKeyboardButton("🗑 Удалить ключ", callback_data=f"del_{username}")]
            ]
        else:
            msg = (
                f"👤 **Пользователь:** `{username}`\n"
                f"{tg_details}"
                f"📊 **Использование трафика:**\n"
                f"  • ⬇️ **Скачано (Download):** `{u_stats['formatted_downlink']}`\n"
                f"  • ⬆️ **Загружено (Upload):** `{u_stats['formatted_uplink']}`\n"
                f"  • 🔄 **Всего:** `{u_stats['formatted_total']}`\n\n"
                f"⚠️ Активная токенизированная подписка не найдена в реестре."
            )
            keyboard = [
                [InlineKeyboardButton("🔄 Сгенерировать токен", callback_data=f"rot_{username}")],
                [InlineKeyboardButton("🔄 Сбросить трафик", callback_data=f"rst_{username}")],
                [InlineKeyboardButton("🗑 Удалить ключ", callback_data=f"del_{username}")]
            ]
        await query.message.reply_text(msg, parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(keyboard))
    elif data.startswith("rst_"):
        username = data[4:]
        reset_user_traffic(username)
        await query.answer(f"Трафик {username} сброшен на 0 B")
        await query.message.reply_text(
            f"✅ Трафик пользователя `{username}` успешно сброшен на **0 B**.",
            parse_mode="Markdown"
        )
    elif data in ("show_stats", "refresh_stats"):
        await query.answer("Обновление статистики...")
        await stats_command(update, context)
    elif data.startswith("rot_"):
        username = data[4:]
        try:
            new_sub = rotate_subscription_token(
                username=username,
                domain=DOMAIN,
                subs_path=SUBS_PATH,
                vless_path=VLESS_PATH,
                trojan_path=TROJAN_PATH,
                www_dir=WWW_DIR,
                reality_port=REALITY_PORT,
                xhttp_port=XHTTP_PORT,
                hy2_port=HY2_PORT,
                hy2_obfs_password=HY2_OBFS_PASSWORD,
                reality_public_key=REALITY_PUBLIC_KEY,
                reality_short_id=REALITY_SHORT_ID,
                reality_sni=REALITY_SNI,
                xhttp_path=XHTTP_PATH,
                vless_template=VLESS_TEMPLATE,
                trojan_template=TROJAN_TEMPLATE,
                hy2_template=HY2_TEMPLATE,
                config_path=CONFIG_JSON
            )
            new_sub_url = new_sub["sub_url"]
            token_preview = new_sub["token"][:6] + "..." + new_sub["token"][-4:]
            msg = (
                f"🔄 **Токен подписки успешно обновлён!**\n\n"
                f"👤 **Пользователь:** `{username}`\n"
                f"🔑 **Новый токен:** `{token_preview}`\n"
                f"⚠️ *Предыдущая ссылка на подписку аннулирована.*\n\n"
                f"📋 **Новая ссылка на подписку:**\n`{new_sub_url}`\n\n"
                f"📦 **Конфиг Sing-Box:**\n`{new_sub['singbox_json_url']}`"
            )
            rot_buttons = [InlineKeyboardButton("🌐 Открыть новую подписку", url=new_sub_url)]
            if new_sub.get("hy2_json_url"):
                rot_buttons.append(InlineKeyboardButton("🚀 Hysteria2 JSON", url=new_sub["hy2_json_url"]))
            keyboard = [
                rot_buttons,
                [InlineKeyboardButton("🗑 Удалить ключ", callback_data=f"del_{username}")]
            ]
            await query.message.reply_text(msg, parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(keyboard))
        except Exception as e:
            logger.error(f"Error rotating subscription token for {username}: {e}")
            await query.message.reply_text(f"❌ Ошибка ротации токена: {e}")


async def text_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not user:
        return

    text = update.message.text.strip()

    if is_admin(user.id):
        if text in ("➕ Создать ключ", "➕ Создать ключ Incy"):
            uname = f"user_{uuid.uuid4().hex[:6]}"
            await process_new_user(update, uname)
        elif text in ("👥 Список ключей", "👥 Список участников"):
            await list_users_command(update, context)
        elif text in ("📊 Трафик пользователей", "📊 Трафик", "📊 Статистика", "/stats"):
            await stats_command(update, context)
        elif text == "📊 Статус сервера":
            await status_command(update, context)
        elif re.match(r"^[a-zA-Z0-9_-]+$", text) and not text.startswith("/"):
            await process_new_user(update, text)
        else:
            await update.message.reply_text(
                "ℹ️ Чтобы создать ключ, введите `/new <имя>` или нажмите кнопку «➕ Создать ключ».",
                reply_markup=get_admin_keyboard()
            )
    else:
        if text in ("🚀 Запросить доступ", "🚀 Получить доступ"):
            await request_access_handler(update, context)
        elif text in ("📱 Мой профиль", "📱 Моя подписка"):
            await show_user_profile(update, context)
        elif text in ("📊 Мой трафик", "📊 Трафик"):
            await show_user_traffic(update, context)
        elif text in ("📖 Инструкция", "📖 Инструкция по подключению", "/help"):
            await show_user_guide(update, context)
        else:
            existing = get_user_by_tg_id(user.id)
            kb = get_user_registered_keyboard() if existing else get_user_unregistered_keyboard()
            await update.message.reply_text("Пожалуйста, воспользуйтесь кнопками меню:", reply_markup=kb)


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Global unhandled exception logger and user notification."""
    logger.error("Unhandled exception processing update: %s", context.error, exc_info=context.error)
    if isinstance(update, Update) and update.effective_message:
        try:
            await update.effective_message.reply_text(
                "⚠️ Произошла внутренняя ошибка при обработке запроса. Подробности записаны в системный журнал."
            )
        except Exception:
            pass


def main():
    try:
        migrated = sync_subscriptions_from_config(
            config_path=CONFIG_JSON,
            domain=DOMAIN,
            subs_path=SUBS_PATH,
            vless_path=VLESS_PATH,
            trojan_path=TROJAN_PATH,
            www_dir=WWW_DIR,
            reality_port=REALITY_PORT,
            xhttp_port=XHTTP_PORT,
            hy2_port=HY2_PORT,
            hy2_obfs_password=HY2_OBFS_PASSWORD,
            reality_public_key=REALITY_PUBLIC_KEY,
            reality_short_id=REALITY_SHORT_ID,
            reality_sni=REALITY_SNI,
            xhttp_path=XHTTP_PATH,
            vless_template=VLESS_TEMPLATE,
            trojan_template=TROJAN_TEMPLATE,
            hy2_template=HY2_TEMPLATE
        )
        if migrated > 0:
            logger.info("Migrated %d legacy user(s) to secure tokenized subscriptions.", migrated)
    except Exception as sync_err:
        logger.warning("Subscription synchronization encountered a non-fatal error: %s", sync_err)

    # Automatically ensure Sing-box configuration includes Hysteria 2 inbound
    if os.path.exists(CONFIG_JSON):
        try:
            def _setup_singbox_hy2(cfg):
                return ensure_singbox_hy2_config(
                    cfg,
                    domain=DOMAIN,
                    hy2_port=HY2_PORT,
                    hy2_obfs_password=HY2_OBFS_PASSWORD
                )

            atomic_modify_singbox_config(
                mutation_fn=_setup_singbox_hy2,
                config_path=CONFIG_JSON,
                control_runner=run_privileged_control
            )
            logger.info("Sing-box Hysteria 2 inbound configuration verified.")
        except Exception as hy2_err:
            logger.warning("Could not automatically configure Sing-box Hysteria 2: %s", hy2_err)

    # Automatically ensure Xray configuration includes traffic statistics API, policy & removes legacy MASQUE inbound
    if os.path.exists(XRAY_CONFIG_JSON):
        try:
            def _setup_xray_features(cfg):
                cfg = ensure_xray_stats_config(cfg)
                cfg = remove_xray_masque_config(cfg)
                return cfg

            atomic_modify_xray_config(
                mutation_fn=_setup_xray_features,
                config_path=XRAY_CONFIG_JSON,
                control_runner=run_privileged_control
            )
            logger.info("Xray traffic statistics API verified and legacy MASQUE removed.")
        except Exception as xray_stats_err:
            logger.warning("Could not automatically configure Xray features: %s", xray_stats_err)

    app = Application.builder().token(TOKEN).build()

    app.add_handler(CommandHandler("start", start_handler))
    app.add_handler(CommandHandler("help", show_user_guide))
    app.add_handler(CommandHandler("cabinet", start_handler))
    app.add_handler(CommandHandler("profile", show_user_profile))
    app.add_handler(CommandHandler("get", request_access_handler))
    app.add_handler(CommandHandler("new", new_user_command))
    app.add_handler(CommandHandler("add", new_user_command))
    app.add_handler(CommandHandler("list", list_users_command))
    app.add_handler(CommandHandler("users", list_users_command))
    app.add_handler(CommandHandler("stats", stats_command))
    app.add_handler(CommandHandler("traffic", stats_command))
    app.add_handler(CommandHandler("del", del_user_command))
    app.add_handler(CommandHandler("status", status_command))

    app.add_handler(CallbackQueryHandler(callback_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, text_handler))
    app.add_error_handler(error_handler)

    # Periodic background stats sync
    if getattr(app, "job_queue", None):
        async def scheduled_stats_sync(context: ContextTypes.DEFAULT_TYPE):
            try:
                sync_traffic_stats()
            except Exception as e:
                logger.debug("Scheduled stats sync error: %s", e)

        app.job_queue.run_repeating(scheduled_stats_sync, interval=120, first=10)

    logger.info("Bot starting...")
    app.run_polling()


if __name__ == "__main__":
    main()
