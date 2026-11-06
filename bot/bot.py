import os
import sys
import json
import uuid
import re
import io
import base64
import subprocess
import logging
from typing import Optional, Set

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
    add_user_to_config,
    delete_user_from_config,
    list_users_from_config,
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
    SubscriptionError
)
from xray_manager import (
    load_xray_config,
    list_users_from_xray,
    add_user_to_xray,
    delete_user_from_xray,
    atomic_modify_xray_config,
    XrayConfigError
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
TG_DOMAIN = os.getenv("TG_DOMAIN", f"tg.{DOMAIN}").strip()
SUBS_PATH = os.getenv("SUBS_PATH", "sub").strip()
VLESS_PATH = os.getenv("VLESS_PATH", "vless").strip()
TROJAN_PATH = os.getenv("TROJAN_PATH", "trojan").strip()

CONFIG_JSON = os.getenv("SINGBOX_CONFIG_JSON", "/etc/sing-box/config.json").strip()
WWW_DIR = os.getenv("SUBS_DIR", f"/var/www/{SUBS_PATH}").strip()
VLESS_TEMPLATE = os.getenv("VLESS_TEMPLATE", "/opt/incy-bot/template-vless.json").strip()
TROJAN_TEMPLATE = os.getenv("TROJAN_TEMPLATE", "/opt/incy-bot/template-trj.json").strip()
SINGBOX_CONTROL = os.getenv("SINGBOX_CONTROL_BIN", "/usr/local/bin/singbox-control").strip()

# Dual-transport modern VPN: Xray REALITY & XHTTP settings
REALITY_PORT = int(os.getenv("REALITY_PORT", "8443").strip())
XHTTP_PORT = int(os.getenv("XHTTP_PORT", "8444").strip())
REALITY_PUBLIC_KEY = os.getenv("REALITY_PUBLIC_KEY", "").strip()
REALITY_SHORT_ID = os.getenv("REALITY_SHORT_ID", "").strip()
REALITY_SNI = os.getenv("REALITY_SNI", "").strip() or DOMAIN
REALITY_DEST = os.getenv("REALITY_DEST", "127.0.0.1:443").strip()
XHTTP_PATH = os.getenv("XHTTP_PATH", "xhttp").strip()
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


def get_keyboard():
    keyboard = [
        ["➕ Создать ключ", "👥 Список ключей"],
        ["🌐 Telegram Web Proxy", "📊 Статус сервера"]
    ]
    return ReplyKeyboardMarkup(keyboard, resize_keyboard=True)


def get_web_proxy_info() -> dict:
    try:
        cmd = []
        if os.geteuid() != 0:
            cmd.append("sudo")
        cmd.extend([SINGBOX_CONTROL, "tgproxy-link"])

        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10
        )
        output = res.stdout
        link_match = re.search(r"Proxy link:\s+(https://\S+)", output)
        tg_link_match = re.search(r"Proxy link \(tg://\):\s+(\S+)", output)
        server_match = re.search(r"Proxy server [^:]*:\s+(\S+)", output)
        secret_match = re.search(r"Proxy secret [^:]*:\s+(\S+)", output)

        return {
            "link": link_match.group(1) if link_match else "",
            "tg_link": tg_link_match.group(1) if tg_link_match else "",
            "server": server_match.group(1) if server_match else "",
            "secret": secret_match.group(1) if secret_match else ""
        }
    except Exception as e:
        logger.error(f"Error getting web proxy info: {e}")
        return {}


def create_user_singbox(username: str) -> Optional[dict]:
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
                mutation_fn=lambda cfg: add_user_to_xray(cfg, valid_username, new_uuid),
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
            reality_public_key=REALITY_PUBLIC_KEY,
            reality_short_id=REALITY_SHORT_ID,
            reality_sni=REALITY_SNI,
            xhttp_path=XHTTP_PATH,
            vless_template=VLESS_TEMPLATE,
            trojan_template=TROJAN_TEMPLATE
        )

        return {
            "username": valid_username,
            "uuid": new_uuid,
            "token": sub_info["token"],
            "incy_sub_url": sub_info["sub_url"],
            "singbox_json_url": sub_info["singbox_json_url"],
            "incy_deeplink": sub_info["deeplink"],
            "vless_link": sub_info["vless_link"],
            "vless_reality_link": sub_info.get("vless_reality_link", ""),
            "vless_xhttp_link": sub_info.get("vless_xhttp_link", ""),
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
    return list_users_from_config(config_path=CONFIG_JSON)


def generate_qr(data: str) -> io.BytesIO:
    qr = qrcode.QRCode(version=1, box_size=8, border=2)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    bio = io.BytesIO()
    img.save(bio, format="PNG")
    bio.seek(0)
    return bio


@admin_required
async def start_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        f"👋 Здравствуйте, {update.effective_user.first_name}!\n\n"
        "Панель управления **Dual-Transport Stealth VPN (Xray REALITY / Sing-Box)** и **Telegram Web Proxy**.\n\n"
        "⚡ **Доступные команды:**\n"
        "• `/new <имя>` — сгенерировать ключ и универсальную подписку\n"
        "• `/list` — список всех пользователей и ключей\n"
        "• `/del <имя>` — удалить пользователя\n"
        "• `/proxy` — ссылки на Telegram Web Proxy\n"
        "• `/status` — статус сервера и служб\n\n"
        "Или используйте кнопки внизу 👇"
    )
    await update.message.reply_text(msg, reply_markup=get_keyboard(), parse_mode="Markdown")


@admin_required
async def new_user_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if context.args:
        username = context.args[0].strip()
    else:
        username = f"user_{uuid.uuid4().hex[:6]}"

    await process_new_user(update, username)


async def process_new_user(update: Update, username: str):
    res = create_user_singbox(username)
    if not res:
        await update.message.reply_text("❌ Ошибка: имя пользователя может содержать только латинские буквы, цифры и знаки `-`, `_`.")
        return

    if "error" in res:
        await update.message.reply_text(f"⚠️ {res['error']}")
        return

    vless_link = res["vless_link"]
    reality_link = res.get("vless_reality_link", "")
    xhttp_link = res.get("vless_xhttp_link", "")
    incy_sub_url = res["incy_sub_url"]
    singbox_json_url = res["singbox_json_url"]
    incy_deeplink = res["incy_deeplink"]

    if reality_link:
        caption = (
            f"✅ **Ключ успешно создан!**\n\n"
            f"👤 **Пользователь:** `{username}`\n"
            f"🔑 **UUID:** `{res['uuid']}`\n\n"
            f"📋 **Универсальная подписка (4 в 1):**\n"
            f"`{incy_sub_url}`\n\n"
            f"📦 **Конфиг Sing-Box JSON:**\n"
            f"`{singbox_json_url}`\n\n"
            f"💡 *Отсканируйте QR-код для подключения VLESS-REALITY-Vision или скопируйте ссылку подписки.*"
        )
    else:
        caption = (
            f"✅ **Ключ успешно создан!**\n\n"
            f"👤 **Пользователь:** `{username}`\n"
            f"🔑 **UUID:** `{res['uuid']}`\n\n"
            f"📋 **Ссылка на подписку:**\n"
            f"`{incy_sub_url}`\n\n"
            f"📦 **Конфиг Sing-Box JSON:**\n"
            f"`{singbox_json_url}`\n\n"
            f"💡 *Отсканируйте QR-код в приложении или скопируйте ссылку подписки.*"
        )

    keyboard = [
        [InlineKeyboardButton("🌐 Открыть подписку", url=incy_sub_url)],
        [InlineKeyboardButton("📦 Sing-Box JSON", url=singbox_json_url)],
        [InlineKeyboardButton("🗑 Удалить этот ключ", callback_data=f"del_{username}")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    # QR encodes primary connection URI for 1-tap instant camera import
    primary_qr_link = reality_link if reality_link else vless_link
    qr_img = generate_qr(primary_qr_link)

    try:
        await update.message.reply_photo(
            photo=qr_img,
            caption=caption[:1024],
            parse_mode="Markdown",
            reply_markup=reply_markup
        )
    except Exception as photo_err:
        logger.warning(f"Failed to send QR photo: {photo_err}, falling back to text message")
        await update.message.reply_text(
            caption,
            parse_mode="Markdown",
            reply_markup=reply_markup,
            disable_web_page_preview=True
        )

    # Follow up with direct connection strings
    if reality_link:
        direct_msg = (
            f"⚡ **Прямые ссылки для ручного импорта (`{username}`):**\n\n"
            f"1️⃣ **[Основной] VLESS + REALITY + Vision (TCP):**\n"
            f"`{reality_link}`\n\n"
            f"2️⃣ **[Резерв] VLESS + XHTTP + REALITY:**\n"
            f"`{xhttp_link}`\n\n"
            f"3️⃣ **[WS Legacy] VLESS + WS + TLS:**\n"
            f"`{vless_link}`"
        )
    else:
        direct_msg = (
            f"⚡ **Прямая ссылка VLESS (`{username}`):**\n\n"
            f"`{vless_link}`"
        )

    await update.message.reply_text(
        direct_msg,
        parse_mode="Markdown",
        disable_web_page_preview=True
    )


@admin_required
async def list_users_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    users = get_users_list()
    if not users:
        await update.message.reply_text("Список пользователей пуст.", reply_markup=get_keyboard())
        return

    msg = f"👥 **Список пользователей Sing-Box ({len(users)}):**\n\n"
    keyboard = []
    for u in users:
        msg += f"• `{u}`\n"
        keyboard.append([
            InlineKeyboardButton(f"🔗 {u}", callback_data=f"info_{u}"),
            InlineKeyboardButton("🗑 Удалить", callback_data=f"del_{u}")
        ])

    reply_markup = InlineKeyboardMarkup(keyboard) if keyboard else None
    await update.message.reply_text(msg, parse_mode="Markdown", reply_markup=reply_markup)


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
async def proxy_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    info = get_web_proxy_info()
    link = info.get("link", "")
    server = info.get("server", "")
    secret = info.get("secret", "")

    msg = (
        "🌐 **Telegram Web Proxy (tproxy-server)**\n\n"
        "Официальный веб-прокси Telegram нового поколения (маскировка под HTTPS-сайт через WebSocket).\n\n"
        f"🖥 **Сервер:** `{server}`\n"
        f"🔐 **Секрет:** `{secret}`\n\n"
        f"🔗 **Ссылка для подключения:**\n{link}\n"
    )

    keyboard = []
    if link:
        keyboard.append([InlineKeyboardButton("🚀 Подключить в Telegram", url=link)])

    reply_markup = InlineKeyboardMarkup(keyboard) if keyboard else None
    await update.message.reply_text(msg, parse_mode="Markdown", reply_markup=reply_markup)


@admin_required
async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    def get_svc_status(svc: str) -> str:
        r = subprocess.run(["systemctl", "is-active", svc], capture_output=True, text=True)
        return "🟢 Active" if r.stdout.strip() == "active" else "🔴 Inactive"

    def get_docker_status(container: str) -> str:
        try:
            r = subprocess.run(["docker", "inspect", "-f", "{{.State.Status}}", container], capture_output=True, text=True)
            status = r.stdout.strip()
            return "🟢 Running" if status == "running" else f"🔴 {status}"
        except Exception:
            return "⚪ Unchecked"

    mem_r = subprocess.run(["free", "-m"], capture_output=True, text=True)
    df_r = subprocess.run(["df", "-h", "/"], capture_output=True, text=True)

    sb_st = get_svc_status("sing-box")
    xr_st = get_svc_status("xray")
    ng_st = get_svc_status("nginx")
    wp_st = get_docker_status("tgweb-proxy")

    msg = (
        "📊 **Статус сервера:**\n\n"
        f"📦 **Sing-Box:** {sb_st}\n"
        f"⚡ **Xray-Core (REALITY/XHTTP):** {xr_st}\n"
        f"🌐 **Nginx:** {ng_st}\n"
        f"✈️ **Telegram Web Proxy:** {wp_st}\n\n"
        f"💾 **Диск:**\n```{df_r.stdout.strip()}```\n\n"
        f"🧠 **Память:**\n```{mem_r.stdout.strip()}```"
    )
    await update.message.reply_text(msg, parse_mode="Markdown")


@admin_required
async def callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    data = query.data
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
        sub_info = get_subscription_info(username, DOMAIN, SUBS_PATH)
        if sub_info:
            sub_url = sub_info["sub_url"]
            sb_json = sub_info["singbox_json_url"]
            token_preview = sub_info["token"][:6] + "..." + sub_info["token"][-4:]
            msg = (
                f"👤 **Пользователь:** `{username}`\n"
                f"🔑 **Секретный токен:** `{token_preview}`\n\n"
                f"📋 **Ссылка на подписку:**\n`{sub_url}`\n\n"
                f"📦 **Конфиг Sing-Box:**\n`{sb_json}`\n"
            )
            keyboard = [
                [InlineKeyboardButton("🌐 Открыть подписку", url=sub_url)],
                [InlineKeyboardButton("🔄 Ротировать токен", callback_data=f"rot_{username}")],
                [InlineKeyboardButton("🗑 Удалить ключ", callback_data=f"del_{username}")]
            ]
        else:
            msg = f"👤 **Пользователь:** `{username}`\n\n⚠️ Активная токенизированная подписка не найдена в реестре."
            keyboard = [
                [InlineKeyboardButton("🔄 Сгенерировать токен", callback_data=f"rot_{username}")],
                [InlineKeyboardButton("🗑 Удалить ключ", callback_data=f"del_{username}")]
            ]
        await query.message.reply_text(msg, parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(keyboard))
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
                reality_public_key=REALITY_PUBLIC_KEY,
                reality_short_id=REALITY_SHORT_ID,
                reality_sni=REALITY_SNI,
                xhttp_path=XHTTP_PATH,
                vless_template=VLESS_TEMPLATE,
                trojan_template=TROJAN_TEMPLATE,
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
            keyboard = [
                [InlineKeyboardButton("🌐 Открыть новую подписку", url=new_sub_url)],
                [InlineKeyboardButton("🗑 Удалить ключ", callback_data=f"del_{username}")]
            ]
            await query.message.reply_text(msg, parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(keyboard))
        except Exception as e:
            logger.error(f"Error rotating subscription token for {username}: {e}")
            await query.message.reply_text(f"❌ Ошибка ротации токена: {e}")


@admin_required
async def text_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()
    if text in ("➕ Создать ключ", "➕ Создать ключ Incy"):
        uname = f"user_{uuid.uuid4().hex[:6]}"
        await process_new_user(update, uname)
    elif text == "👥 Список ключей":
        await list_users_command(update, context)
    elif text == "🌐 Telegram Web Proxy":
        await proxy_command(update, context)
    elif text == "📊 Статус сервера":
        await status_command(update, context)
    else:
        if re.match(r"^[a-zA-Z0-9_-]+$", text) and not text.startswith("/"):
            await process_new_user(update, text)
        else:
            await update.message.reply_text(
                "ℹ️ Чтобы создать ключ, введите `/new <имя>` или нажмите кнопку «➕ Создать ключ».",
                reply_markup=get_keyboard()
            )


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
            reality_public_key=REALITY_PUBLIC_KEY,
            reality_short_id=REALITY_SHORT_ID,
            reality_sni=REALITY_SNI,
            xhttp_path=XHTTP_PATH,
            vless_template=VLESS_TEMPLATE,
            trojan_template=TROJAN_TEMPLATE
        )
        if migrated > 0:
            logger.info("Migrated %d legacy user(s) to secure tokenized subscriptions.", migrated)
    except Exception as sync_err:
        logger.warning("Subscription synchronization encountered a non-fatal error: %s", sync_err)

    app = Application.builder().token(TOKEN).build()

    app.add_handler(CommandHandler("start", start_handler))
    app.add_handler(CommandHandler("help", start_handler))
    app.add_handler(CommandHandler("new", new_user_command))
    app.add_handler(CommandHandler("add", new_user_command))
    app.add_handler(CommandHandler("list", list_users_command))
    app.add_handler(CommandHandler("users", list_users_command))
    app.add_handler(CommandHandler("del", del_user_command))
    app.add_handler(CommandHandler("proxy", proxy_command))
    app.add_handler(CommandHandler("webproxy", proxy_command))
    app.add_handler(CommandHandler("status", status_command))

    app.add_handler(CallbackQueryHandler(callback_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, text_handler))
    app.add_error_handler(error_handler)

    logger.info("Bot starting...")
    app.run_polling()


if __name__ == "__main__":
    main()
