import os
import sys
import json
import uuid
import re
import io
import base64
import subprocess
import logging
from typing import Optional, List

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
ADMIN_IDS_RAW = os.getenv("TELEGRAM_ADMIN_IDS", "").strip()
ADMIN_IDS: List[int] = [int(x.strip()) for x in ADMIN_IDS_RAW.split(",") if x.strip().isdigit()]

DOMAIN = os.getenv("MAIN_DOMAIN", "localhost").strip()
TG_DOMAIN = os.getenv("TG_DOMAIN", f"tg.{DOMAIN}").strip()
SUBS_PATH = os.getenv("SUBS_PATH", "sub").strip()
VLESS_PATH = os.getenv("VLESS_PATH", "vless").strip()
TROJAN_PATH = os.getenv("TROJAN_PATH", "trojan").strip()

CONFIG_JSON = os.getenv("SINGBOX_CONFIG_JSON", "/etc/sing-box/config.json").strip()
WWW_DIR = os.getenv("SUBS_DIR", f"/var/www/{SUBS_PATH}").strip()
VLESS_TEMPLATE = os.getenv("VLESS_TEMPLATE", "/opt/incy-bot/template-vless.json").strip()
TROJAN_TEMPLATE = os.getenv("TROJAN_TEMPLATE", "/opt/incy-bot/template-trj.json").strip()

if not TOKEN:
    logger.error("FATAL: TELEGRAM_BOT_TOKEN environment variable is not set!")
    sys.exit(1)


def is_admin(user_id: int) -> bool:
    return not ADMIN_IDS or user_id in ADMIN_IDS


def get_keyboard():
    keyboard = [
        ["➕ Создать ключ Incy", "👥 Список ключей"],
        ["🌐 Telegram Web Proxy", "📊 Статус сервера"]
    ]
    return ReplyKeyboardMarkup(keyboard, resize_keyboard=True)


def get_web_proxy_info() -> dict:
    try:
        res = subprocess.run(
            ["docker", "exec", "tgweb-proxy", "show-link"],
            capture_output=True,
            text=True,
            timeout=5
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
    if not re.match(r"^[a-zA-Z0-9_-]+$", username):
        return None

    try:
        with open(CONFIG_JSON, "r", encoding="utf-8") as f:
            cfg = json.load(f)

        # Check existing user
        for ib in cfg.get("inbounds", []):
            if ib.get("tag") in ("vless-in", "trojan-in"):
                for u in ib.get("users", []):
                    if u.get("name") == username:
                        return {"error": f"Пользователь {username} уже существует!"}

        new_uuid = str(uuid.uuid4())
        new_pass = uuid.uuid4().hex[:16]

        for ib in cfg.get("inbounds", []):
            if ib.get("tag") == "vless-in":
                ib.setdefault("users", []).append({"name": username, "uuid": new_uuid})
            elif ib.get("tag") == "trojan-in":
                ib.setdefault("users", []).append({"name": username, "password": new_pass})

        with open(CONFIG_JSON, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)

        # Reload sing-box core
        subprocess.run(["systemctl", "reload", "sing-box.service"], check=True)

        os.makedirs(WWW_DIR, exist_ok=True)

        # 1. Base64 Incy / Happ / V2Ray subscription (.txt)
        vless_link = f"vless://{new_uuid}@{DOMAIN}:443?security=tls&encryption=none&type=ws&path=%2F{VLESS_PATH}#{DOMAIN}-VLESS-{username}"
        trojan_link = f"trojan://{new_pass}@{DOMAIN}:443?security=tls&type=ws&path=%2F{TROJAN_PATH}#{DOMAIN}-Trojan-{username}"
        sub_body = f"{vless_link}\n{trojan_link}\n"
        sub_b64 = base64.b64encode(sub_body.encode("utf-8")).decode("utf-8")

        sub_txt_file = f"{WWW_DIR}/{username}.txt"
        with open(sub_txt_file, "w", encoding="utf-8") as f:
            f.write(sub_b64)
        os.chmod(sub_txt_file, 0o644)

        # 2. Sing-Box full JSON profile from template
        if os.path.exists(VLESS_TEMPLATE):
            with open(VLESS_TEMPLATE, "r", encoding="utf-8") as f:
                vless_client = json.load(f)

            for ob in vless_client.get("outbounds", []):
                if ob.get("tag") == "proxy":
                    ob["uuid"] = new_uuid

            client_file = f"{WWW_DIR}/{username}-VLESS-CLIENT.json"
            with open(client_file, "w", encoding="utf-8") as f:
                json.dump(vless_client, f, indent=2, ensure_ascii=False)
            os.chmod(client_file, 0o644)

        # 3. Trojan full JSON profile from template
        if os.path.exists(TROJAN_TEMPLATE):
            with open(TROJAN_TEMPLATE, "r", encoding="utf-8") as f:
                trj_client = json.load(f)

            for ob in trj_client.get("outbounds", []):
                if ob.get("tag") == "proxy":
                    ob["password"] = new_pass

            trj_file = f"{WWW_DIR}/{username}-TRJ-CLIENT.json"
            with open(trj_file, "w", encoding="utf-8") as f:
                json.dump(trj_client, f, indent=2, ensure_ascii=False)
            os.chmod(trj_file, 0o644)

        incy_sub_url = f"https://{DOMAIN}/{SUBS_PATH}/{username}.txt"
        singbox_json_url = f"https://{DOMAIN}/{SUBS_PATH}/{username}-VLESS-CLIENT.json"
        incy_deeplink = f"incy://add/{incy_sub_url}"

        return {
            "username": username,
            "uuid": new_uuid,
            "incy_sub_url": incy_sub_url,
            "singbox_json_url": singbox_json_url,
            "incy_deeplink": incy_deeplink,
            "vless_link": vless_link,
            "trojan_link": trojan_link
        }
    except Exception as e:
        logger.error(f"Error creating user: {e}", exc_info=True)
        return {"error": str(e)}


def delete_user_singbox(username: str) -> bool:
    try:
        with open(CONFIG_JSON, "r", encoding="utf-8") as f:
            cfg = json.load(f)

        found = False
        for ib in cfg.get("inbounds", []):
            if ib.get("tag") in ("vless-in", "trojan-in"):
                users = ib.get("users", [])
                new_users = [u for u in users if u.get("name") != username]
                if len(new_users) != len(users):
                    ib["users"] = new_users
                    found = True

        if found:
            with open(CONFIG_JSON, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2, ensure_ascii=False)
            subprocess.run(["systemctl", "reload", "sing-box.service"], check=True)

        for f_name in (f"{username}.txt", f"{username}-VLESS-CLIENT.json", f"{username}-TRJ-CLIENT.json"):
            p = f"{WWW_DIR}/{f_name}"
            if os.path.exists(p):
                os.remove(p)

        return found
    except Exception as e:
        logger.error(f"Error deleting user {username}: {e}")
        return False


def get_users_list() -> list:
    try:
        with open(CONFIG_JSON, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        users = []
        for ib in cfg.get("inbounds", []):
            if ib.get("tag") == "vless-in":
                for u in ib.get("users", []):
                    users.append(u.get("name"))
        return sorted(list(set(users)))
    except Exception as e:
        logger.error(f"Error listing users: {e}")
        return []


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
    if not is_admin(update.effective_user.id):
        await update.message.reply_text("⛔ Доступ запрещён.")
        return

    msg = (
        f"👋 Здравствуйте, {update.effective_user.first_name}!\n\n"
        "Панель управления **Sing-Box Incy** и **Telegram Web Proxy**.\n\n"
        "⚡ **Доступные команды:**\n"
        "• `/new <имя>` — сгенерировать ключ для Incy\n"
        "• `/list` — список всех пользователей и ключей\n"
        "• `/del <имя>` — удалить пользователя\n"
        "• `/proxy` — ссылки на Telegram Web Proxy\n"
        "• `/status` — статус сервера и служб\n\n"
        "Или используйте кнопки внизу 👇"
    )
    await update.message.reply_text(msg, reply_markup=get_keyboard(), parse_mode="Markdown")


async def new_user_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        await update.message.reply_text("⛔ Доступ запрещён.")
        return

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
    incy_sub_url = res["incy_sub_url"]
    singbox_json_url = res["singbox_json_url"]
    incy_deeplink = res["incy_deeplink"]

    caption = (
        f"✅ **Ключ для Incy успешно создан!**\n\n"
        f"👤 **Пользователь:** `{username}`\n"
        f"🔑 **UUID:** `{res['uuid']}`\n\n"
        f"📋 **1. Ссылка на ПОДПИСКУ (Incy / Happ / V2Ray):**\n"
        f"`{incy_sub_url}`\n\n"
        f"⚡ **2. Прямая VLESS ссылка (нажмите для копирования):**\n"
        f"`{vless_link}`\n\n"
        f"📲 **3. Диплинк для добавления подписки в Incy в 1 клик:**\n"
        f"`{incy_deeplink}`\n\n"
        f"📦 **4. Конфиг Sing-Box JSON:**\n"
        f"`{singbox_json_url}`\n\n"
        f"💡 *В приложении Incy нажмите «+» ➔ «Сканировать QR-код» и наведите камеру на QR ниже, либо вставьте ссылку подписки!*"
    )

    keyboard = [
        [InlineKeyboardButton("🌐 Открыть подписку Incy", url=incy_sub_url)],
        [InlineKeyboardButton("📦 Sing-Box JSON", url=singbox_json_url)],
        [InlineKeyboardButton("🗑 Удалить этот ключ", callback_data=f"del_{username}")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    # QR encodes direct VLESS URI for 1-tap instant camera import in Incy
    qr_img = generate_qr(vless_link)

    await update.message.reply_photo(
        photo=qr_img,
        caption=caption,
        parse_mode="Markdown",
        reply_markup=reply_markup
    )


async def list_users_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        await update.message.reply_text("⛔ Доступ запрещён.")
        return

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
            InlineKeyboardButton(f"🗑 Удалить", callback_data=f"del_{u}")
        ])

    reply_markup = InlineKeyboardMarkup(keyboard) if keyboard else None
    await update.message.reply_text(msg, parse_mode="Markdown", reply_markup=reply_markup)


async def del_user_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        await update.message.reply_text("⛔ Доступ запрещён.")
        return

    if not context.args:
        await update.message.reply_text("Использование: `/del <имя_пользователя>`", parse_mode="Markdown")
        return

    username = context.args[0].strip()
    if delete_user_singbox(username):
        await update.message.reply_text(f"🗑 Пользователь `{username}` удалён.", parse_mode="Markdown")
    else:
        await update.message.reply_text(f"⚠️ Пользователь `{username}` не найден.")


async def proxy_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        await update.message.reply_text("⛔ Доступ запрещён.")
        return

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


async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        await update.message.reply_text("⛔ Доступ запрещён.")
        return

    def get_svc_status(svc: str) -> str:
        r = subprocess.run(["systemctl", "is-active", svc], capture_output=True, text=True)
        return "🟢 Active" if r.stdout.strip() == "active" else "🔴 Inactive"

    def get_docker_status(container: str) -> str:
        r = subprocess.run(["docker", "inspect", "-f", "{{.State.Status}}", container], capture_output=True, text=True)
        status = r.stdout.strip()
        return "🟢 Running" if status == "running" else f"🔴 {status}"

    mem_r = subprocess.run(["free", "-m"], capture_output=True, text=True)
    df_r = subprocess.run(["df", "-h", "/"], capture_output=True, text=True)

    sb_st = get_svc_status("sing-box")
    ng_st = get_svc_status("nginx")
    wp_st = get_docker_status("tgweb-proxy")

    msg = (
        "📊 **Статус сервера:**\n\n"
        f"📦 **Sing-Box:** {sb_st}\n"
        f"🌐 **Nginx:** {ng_st}\n"
        f"✈️ **Telegram Web Proxy:** {wp_st}\n\n"
        f"💾 **Диск:**\n```{df_r.stdout.strip()}```\n\n"
        f"🧠 **Память:**\n```{mem_r.stdout.strip()}```"
    )
    await update.message.reply_text(msg, parse_mode="Markdown")


async def callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    if not is_admin(query.from_user.id):
        await query.message.reply_text("⛔ Доступ запрещён.")
        return

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
        incy_sub = f"https://{DOMAIN}/{SUBS_PATH}/{username}.txt"
        sb_json = f"https://{DOMAIN}/{SUBS_PATH}/{username}-VLESS-CLIENT.json"
        msg = (
            f"👤 **Пользователь:** `{username}`\n\n"
            f"📋 **Подписка Incy:**\n`{incy_sub}`\n\n"
            f"📦 **Конфиг Sing-Box:**\n`{sb_json}`\n"
        )
        keyboard = [
            [InlineKeyboardButton("🌐 Открыть подписку", url=incy_sub)],
            [InlineKeyboardButton("🗑 Удалить ключ", callback_data=f"del_{username}")]
        ]
        await query.message.reply_text(msg, parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(keyboard))


async def text_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        await update.message.reply_text("⛔ Доступ запрещён.")
        return

    text = update.message.text.strip()
    if text == "➕ Создать ключ Incy":
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
                "ℹ️ Чтобы создать ключ, введите `/new <имя>` или нажмите кнопку «➕ Создать ключ Incy».",
                reply_markup=get_keyboard()
            )


def main():
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

    logger.info("Bot starting...")
    app.run_polling()


if __name__ == "__main__":
    main()
