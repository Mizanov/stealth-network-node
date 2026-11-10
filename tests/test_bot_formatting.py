#!/usr/bin/env python3
"""
Unit tests for Telegram Bot Markdown escaping and subscription delivery formatting.
Verifies:
1. Markdown special characters in usernames/firstnames are escaped.
2. deliver_user_credentials extracts subscription URL correctly and provides clickable inline button.
3. User list rendering handles usernames with underscores without failing Markdown parsing.
"""

import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

# Add bot directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bot")))

# Mock qrcode and telegram modules if not present locally
if "qrcode" not in sys.modules:
    sys.modules["qrcode"] = MagicMock()
if "telegram" not in sys.modules:
    tg_mock = MagicMock()
    class MockInlineKeyboardButton:
        def __init__(self, text, url=None, callback_data=None):
            self.text = text
            self.url = url
            self.callback_data = callback_data
    tg_mock.InlineKeyboardButton = MockInlineKeyboardButton
    class MockInlineKeyboardMarkup:
        def __init__(self, inline_keyboard):
            self.inline_keyboard = inline_keyboard
    tg_mock.InlineKeyboardMarkup = MockInlineKeyboardMarkup
    tg_mock.ReplyKeyboardMarkup = MagicMock()
    sys.modules["telegram"] = tg_mock
if "telegram.ext" not in sys.modules:
    sys.modules["telegram.ext"] = MagicMock()

os.environ["TELEGRAM_BOT_TOKEN"] = "123456:mock_token_for_tests"
os.environ["TELEGRAM_ADMIN_IDS"] = "12345678"

from bot import escape_md, build_hy2_link, format_hy2_section, deliver_user_credentials, list_users_command, callback_handler


class TestBotFormatting(unittest.IsolatedAsyncioTestCase):

    def test_escape_md(self):
        self.assertEqual(escape_md("Olesya_Media"), r"Olesya\_Media")
        self.assertEqual(escape_md("test_user_name"), r"test\_user\_name")
        self.assertEqual(escape_md("*star*"), r"\*star\*")
        self.assertEqual(escape_md("`code`"), r"\`code\`")
        self.assertEqual(escape_md("[test]"), r"\[test]")
        self.assertEqual(escape_md(""), "")
        self.assertEqual(escape_md(None), "")

    async def test_deliver_user_credentials_with_sub_url(self):
        target_msg = AsyncMock()
        sub_info = {
            "token": "tok1234567890abcdef",
            "sub_url": "https://example.com/sub/tok1234567890abcdef.txt",
            "vless_reality_link": "vless://user@example.com:8443?security=reality#Reality",
            "hy2_link": "hysteria2://pass@example.com:443#Hy2",
            "vless_xhttp_link": "vless://user@example.com:8444?security=reality#XHTTP"
        }

        with patch("bot.generate_qr", return_value=MagicMock()):
            await deliver_user_credentials(target_msg, "testuser", sub_info, is_self_service=True)

        self.assertTrue(target_msg.reply_photo.called)
        kwargs = target_msg.reply_photo.call_args.kwargs
        caption = kwargs["caption"]
        reply_markup = kwargs["reply_markup"]

        # Caption must include the subscription link
        self.assertIn("https://example.com/sub/tok1234567890abcdef.txt", caption)
        self.assertNotIn("`_Формируется..._`", caption)

        # Inline keyboard must include the 5-in-1 connect button
        buttons = [btn for row in reply_markup.inline_keyboard for btn in row]
        button_urls = [btn.url for btn in buttons if getattr(btn, "url", None)]
        self.assertIn("https://example.com/sub/tok1234567890abcdef.txt", button_urls)

    async def test_deliver_user_credentials_incy_sub_url_fallback(self):
        target_msg = AsyncMock()
        sub_info = {
            "token": "tok99999",
            "incy_sub_url": "https://example.com/sub/tok99999.txt",
            "vless_reality_link": "vless://user@example.com:8443#Reality"
        }

        with patch("bot.generate_qr", return_value=MagicMock()):
            await deliver_user_credentials(target_msg, "fallbackuser", sub_info, is_self_service=False)

        self.assertTrue(target_msg.reply_photo.called)
        kwargs = target_msg.reply_photo.call_args.kwargs
        caption = kwargs["caption"]
        self.assertIn("https://example.com/sub/tok99999.txt", caption)

    @patch("bot.get_users_list", return_value=["tg_olesya_media", "tg_mizan0v"])
    @patch("bot.sync_traffic_stats")
    @patch("bot.get_user_traffic", return_value={"formatted_total": "1.2 MB", "formatted_downlink": "1.0 MB", "formatted_uplink": "200 KB"})
    @patch("bot.get_all_users_meta", return_value={
        "tg_olesya_media": {
            "meta": {
                "tg_username": "Olesya_Media",
                "tg_first_name": "O l e s y a",
                "tg_id": 2103511203
            }
        },
        "tg_mizan0v": {
            "meta": {
                "tg_username": "Mizan0v",
                "tg_first_name": "Aleksei",
                "tg_id": 659398360
            }
        }
    })
    async def test_list_users_escapes_underscores(self, mock_meta, mock_traffic, mock_sync, mock_users):
        update = MagicMock()
        update.message = AsyncMock()
        update.effective_user.id = 12345678
        context = MagicMock()

        with patch("bot.is_admin", return_value=True):
            await list_users_command(update, context)

        self.assertTrue(update.message.reply_text.called)
        call_args = update.message.reply_text.call_args
        msg = call_args.args[0] if call_args.args else call_args.kwargs.get("text", "")

        # Must escape the underscore in Olesya_Media
        self.assertIn(r"@Olesya\_Media", msg)
        self.assertIn("tg_olesya_media", msg)

    def test_hy2_helpers(self):
        link = build_hy2_link("alice", "pass123")
        self.assertIn("hysteria2://pass123@", link)
        self.assertIn("#Hysteria2-alice", link)
        self.assertEqual(build_hy2_link("alice", ""), "")

        section = format_hy2_section("https://example.com/tok-hy2.json", link)
        self.assertIn("Конфиг Hysteria 2 (JSON)", section)
        self.assertIn("https://example.com/tok-hy2.json", section)
        self.assertIn("Прямая ссылка Hysteria 2", section)
        self.assertIn(link, section)

    @patch("bot.get_user_traffic", return_value={"formatted_total": "5.0 MB", "formatted_downlink": "4.0 MB", "formatted_uplink": "1.0 MB"})
    @patch("bot.get_subscription_info", return_value={
        "token": "2gWk5TCzW0-BR5aWd_R97Q",
        "trojan_pass": "hy2secretpass",
        "sub_url": "https://wildnode.duckdns.org/sub/2gWk5TCzW0-BR5aWd_R97Q.txt",
        "singbox_json_url": "https://wildnode.duckdns.org/sub/2gWk5TCzW0-BR5aWd_R97Q-vless.json",
        "hy2_json_url": "https://wildnode.duckdns.org/sub/2gWk5TCzW0-BR5aWd_R97Q-hy2.json",
    })
    @patch("bot.get_all_users_meta", return_value={
        "tg_olesya_media": {
            "meta": {
                "tg_username": "Olesya_Media",
                "tg_first_name": "Olesya",
                "tg_id": 2103511203
            }
        }
    })
    async def test_info_callback_shows_hy2_in_text_and_removes_url_buttons(self, mock_meta, mock_sub, mock_traffic):
        update = MagicMock()
        update.callback_query = AsyncMock()
        update.callback_query.data = "info_tg_olesya_media"
        update.callback_query.message = AsyncMock()
        update.effective_user.id = 12345678
        context = MagicMock()

        with patch("bot.is_admin", return_value=True):
            await callback_handler(update, context)

        self.assertTrue(update.callback_query.message.reply_text.called)
        kwargs = update.callback_query.message.reply_text.call_args.kwargs
        args = update.callback_query.message.reply_text.call_args.args
        msg = args[0] if args else kwargs.get("text", "")
        reply_markup = kwargs["reply_markup"]

        # Text must contain subscription, Sing-Box, Hysteria2 JSON, and direct hy2 link
        self.assertIn("https://wildnode.duckdns.org/sub/2gWk5TCzW0-BR5aWd_R97Q.txt", msg)
        self.assertIn("https://wildnode.duckdns.org/sub/2gWk5TCzW0-BR5aWd_R97Q-vless.json", msg)
        self.assertIn("https://wildnode.duckdns.org/sub/2gWk5TCzW0-BR5aWd_R97Q-hy2.json", msg)
        self.assertIn("hysteria2://hy2secretpass@", msg)
        self.assertIn("#Hysteria2-tg_olesya_media", msg)

        # Removed URL buttons must NOT be present; only admin management callbacks remain
        buttons = [btn for row in reply_markup.inline_keyboard for btn in row]
        button_texts = [btn.text for btn in buttons]
        button_callbacks = [btn.callback_data for btn in buttons]
        self.assertFalse(any("Открыть подписку" in t for t in button_texts))
        self.assertFalse(any("Sing-Box JSON" in t for t in button_texts))
        self.assertFalse(any("Hysteria2 JSON" in t for t in button_texts))
        self.assertEqual(button_callbacks, [
            "rot_tg_olesya_media",
            "rst_tg_olesya_media",
            "del_tg_olesya_media"
        ])

    @patch("bot.rotate_subscription_token", return_value={
        "token": "newtoken1234567890",
        "trojan_pass": "rotatedhy2pass",
        "sub_url": "https://wildnode.duckdns.org/sub/newtoken1234567890.txt",
        "singbox_json_url": "https://wildnode.duckdns.org/sub/newtoken1234567890-vless.json",
        "hy2_json_url": "https://wildnode.duckdns.org/sub/newtoken1234567890-hy2.json",
    })
    async def test_rot_callback_shows_hy2_in_text_and_removes_url_buttons(self, mock_rot):
        update = MagicMock()
        update.callback_query = AsyncMock()
        update.callback_query.data = "rot_tg_olesya_media"
        update.callback_query.message = AsyncMock()
        update.effective_user.id = 12345678
        context = MagicMock()

        with patch("bot.is_admin", return_value=True):
            await callback_handler(update, context)

        self.assertTrue(update.callback_query.message.reply_text.called)
        kwargs = update.callback_query.message.reply_text.call_args.kwargs
        args = update.callback_query.message.reply_text.call_args.args
        msg = args[0] if args else kwargs.get("text", "")
        reply_markup = kwargs["reply_markup"]

        self.assertIn("https://wildnode.duckdns.org/sub/newtoken1234567890-hy2.json", msg)
        self.assertIn("hysteria2://rotatedhy2pass@", msg)

        buttons = [btn for row in reply_markup.inline_keyboard for btn in row]
        button_texts = [btn.text for btn in buttons]
        button_callbacks = [btn.callback_data for btn in buttons]
        self.assertFalse(any("Открыть новую подписку" in t for t in button_texts))
        self.assertFalse(any("Hysteria2 JSON" in t for t in button_texts))
        self.assertEqual(button_callbacks, ["del_tg_olesya_media"])


if __name__ == "__main__":
    unittest.main()
