"""
Unit tests for Incy-Bot authentication and authorization security layer.
Verifies fail-closed behavior, startup validation, unknown user rejection,
authorized admin success, and callback query protection.
"""

import asyncio
import sys
import os
import unittest
from unittest.mock import AsyncMock, MagicMock

# Add bot directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bot")))

from auth import (
    parse_admin_ids,
    is_admin,
    admin_required,
    AuthorizationConfigurationError,
)


class TestAdminIdParsing(unittest.TestCase):
    """Test suite for TELEGRAM_ADMIN_IDS parsing and fail-closed validation."""

    def test_empty_string_fails(self):
        """Empty string must raise AuthorizationConfigurationError (fail-closed)."""
        with self.assertRaises(AuthorizationConfigurationError):
            parse_admin_ids("")

    def test_none_value_fails(self):
        """None value must raise AuthorizationConfigurationError."""
        with self.assertRaises(AuthorizationConfigurationError):
            parse_admin_ids(None)

    def test_whitespace_only_fails(self):
        """Whitespace-only string must raise AuthorizationConfigurationError."""
        with self.assertRaises(AuthorizationConfigurationError):
            parse_admin_ids("   \t  \n  ")

    def test_non_numeric_characters_fail(self):
        """Non-numeric values must be rejected."""
        with self.assertRaises(AuthorizationConfigurationError):
            parse_admin_ids("admin,root,12345")

    def test_negative_or_zero_ids_fail(self):
        """Negative numbers or zero must be rejected."""
        with self.assertRaises(AuthorizationConfigurationError):
            parse_admin_ids("0")
        with self.assertRaises(AuthorizationConfigurationError):
            parse_admin_ids("-12345")

    def test_partial_invalid_entry_fails_entire_configuration(self):
        """If any ID in the comma-separated list is invalid, entire parsing fails."""
        with self.assertRaises(AuthorizationConfigurationError):
            parse_admin_ids("12345678,invalid_user,87654321")

    def test_valid_single_id(self):
        """Single valid numeric ID parses correctly."""
        result = parse_admin_ids("123456789")
        self.assertEqual(result, {123456789})

    def test_valid_multiple_ids_with_whitespace(self):
        """Multiple IDs with varying whitespace parse into an integer set."""
        result = parse_admin_ids(" 123456789, 987654321 ,  555444333  ")
        self.assertEqual(result, {123456789, 987654321, 555444333})


class TestIsAdminLogic(unittest.TestCase):
    """Test suite for is_admin fail-closed evaluation."""

    def test_empty_admin_set_never_authorizes(self):
        """If admin set is empty, is_admin must NEVER return True."""
        empty_admins = set()
        self.assertFalse(is_admin(12345, empty_admins))
        self.assertFalse(is_admin(0, empty_admins))
        self.assertFalse(is_admin(-1, empty_admins))

    def test_none_user_id_never_authorizes(self):
        """None user ID must return False even if admin set is populated."""
        admins = {12345, 67890}
        self.assertFalse(is_admin(None, admins))

    def test_unknown_user_rejected(self):
        """User ID not in the set must return False."""
        admins = {12345, 67890}
        self.assertFalse(is_admin(99999, admins))
        self.assertFalse(is_admin(12346, admins))

    def test_authorized_admin_accepted(self):
        """User ID present in the set must return True."""
        admins = {12345, 67890}
        self.assertTrue(is_admin(12345, admins))
        self.assertTrue(is_admin(67890, admins))


class TestAdminRequiredDecorator(unittest.IsolatedAsyncioTestCase):
    """Test suite for @admin_required handler decorator."""

    def setUp(self):
        self.admin_id = 111222333
        self.intruder_id = 999888777
        self.admin_set = {self.admin_id}
        self.decorator = admin_required(self.admin_set)

    async def test_authorized_message_handler_executes(self):
        """Authorized user executing a message command gets normal execution."""
        mock_handler = AsyncMock(return_value="executed_successfully")
        decorated = self.decorator(mock_handler)

        mock_update = MagicMock()
        mock_update.effective_user.id = self.admin_id
        mock_update.effective_user.username = "real_admin"
        mock_update.callback_query = None
        mock_context = MagicMock()

        result = await decorated(mock_update, mock_context)
        self.assertEqual(result, "executed_successfully")
        mock_handler.assert_awaited_once_with(mock_update, mock_context)

    async def test_unauthorized_message_handler_blocked(self):
        """Unauthorized user executing a message command is blocked with access denied."""
        mock_handler = AsyncMock(return_value="should_not_run")
        decorated = self.decorator(mock_handler)

        mock_update = MagicMock()
        mock_update.effective_user.id = self.intruder_id
        mock_update.effective_user.username = "intruder"
        mock_update.callback_query = None
        mock_update.effective_message.reply_text = AsyncMock()
        mock_context = MagicMock()

        result = await decorated(mock_update, mock_context)
        self.assertIsNone(result)
        mock_handler.assert_not_awaited()
        mock_update.effective_message.reply_text.assert_awaited_once_with("⛔ Доступ запрещён.")

    async def test_authorized_callback_handler_executes(self):
        """Authorized user clicking an inline button callback query is allowed."""
        mock_handler = AsyncMock(return_value="callback_success")
        decorated = self.decorator(mock_handler)

        mock_update = MagicMock()
        mock_update.effective_user.id = self.admin_id
        mock_update.effective_user.username = "real_admin"
        mock_update.callback_query.answer = AsyncMock()
        mock_context = MagicMock()

        result = await decorated(mock_update, mock_context)
        self.assertEqual(result, "callback_success")
        mock_handler.assert_awaited_once_with(mock_update, mock_context)

    async def test_unauthorized_callback_query_blocked_and_alerted(self):
        """Unauthorized user attempting callback query bypass is rejected with alert."""
        mock_handler = AsyncMock(return_value="should_not_run")
        decorated = self.decorator(mock_handler)

        mock_update = MagicMock()
        mock_update.effective_user.id = self.intruder_id
        mock_update.effective_user.username = "attacker"
        mock_update.callback_query.answer = AsyncMock()
        mock_context = MagicMock()

        result = await decorated(mock_update, mock_context)
        self.assertIsNone(result)
        mock_handler.assert_not_awaited()
        mock_update.callback_query.answer.assert_awaited_once_with("⛔ Доступ запрещён.", show_alert=True)


if __name__ == "__main__":
    unittest.main()
