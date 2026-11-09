#!/usr/bin/env python3
"""
Unit tests for transactional sing-box configuration manager:
- Strict username validation (anti-traversal, length, charset)
- File locking and concurrency safety
- Pre-validation of configuration via helper
- Atomic replacement and automatic backup
- Automatic rollback on reload/health failure
- User addition, deletion, and listing
"""

import os
import sys
import json
import shutil
import tempfile
import unittest
import subprocess
from unittest.mock import MagicMock, patch

# Add bot directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bot")))

from config_manager import (
    validate_username,
    config_lock,
    atomic_modify_singbox_config,
    add_user_to_config,
    delete_user_from_config,
    list_users_from_config,
    InvalidUsernameError,
    UserAlreadyExistsError,
    UserNotFoundError,
    ConfigLoadError,
    ConfigValidationError,
    ConfigReloadError
)


class TestUsernameValidation(unittest.TestCase):
    """Verifies strict username validation against malicious input and format errors."""

    def test_valid_usernames(self):
        valid_cases = ["alice", "bob_123", "charlie-net", "A", "User_Name-99", "12345"]
        for u in valid_cases:
            self.assertEqual(validate_username(u), u)

    def test_invalid_characters_rejected(self):
        invalid_cases = [
            "user name",
            "user@domain",
            "user!123",
            "user#hash",
            "user$var",
            "user;rm -rf",
            "user|cat",
            "user&cmd"
        ]
        for u in invalid_cases:
            with self.assertRaises(InvalidUsernameError):
                validate_username(u)

    def test_path_traversal_rejected(self):
        traversal_cases = [
            "../etc/passwd",
            "..",
            "user/dir",
            "user\\dir",
            "/absolute/path",
            "foo/../bar"
        ]
        for u in traversal_cases:
            with self.assertRaises(InvalidUsernameError):
                validate_username(u)

    def test_length_limits(self):
        with self.assertRaises(InvalidUsernameError):
            validate_username("")
        with self.assertRaises(InvalidUsernameError):
            validate_username("   ")
        # 32 characters is allowed
        self.assertEqual(len(validate_username("a" * 32)), 32)
        # 33 characters must fail
        with self.assertRaises(InvalidUsernameError):
            validate_username("a" * 33)


class TestTransactionalConfigManager(unittest.TestCase):
    """Verifies atomic mutations, validation, and rollback semantics."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="singbox_test_cfg_")
        self.config_path = os.path.join(self.test_dir, "config.json")
        self.backup_path = os.path.join(self.test_dir, "config.json.bak")
        self.lock_path = os.path.join(self.test_dir, "config.lock")

        self.initial_config = {
            "inbounds": [
                {
                    "type": "vless",
                    "tag": "vless-in",
                    "listen_port": 10001,
                    "users": [
                        {"name": "existing_user", "uuid": "00000000-0000-0000-0000-000000000000"}
                    ]
                },
                {
                    "type": "trojan",
                    "tag": "trojan-in",
                    "listen_port": 10002,
                    "users": [
                        {"name": "existing_user", "password": "pass1234existing"}
                    ]
                }
            ],
            "outbounds": [
                {"type": "direct", "tag": "direct"}
            ]
        }
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(self.initial_config, f, indent=2)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_config_lock_mutual_exclusion(self):
        """Verifies that config_lock acquires exclusive lock on the file."""
        with config_lock(self.lock_path):
            # Attempt to acquire another lock non-blocking in subprocess
            code = (
                f"import fcntl, os\n"
                f"fd = os.open('{self.lock_path}', os.O_RDWR)\n"
                f"try:\n"
                f"    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\n"
                f"    print('ACQUIRED')\n"
                f"except BlockingIOError:\n"
                f"    print('BLOCKED')\n"
            )
            res = subprocess.run(["python3", "-c", code], capture_output=True, text=True)
            self.assertEqual(res.stdout.strip(), "BLOCKED")

    def test_successful_atomic_mutation(self):
        """Valid mutator updates config, invokes reload and status, and creates backup."""
        calls = []

        def mock_runner(action, target=None):
            calls.append((action, target))
            return MagicMock(returncode=0)

        def mutator(cfg):
            cfg["inbounds"][0]["users"].append({"name": "newuser", "uuid": "11111111-1111-1111-1111-111111111111"})
            return cfg, "MUTATED_OK"

        res = atomic_modify_singbox_config(
            mutator_fn=mutator,
            config_path=self.config_path,
            backup_path=self.backup_path,
            control_runner=mock_runner,
            lock_path=self.lock_path
        )

        self.assertEqual(res, "MUTATED_OK")
        # Check calls: pre-validation check, reload, status
        self.assertEqual(calls[0][0], "check")
        self.assertTrue(calls[0][1].endswith(".json"))
        self.assertEqual(calls[1], ("reload", None))
        self.assertEqual(calls[2], ("status", None))

        # Verify backup exists and contains original config
        self.assertTrue(os.path.exists(self.backup_path))
        with open(self.backup_path, "r", encoding="utf-8") as f:
            backup_data = json.load(f)
        self.assertEqual(len(backup_data["inbounds"][0]["users"]), 1)

        # Verify live config was updated
        with open(self.config_path, "r", encoding="utf-8") as f:
            live_data = json.load(f)
        self.assertEqual(len(live_data["inbounds"][0]["users"]), 2)
        self.assertEqual(live_data["inbounds"][0]["users"][1]["name"], "newuser")

    def test_validation_failure_aborts_without_modifying_live_config(self):
        """When check fails, original config must remain 100% untouched and no backup created."""
        def failing_check_runner(action, target=None):
            if action == "check":
                raise subprocess.CalledProcessError(1, ["singbox-control", "check"], stderr="Syntax error: invalid inbound field")
            return MagicMock(returncode=0)

        def mutator(cfg):
            cfg["inbounds"][0]["users"].append({"name": "baduser", "uuid": "bad"})
            return cfg, "OK"

        with self.assertRaises(ConfigValidationError) as ctx:
            atomic_modify_singbox_config(
                mutator_fn=mutator,
                config_path=self.config_path,
                backup_path=self.backup_path,
                control_runner=failing_check_runner,
                lock_path=self.lock_path
            )

        self.assertIn("Syntax error", str(ctx.exception))

        # Live config must still have exactly 1 user
        with open(self.config_path, "r", encoding="utf-8") as f:
            live_data = json.load(f)
        self.assertEqual(len(live_data["inbounds"][0]["users"]), 1)
        self.assertEqual(live_data["inbounds"][0]["users"][0]["name"], "existing_user")

    def test_reload_failure_triggers_automatic_rollback(self):
        """When reload or status check fails, live config is automatically restored from backup."""
        reload_attempt = 0

        def runner_fail_first_reload(action, target=None):
            nonlocal reload_attempt
            if action == "check":
                return MagicMock(returncode=0)
            if action == "reload":
                reload_attempt += 1
                if reload_attempt == 1:
                    # First reload (after applying candidate) fails
                    raise subprocess.CalledProcessError(1, ["singbox-control", "reload"], stderr="Daemon failed to reload")
                # Second reload (during rollback) succeeds
                return MagicMock(returncode=0)
            if action == "status":
                return MagicMock(returncode=0)
            return MagicMock(returncode=0)

        def mutator(cfg):
            cfg["inbounds"][0]["users"].append({"name": "crashuser", "uuid": "999"})
            return cfg, "OK"

        with self.assertRaises(ConfigReloadError) as ctx:
            atomic_modify_singbox_config(
                mutator_fn=mutator,
                config_path=self.config_path,
                backup_path=self.backup_path,
                control_runner=runner_fail_first_runner if False else runner_fail_first_reload,
                lock_path=self.lock_path
            )

        self.assertIn("успешно восстановлена", str(ctx.exception))

        # Live config must have been rolled back to exactly the original state!
        with open(self.config_path, "r", encoding="utf-8") as f:
            live_data = json.load(f)
        self.assertEqual(len(live_data["inbounds"][0]["users"]), 1)
        self.assertEqual(live_data["inbounds"][0]["users"][0]["name"], "existing_user")
        self.assertEqual(reload_attempt, 2)  # Initial reload failed, rollback reload succeeded

    def test_add_user_success(self):
        """add_user_to_config properly updates vless and trojan inbounds."""
        def mock_runner(action, target=None):
            return MagicMock(returncode=0)

        res = add_user_to_config(
            username="new_alice",
            new_uuid="aaaa-bbbb-cccc",
            new_pass="secretpass123",
            config_path=self.config_path,
            backup_path=self.backup_path,
            control_runner=mock_runner,
            lock_path=self.lock_path
        )

        self.assertEqual(res["username"], "new_alice")
        self.assertEqual(res["uuid"], "aaaa-bbbb-cccc")
        self.assertEqual(res["password"], "secretpass123")

        with open(self.config_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        vless_users = [u["name"] for u in cfg["inbounds"][0]["users"]]
        trojan_users = [u["name"] for u in cfg["inbounds"][1]["users"]]
        self.assertIn("new_alice", vless_users)
        self.assertIn("new_alice", trojan_users)

    def test_add_user_duplicate_fails(self):
        """Adding duplicate user raises UserAlreadyExistsError without altering config."""
        def mock_runner(action, target=None):
            return MagicMock(returncode=0)

        with self.assertRaises(UserAlreadyExistsError):
            add_user_to_config(
                username="existing_user",
                new_uuid="xxxx-yyyy",
                new_pass="pass",
                config_path=self.config_path,
                backup_path=self.backup_path,
                control_runner=mock_runner,
                lock_path=self.lock_path
            )

    def test_delete_user_success(self):
        """delete_user_from_config removes user from all inbounds."""
        def mock_runner(action, target=None):
            return MagicMock(returncode=0)

        deleted = delete_user_from_config(
            username="existing_user",
            config_path=self.config_path,
            backup_path=self.backup_path,
            control_runner=mock_runner,
            lock_path=self.lock_path
        )

        self.assertTrue(deleted)
        with open(self.config_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        self.assertEqual(len(cfg["inbounds"][0]["users"]), 0)
        self.assertEqual(len(cfg["inbounds"][1]["users"]), 0)

    def test_delete_user_not_found_fails(self):
        """Deleting non-existent user raises UserNotFoundError."""
        def mock_runner(action, target=None):
            return MagicMock(returncode=0)

        with self.assertRaises(UserNotFoundError):
            delete_user_from_config(
                username="ghost_user",
                config_path=self.config_path,
                backup_path=self.backup_path,
                control_runner=mock_runner,
                lock_path=self.lock_path
            )

    def test_list_users(self):
        """list_users_from_config returns sorted distinct user list."""
        users = list_users_from_config(config_path=self.config_path, lock_path=self.lock_path)
        self.assertEqual(users, ["existing_user"])

    def test_corrupted_config_raises_config_load_error(self):
        """Malformed JSON raises ConfigLoadError and prevents modification."""
        with open(self.config_path, "w", encoding="utf-8") as f:
            f.write("{ INVALID JSON CONTENT")

        with self.assertRaises(ConfigLoadError):
            atomic_modify_singbox_config(
                mutator_fn=lambda c: (c, None),
                config_path=self.config_path,
                backup_path=self.backup_path,
                control_runner=lambda a, t=None: None,
                lock_path=self.lock_path
            )


if __name__ == "__main__":
    unittest.main()
