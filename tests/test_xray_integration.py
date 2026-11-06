"""
Comprehensive Integration & Security Tests for Dual-Transport Xray Architecture:
1. Xray Transactional Configuration Manager (atomic mutations, flock, validation, rollback)
2. Dual-transport subscription generation (Primary REALITY Vision, Backup REALITY XHTTP, Legacy WS)
3. Privileged helper actions (xray-check, xray-reload, xray-rollback, xray-status)
4. Sudoers permissions and visudo validation
"""

import os
import sys
import json
import base64
import tempfile
import shutil
import unittest
import subprocess
from unittest.mock import MagicMock

# Add bot directory to sys.path
BOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bot"))
if BOT_DIR not in sys.path:
    sys.path.insert(0, BOT_DIR)

from xray_manager import (
    load_xray_config,
    list_users_from_xray,
    add_user_to_xray,
    delete_user_from_xray,
    atomic_modify_xray_config,
    XrayConfigError,
    XrayValidationError,
    XrayReloadError
)
from subscription_manager import (
    create_or_update_subscription,
    get_subscription_info,
    rotate_subscription_token,
    revoke_subscription
)


SAMPLE_XRAY_CONFIG = {
    "log": {"loglevel": "warning"},
    "inbounds": [
        {
            "tag": "vless-reality-vision-in",
            "port": 8443,
            "listen": "0.0.0.0",
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "11111111-1111-1111-1111-111111111111",
                        "flow": "xtls-rprx-vision",
                        "email": "existing_user"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": False,
                    "dest": "dl.google.com:443",
                    "serverNames": ["dl.google.com"],
                    "privateKey": "SAMPLE_PRIVKEY_XXXXXXXXXXXXXXXXXXXXXXXXX",
                    "shortIds": ["abcdef0123456789"]
                }
            }
        },
        {
            "tag": "vless-reality-xhttp-in",
            "port": 8444,
            "listen": "0.0.0.0",
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "11111111-1111-1111-1111-111111111111",
                        "email": "existing_user"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "xhttp",
                "xhttpSettings": {
                    "path": "/xhttp",
                    "mode": "auto"
                },
                "security": "reality",
                "realitySettings": {
                    "show": False,
                    "dest": "dl.google.com:443",
                    "serverNames": ["dl.google.com"],
                    "privateKey": "SAMPLE_PRIVKEY_XXXXXXXXXXXXXXXXXXXXXXXXX",
                    "shortIds": ["abcdef0123456789"]
                }
            }
        }
    ],
    "outbounds": [{"protocol": "freedom", "tag": "direct"}]
}


class TestXrayManager(unittest.TestCase):
    """Verifies Xray configuration mutation and transactional semantics."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.config_path = os.path.join(self.test_dir, "xray_config.json")
        self.lock_path = os.path.join(self.test_dir, "xray_config.lock")
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(SAMPLE_XRAY_CONFIG, f, indent=2)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_load_and_list_users(self):
        """Loads valid config and lists registered emails."""
        users = list_users_from_xray(self.config_path)
        self.assertEqual(users, ["existing_user"])

    def test_load_non_existent_config_raises(self):
        """Loading missing configuration file raises XrayConfigError."""
        with self.assertRaises(XrayConfigError):
            load_xray_config(os.path.join(self.test_dir, "non_existent.json"))

    def test_add_user_to_xray_inbounds(self):
        """Adding user updates both Vision (with flow) and XHTTP inbounds."""
        data = load_xray_config(self.config_path)
        new_uuid = "22222222-2222-2222-2222-222222222222"
        updated = add_user_to_xray(data, "test_user_2", new_uuid)

        # Vision inbound check
        vision_clients = updated["inbounds"][0]["settings"]["clients"]
        self.assertEqual(len(vision_clients), 2)
        added_vision = next(c for c in vision_clients if c["email"] == "test_user_2")
        self.assertEqual(added_vision["id"], new_uuid)
        self.assertEqual(added_vision["flow"], "xtls-rprx-vision")

        # XHTTP inbound check
        xhttp_clients = updated["inbounds"][1]["settings"]["clients"]
        self.assertEqual(len(xhttp_clients), 2)
        added_xhttp = next(c for c in xhttp_clients if c["email"] == "test_user_2")
        self.assertEqual(added_xhttp["id"], new_uuid)
        self.assertNotIn("flow", added_xhttp)

    def test_add_user_idempotence(self):
        """Adding duplicate user does not create duplicate client entries."""
        data = load_xray_config(self.config_path)
        new_uuid = "22222222-2222-2222-2222-222222222222"
        add_user_to_xray(data, "test_user_2", new_uuid)
        add_user_to_xray(data, "test_user_2", new_uuid)

        vision_clients = data["inbounds"][0]["settings"]["clients"]
        self.assertEqual(len(vision_clients), 2)

    def test_delete_user_from_xray(self):
        """Deleting user removes them from all inbounds."""
        data = load_xray_config(self.config_path)
        updated = delete_user_from_xray(data, "existing_user")
        for ib in updated["inbounds"]:
            self.assertEqual(len(ib["settings"]["clients"]), 0)

    def test_atomic_modify_success(self):
        """Transactional modification updates file, creates .bak, and calls control_runner."""
        mock_runner = MagicMock()
        new_uuid = "33333333-3333-3333-3333-333333333333"

        def mutate(cfg):
            return add_user_to_xray(cfg, "atomic_user", new_uuid)

        atomic_modify_xray_config(
            mutation_fn=mutate,
            config_path=self.config_path,
            lock_path=self.lock_path,
            control_runner=mock_runner
        )

        mock_runner.assert_any_call("xray-check", unittest.mock.ANY)
        mock_runner.assert_any_call("xray-reload", None)
        mock_runner.assert_any_call("xray-status", None)

        users = list_users_from_xray(self.config_path)
        self.assertIn("atomic_user", users)
        self.assertTrue(os.path.exists(f"{self.config_path}.bak"))

    def test_atomic_modify_validation_failure_rollbacks(self):
        """If validation helper rejects temp config, file is untouched and raises XrayValidationError."""
        def failing_runner(action, target):
            if action == "xray-check":
                raise subprocess.CalledProcessError(1, "xray-check", stderr="Invalid config")

        new_uuid = "44444444-4444-4444-4444-444444444444"
        def mutate(cfg):
            return add_user_to_xray(cfg, "rejected_user", new_uuid)

        with self.assertRaises(XrayValidationError):
            atomic_modify_xray_config(
                mutation_fn=mutate,
                config_path=self.config_path,
                lock_path=self.lock_path,
                control_runner=failing_runner
            )

        # Ensure rejected user is NOT in config
        users = list_users_from_xray(self.config_path)
        self.assertNotIn("rejected_user", users)

    def test_atomic_modify_reload_failure_restores_backup(self):
        """If reload fails, active config is restored from backup."""
        def failing_reload_runner(action, target):
            if action == "xray-reload":
                raise RuntimeError("Service failed to reload")

        new_uuid = "55555555-5555-5555-5555-555555555555"
        def mutate(cfg):
            return add_user_to_xray(cfg, "reload_fail_user", new_uuid)

        with self.assertRaises(XrayReloadError):
            atomic_modify_xray_config(
                mutation_fn=mutate,
                config_path=self.config_path,
                lock_path=self.lock_path,
                control_runner=failing_reload_runner
            )

        users = list_users_from_xray(self.config_path)
        self.assertNotIn("reload_fail_user", users)
        self.assertIn("existing_user", users)


class TestDualTransportSubscription(unittest.TestCase):
    """Verifies dual-transport subscription link and client JSON generation."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.www_dir = os.path.join(self.test_dir, "www")
        self.registry_path = os.path.join(self.test_dir, "subscriptions.json")
        self.lock_path = os.path.join(self.test_dir, "sub.lock")
        self.vless_template = os.path.join(self.test_dir, "template-vless.json")
        self.trojan_template = os.path.join(self.test_dir, "template-trj.json")

        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        src_vless_tmpl = os.path.join(repo_root, "config", "templates", "template-vless.json")
        src_trj_tmpl = os.path.join(repo_root, "config", "templates", "template-trj.json")

        if os.path.exists(src_vless_tmpl):
            shutil.copy2(src_vless_tmpl, self.vless_template)
        else:
            with open(self.vless_template, "w", encoding="utf-8") as f:
                json.dump({"outbounds": [{"type": "vless", "tag": "proxy"}]}, f)

        if os.path.exists(src_trj_tmpl):
            shutil.copy2(src_trj_tmpl, self.trojan_template)
        else:
            with open(self.trojan_template, "w", encoding="utf-8") as f:
                json.dump({"outbounds": [{"type": "trojan", "tag": "proxy"}]}, f)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_subscription_generation_with_reality(self):
        """Generates all 4 profiles when REALITY is enabled."""
        res = create_or_update_subscription(
            username="alice",
            vless_uuid="aaaa-bbbb-cccc-dddd",
            trojan_pass="secrettrjpass",
            domain="example.org",
            subs_path="sub",
            vless_path="vlessws",
            trojan_path="trjws",
            www_dir=self.www_dir,
            reality_port=8443,
            xhttp_port=8444,
            reality_public_key="TEST_PUB_KEY_1234567890",
            reality_short_id="0123456789abcdef",
            reality_sni="dl.google.com",
            xhttp_path="xhttp",
            vless_template=self.vless_template,
            trojan_template=self.trojan_template,
            registry_path=self.registry_path,
            lock_path=self.lock_path
        )

        token = res["token"]
        self.assertTrue(len(token) >= 22)
        txt_file = os.path.join(self.www_dir, f"{token}.txt")
        self.assertTrue(os.path.exists(txt_file))

        with open(txt_file, "r", encoding="utf-8") as f:
            b64_content = f.read().strip()
        decoded = base64.b64decode(b64_content).decode("utf-8")

        lines = [line.strip() for line in decoded.strip().split("\n") if line.strip()]
        self.assertEqual(len(lines), 4)

        # 1. Primary REALITY Vision
        self.assertIn("vless://aaaa-bbbb-cccc-dddd@example.org:8443", lines[0])
        self.assertIn("security=reality", lines[0])
        self.assertIn("pbk=TEST_PUB_KEY_1234567890", lines[0])
        self.assertIn("sid=0123456789abcdef", lines[0])
        self.assertIn("sni=dl.google.com", lines[0])
        self.assertIn("flow=xtls-rprx-vision", lines[0])
        self.assertIn("#⚡ [Основной] VLESS-REALITY-Vision", lines[0])

        # 2. Backup REALITY XHTTP
        self.assertIn("vless://aaaa-bbbb-cccc-dddd@example.org:8444", lines[1])
        self.assertIn("type=xhttp", lines[1])
        self.assertIn("path=%2Fxhttp", lines[1])
        self.assertIn("#🛡️ [Резерв] VLESS-XHTTP-REALITY", lines[1])

        # 3. Legacy VLESS WS
        self.assertIn("vless://aaaa-bbbb-cccc-dddd@example.org:443", lines[2])
        self.assertIn("type=ws", lines[2])
        self.assertIn("#🌐 [WS] VLESS-WS-TLS", lines[2])

        # 4. Legacy Trojan WS
        self.assertIn("trojan://secrettrjpass@example.org:443", lines[3])
        self.assertIn("#🔒 [WS] Trojan-WS-TLS", lines[3])

        # Check vless client JSON
        client_json = os.path.join(self.www_dir, f"{token}-vless.json")
        self.assertTrue(os.path.exists(client_json))
        with open(client_json, "r", encoding="utf-8") as f:
            cj = json.load(f)
        for ob in cj.get("outbounds", []):
            if ob.get("type") == "vless":
                self.assertEqual(ob.get("uuid"), "aaaa-bbbb-cccc-dddd")

    def test_subscription_backward_compatibility_without_reality(self):
        """Falls back to 2 legacy profiles when reality_public_key is not configured."""
        res = create_or_update_subscription(
            username="bob",
            vless_uuid="bbbb-cccc-dddd-eeee",
            trojan_pass="trjbobpass",
            domain="legacy.org",
            subs_path="sub",
            vless_path="vlessws",
            trojan_path="trjws",
            www_dir=self.www_dir,
            reality_public_key="",  # Not configured
            vless_template=self.vless_template,
            trojan_template=self.trojan_template,
            registry_path=self.registry_path,
            lock_path=self.lock_path
        )

        token = res["token"]
        txt_file = os.path.join(self.www_dir, f"{token}.txt")
        with open(txt_file, "r", encoding="utf-8") as f:
            decoded = base64.b64decode(f.read().strip()).decode("utf-8")
        lines = [line.strip() for line in decoded.strip().split("\n") if line.strip()]
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[0].startswith("vless://"))
        self.assertTrue(lines[1].startswith("trojan://"))


class TestSingboxControlXrayActions(unittest.TestCase):
    """Verifies scripts/singbox-control.sh enforces strict security on xray actions."""

    def setUp(self):
        self.repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.script_path = os.path.join(self.repo_root, "scripts", "singbox-control.sh")

    def test_xray_check_missing_target_fails(self):
        """xray-check without path parameter must fail."""
        res = subprocess.run([self.script_path, "xray-check"], capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Missing target path", res.stderr)

    def test_xray_check_disallowed_directory_fails(self):
        """xray-check pointing outside /etc/xray or /tmp/xray_* must be rejected."""
        passwd_path = "/etc/passwd"
        if os.path.exists(passwd_path):
            res = subprocess.run([self.script_path, "xray-check", passwd_path], capture_output=True, text=True)
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("outside allowed directories", res.stderr)

    def test_xray_check_valid_tmp_file(self):
        """xray-check validates valid JSON file located in /tmp/xray_*."""
        tmp_cfg = tempfile.NamedTemporaryFile(prefix="xray_test_", suffix=".json", dir="/tmp", delete=False)
        try:
            with open(tmp_cfg.name, "w", encoding="utf-8") as f:
                json.dump({"inbounds": [{"tag": "vless-in"}]}, f)

            res = subprocess.run([self.script_path, "xray-check", tmp_cfg.name], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0)
        finally:
            if os.path.exists(tmp_cfg.name):
                os.remove(tmp_cfg.name)

    def test_xray_check_invalid_json_fails(self):
        """xray-check rejects corrupt non-JSON file."""
        tmp_cfg = tempfile.NamedTemporaryFile(prefix="xray_bad_", suffix=".json", dir="/tmp", delete=False)
        try:
            with open(tmp_cfg.name, "w", encoding="utf-8") as f:
                f.write("NOT_VALID_JSON{{{")

            res = subprocess.run([self.script_path, "xray-check", tmp_cfg.name], capture_output=True, text=True)
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("validation failed", res.stderr)
        finally:
            if os.path.exists(tmp_cfg.name):
                os.remove(tmp_cfg.name)

    def test_xray_rollback_restores_file(self):
        """xray-rollback restores active config from backup."""
        tmp_dir = tempfile.mkdtemp(prefix="xray_rb_")
        try:
            cfg_path = os.path.join(tmp_dir, "config.json")
            bak_path = os.path.join(tmp_dir, "config.json.bak")
            with open(cfg_path, "w") as f:
                f.write("BROKEN_DATA")
            with open(bak_path, "w") as f:
                f.write('{"inbounds": []}')

            env = os.environ.copy()
            env["XRAY_CONFIG_FILE"] = cfg_path
            env["XRAY_BACKUP_FILE"] = bak_path

            res = subprocess.run([self.script_path, "xray-rollback"], capture_output=True, text=True, env=env)
            self.assertEqual(res.returncode, 0)
            with open(cfg_path, "r") as f:
                self.assertEqual(f.read(), '{"inbounds": []}')
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)


class TestSudoersXrayPermissions(unittest.TestCase):
    """Verifies that config/sudoers/incy-bot.sudoers covers all xray operations and parses with visudo."""

    def setUp(self):
        self.repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.sudoers_file = os.path.join(self.repo_root, "config", "sudoers", "incy-bot.sudoers")

    def test_visudo_syntax(self):
        """visudo -cf must parse sudoers file cleanly."""
        res = subprocess.run(["visudo", "-cf", self.sudoers_file], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"visudo syntax check failed: {res.stderr}")

    def test_xray_actions_in_sudoers(self):
        """Sudoers must include xray-check, xray-reload, xray-rollback, and xray-status."""
        with open(self.sudoers_file, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("/usr/local/bin/singbox-control xray-check /etc/xray/*", content)
        self.assertIn("/usr/local/bin/singbox-control xray-check /tmp/xray_*", content)
        self.assertIn("/usr/local/bin/singbox-control xray-reload", content)
        self.assertIn("/usr/local/bin/singbox-control xray-rollback", content)
        self.assertIn("/usr/local/bin/singbox-control xray-status", content)


if __name__ == "__main__":
    unittest.main()
