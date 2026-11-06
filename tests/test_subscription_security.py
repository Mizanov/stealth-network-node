#!/usr/bin/env python3
"""
Unit tests for VPN Subscription Security & Tokenization (Stage 3).
Verifies:
1. Cryptographic token generation (128-bit entropy, URL-safe)
2. No Telegram ID or username in public URLs or file paths
3. User subscription isolation (unguessability, no cross-access)
4. Token rotation (old token file deletion, new token creation)
5. Token revocation (cleanup of subscription files and registry)
6. Nginx hardening (autoindex off, access_log off, anti-caching headers)
"""

import os
import sys
import json
import shutil
import base64
import tempfile
import unittest

# Add bot directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bot")))

from subscription_manager import (
    generate_token,
    create_or_update_subscription,
    get_subscription_info,
    rotate_subscription_token,
    revoke_subscription,
    SubscriptionError
)


class TestSubscriptionTokenGeneration(unittest.TestCase):
    """Verifies that tokens meet cryptographic security standards."""

    def test_token_entropy_and_uniqueness(self):
        tokens = {generate_token() for _ in range(100)}
        # 100 unique tokens
        self.assertEqual(len(tokens), 100)
        # Each token should be at least 20 chars long (16 bytes base64url = 22 chars)
        for t in tokens:
            self.assertGreaterEqual(len(t), 20)
            # Must be safe for URLs (no spaces, slashes, or query chars)
            self.assertTrue(all(c.isalnum() or c in "-_" for c in t))


class TestSubscriptionLifecycle(unittest.TestCase):
    """Verifies creation, isolation, rotation, and revocation of subscriptions."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="sub_security_test_")
        self.www_dir = os.path.join(self.test_dir, "www")
        self.registry_path = os.path.join(self.test_dir, "subscriptions.json")
        self.lock_path = os.path.join(self.test_dir, "sub.lock")

        # Mock templates
        self.vless_tmpl = os.path.join(self.test_dir, "vless.json")
        with open(self.vless_tmpl, "w", encoding="utf-8") as f:
            json.dump({"outbounds": [{"tag": "proxy", "uuid": ""}]}, f)

        self.trj_tmpl = os.path.join(self.test_dir, "trj.json")
        with open(self.trj_tmpl, "w", encoding="utf-8") as f:
            json.dump({"outbounds": [{"tag": "proxy", "password": ""}]}, f)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_create_subscription_uses_token_not_username(self):
        """Subscription URL and files must use crypto token, NEVER username or telegram ID."""
        username = "alice_secret"
        telegram_id = 123456789

        res = create_or_update_subscription(
            username=username,
            vless_uuid="uuid-alice-1234",
            trojan_pass="pass-alice-5678",
            domain="vpn.example.com",
            subs_path="secret_sub_path",
            vless_path="vless_ws",
            trojan_path="trj_ws",
            www_dir=self.www_dir,
            vless_template=self.vless_tmpl,
            trojan_template=self.trj_tmpl,
            registry_path=self.registry_path,
            lock_path=self.lock_path
        )

        token = res["token"]
        self.assertNotIn(username, res["sub_url"])
        self.assertNotIn(str(telegram_id), res["sub_url"])
        self.assertIn(token, res["sub_url"])

        # Check files on disk
        files = os.listdir(self.www_dir)
        # None of the files on disk should contain the username
        for f in files:
            self.assertNotIn(username, f)
            self.assertNotIn(str(telegram_id), f)

        # Tokenized files must exist
        self.assertIn(f"{token}.txt", files)
        self.assertIn(f"{token}-vless.json", files)
        self.assertIn(f"{token}-trj.json", files)

        # Verify content
        with open(os.path.join(self.www_dir, f"{token}.txt"), "r") as f:
            raw_b64 = f.read().strip()
        decoded = base64.b64decode(raw_b64).decode("utf-8")
        self.assertIn("vless://uuid-alice-1234", decoded)
        self.assertIn("trojan://pass-alice-5678", decoded)

    def test_user_isolation_and_anti_enumeration(self):
        """Two users must receive independent, unguessable tokens; knowing one gives no access to the other."""
        user1_res = create_or_update_subscription(
            username="user_alpha",
            vless_uuid="uuid-alpha",
            trojan_pass="pass-alpha",
            domain="vpn.example.com",
            subs_path="sub",
            vless_path="v",
            trojan_path="t",
            www_dir=self.www_dir,
            vless_template=self.vless_tmpl,
            trojan_template=self.trj_tmpl,
            registry_path=self.registry_path,
            lock_path=self.lock_path
        )

        user2_res = create_or_update_subscription(
            username="user_beta",
            vless_uuid="uuid-beta",
            trojan_pass="pass-beta",
            domain="vpn.example.com",
            subs_path="sub",
            vless_path="v",
            trojan_path="t",
            www_dir=self.www_dir,
            vless_template=self.vless_tmpl,
            trojan_template=self.trj_tmpl,
            registry_path=self.registry_path,
            lock_path=self.lock_path
        )

        self.assertNotEqual(user1_res["token"], user2_res["token"])

        # Predictable paths like /sub/user_beta.txt do NOT exist
        guessable_path = os.path.join(self.www_dir, "user_beta.txt")
        self.assertFalse(os.path.exists(guessable_path))

    def test_token_rotation_invalidates_old_token(self):
        """Rotating a token creates a new token and deletes the old files from disk immediately."""
        username = "charlie"
        res1 = create_or_update_subscription(
            username=username,
            vless_uuid="uuid-charlie",
            trojan_pass="pass-charlie",
            domain="vpn.example.com",
            subs_path="sub",
            vless_path="v",
            trojan_path="t",
            www_dir=self.www_dir,
            vless_template=self.vless_tmpl,
            trojan_template=self.trj_tmpl,
            registry_path=self.registry_path,
            lock_path=self.lock_path
        )
        old_token = res1["token"]
        old_file = os.path.join(self.www_dir, f"{old_token}.txt")
        self.assertTrue(os.path.exists(old_file))

        # Rotate token
        res2 = rotate_subscription_token(
            username=username,
            domain="vpn.example.com",
            subs_path="sub",
            vless_path="v",
            trojan_path="t",
            www_dir=self.www_dir,
            vless_template=self.vless_tmpl,
            trojan_template=self.trj_tmpl,
            registry_path=self.registry_path,
            lock_path=self.lock_path
        )
        new_token = res2["token"]
        self.assertNotEqual(old_token, new_token)

        # Old file MUST BE DELETED (404 for anyone with old link)
        self.assertFalse(os.path.exists(old_file))

        # New file must exist
        new_file = os.path.join(self.www_dir, f"{new_token}.txt")
        self.assertTrue(os.path.exists(new_file))

    def test_subscription_revocation(self):
        """Revoking subscription removes all files and deletes registry entry."""
        username = "dave"
        res = create_or_update_subscription(
            username=username,
            vless_uuid="uuid-dave",
            trojan_pass="pass-dave",
            domain="vpn.example.com",
            subs_path="sub",
            vless_path="v",
            trojan_path="t",
            www_dir=self.www_dir,
            vless_template=self.vless_tmpl,
            trojan_template=self.trj_tmpl,
            registry_path=self.registry_path,
            lock_path=self.lock_path
        )
        token = res["token"]
        token_file = os.path.join(self.www_dir, f"{token}.txt")
        self.assertTrue(os.path.exists(token_file))

        # Revoke
        revoked = revoke_subscription(
            username=username,
            www_dir=self.www_dir,
            registry_path=self.registry_path,
            lock_path=self.lock_path
        )
        self.assertTrue(revoked)

        # File must be gone
        self.assertFalse(os.path.exists(token_file))

        # Querying info must return None
        info = get_subscription_info(
            username=username,
            domain="vpn.example.com",
            subs_path="sub",
            registry_path=self.registry_path,
            lock_path=self.lock_path
        )
        self.assertIsNone(info)


class TestNginxSubscriptionHardening(unittest.TestCase):
    """Verifies Nginx template enforces autoindex off, access_log off, and anti-caching."""

    def test_nginx_template_directives(self):
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        nginx_tmpl = os.path.join(repo_root, "config", "nginx", "nginx.conf.template")

        with open(nginx_tmpl, "r", encoding="utf-8") as f:
            content = f.read()

        # Find subscription location block
        self.assertIn("location ~ ^/{{SUBS_PATH}}/", content)
        sub_block = content[content.find("location ~ ^/{{SUBS_PATH}}/"):content.find("location /{{RULESET_PATH}}/")]

        # Autoindex must be explicitly off (anti-directory enumeration)
        self.assertIn("autoindex off;", sub_block)

        # Access log must be off to protect tokens from being recorded in logs
        self.assertIn("access_log off;", sub_block)

        # Anti-caching headers must be present
        self.assertIn("Cache-Control", sub_block)
        self.assertIn("no-store", sub_block)
        self.assertIn("Pragma", sub_block)


if __name__ == "__main__":
    unittest.main()
