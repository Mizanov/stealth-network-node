"""
Security and system hardening validation test suite.
Verifies sudoers syntax with visudo, root-owned helper argument filtering,
path traversal defense, and systemd unit sandboxing.
"""

import os
import re
import subprocess
import tempfile
import unittest


class TestSudoersConfiguration(unittest.TestCase):
    """Verifies that config/sudoers/incy-bot.sudoers is syntactically valid and strictly scoped."""

    def setUp(self):
        self.repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.sudoers_file = os.path.join(self.repo_root, "config", "sudoers", "incy-bot.sudoers")

    def test_sudoers_file_exists(self):
        """File config/sudoers/incy-bot.sudoers must exist."""
        self.assertTrue(os.path.isfile(self.sudoers_file))

    def test_visudo_syntax_check(self):
        """visudo -cf must parse the sudoers file with returncode 0."""
        res = subprocess.run(["visudo", "-cf", self.sudoers_file], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"visudo syntax error: {res.stderr}")
        self.assertIn("parsed OK", res.stdout)

    def test_sudoers_no_arbitrary_root_commands(self):
        """Ensure incy-bot is NOT granted arbitrary ALL commands."""
        with open(self.sudoers_file, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        for line in lines:
            if line.startswith("Defaults:"):
                continue
            self.assertTrue(line.startswith("incy-bot ALL=(ALL) NOPASSWD: /usr/local/bin/singbox-control"))
            # Must strictly name /usr/local/bin/singbox-control, never general shells or ALL

    def test_sudoers_has_all_control_actions(self):
        """Sudoers must allow check, reload, rollback, and status."""
        with open(self.sudoers_file, "r", encoding="utf-8") as f:
            content = f.read()
        for action in ("check", "reload", "rollback", "status"):
            self.assertIn(f"/usr/local/bin/singbox-control {action}", content)
        self.assertNotIn("ALL=(ALL) ALL", content)
        self.assertNotIn("NOPASSWD: ALL", content)
        self.assertNotIn("/bin/bash", content)
        self.assertNotIn("/bin/sh", content)


class TestSingboxControlHelper(unittest.TestCase):
    """Verifies scripts/singbox-control.sh enforces strict parameter validation and blocks traversal."""

    def setUp(self):
        self.repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.script_path = os.path.join(self.repo_root, "scripts", "singbox-control.sh")

    def test_script_exists_and_executable(self):
        """scripts/singbox-control.sh must exist and be executable."""
        self.assertTrue(os.path.isfile(self.script_path))
        self.assertTrue(os.access(self.script_path, os.X_OK))

    def test_empty_action_fails(self):
        """Invoking script without arguments must exit with code 1."""
        res = subprocess.run([self.script_path], capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Invalid action", res.stderr)

    def test_arbitrary_action_fails(self):
        """Arbitrary actions must be rejected."""
        res = subprocess.run([self.script_path, "cat /etc/shadow"], capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Invalid action", res.stderr)

    def test_check_missing_target_fails(self):
        """check action without path parameter must fail."""
        res = subprocess.run([self.script_path, "check"], capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Missing target path", res.stderr)

    def test_check_non_existent_file_fails(self):
        """check action for non-existent file must fail."""
        res = subprocess.run([self.script_path, "check", "/tmp/non_existent_file_12345.json"], capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("does not exist", res.stderr)

    def test_check_disallowed_directory_fails(self):
        """check action pointing to /etc/shadow or /etc/passwd must be rejected."""
        passwd_path = "/etc/passwd"
        if os.path.exists(passwd_path):
            res = subprocess.run([self.script_path, "check", passwd_path], capture_output=True, text=True)
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("outside allowed directories", res.stderr)

    def test_check_path_traversal_blocked(self):
        """Path traversal like /tmp/singbox_dir/../../etc/passwd must be rejected."""
        test_dir = tempfile.mkdtemp(prefix="singbox_dir_", dir="/tmp")
        try:
            passwd_path = "/etc/passwd"
            if os.path.exists(passwd_path):
                traversal_path = os.path.join(test_dir, "..", "..", "etc", "passwd")
                res = subprocess.run([self.script_path, "check", traversal_path], capture_output=True, text=True)
                self.assertNotEqual(res.returncode, 0)
                self.assertIn("outside allowed directories", res.stderr)
        finally:
            if os.path.exists(test_dir):
                os.rmdir(test_dir)

    def test_rollback_missing_backup_fails(self):
        """Rollback without backup file must fail with non-zero exit code."""
        env = os.environ.copy()
        env["SINGBOX_BACKUP_FILE"] = "/tmp/singbox_nonexistent_backup.json.bak"
        env["SINGBOX_CONFIG_FILE"] = "/tmp/singbox_dummy_config.json"
        res = subprocess.run([self.script_path, "rollback"], capture_output=True, text=True, env=env)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Backup file", res.stderr)

    def test_rollback_restores_file(self):
        """Rollback must copy backup content to active config path."""
        with tempfile.NamedTemporaryFile(prefix="singbox_backup_", delete=False) as bk:
            bk.write(b'{"backup": true}')
            bk_path = bk.name
        with tempfile.NamedTemporaryFile(prefix="singbox_cfg_", delete=False) as cfg:
            cfg.write(b'{"live": true}')
            cfg_path = cfg.name

        try:
            env = os.environ.copy()
            env["SINGBOX_BACKUP_FILE"] = bk_path
            env["SINGBOX_CONFIG_FILE"] = cfg_path
            env["SYSTEMCTL_BIN"] = "/bin/echo"
            res = subprocess.run([self.script_path, "rollback"], capture_output=True, text=True, env=env)
            self.assertEqual(res.returncode, 0)
            with open(cfg_path, "rb") as f:
                content = f.read()
            self.assertEqual(content, b'{"backup": true}')
        finally:
            for p in (bk_path, cfg_path):
                if os.path.exists(p):
                    os.remove(p)


class TestSystemdServiceHardening(unittest.TestCase):
    """Verifies that bot/incy-bot.service applies strict systemd sandboxing."""

    def setUp(self):
        self.repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.service_file = os.path.join(self.repo_root, "bot", "incy-bot.service")
        with open(self.service_file, "r", encoding="utf-8") as f:
            self.content = f.read()

    def test_user_not_root(self):
        """Service must NOT run as root."""
        self.assertIn("User=incy-bot", self.content)
        self.assertIn("Group=incy-bot", self.content)
        self.assertNotIn("User=root", self.content)

    def test_sandboxing_directives(self):
        """Critical systemd hardening directives must be present."""
        expected_directives = [
            "NoNewPrivileges=false",
            "PrivateTmp=true",
            "ProtectSystem=strict",
            "ProtectHome=true",
            "ProtectKernelTunables=true",
            "ProtectKernelModules=true",
            "ProtectControlGroups=true",
            "LockPersonality=true",
            "ReadWritePaths=/opt/incy-bot /var/www /etc/sing-box /etc/xray /tmp",
        ]
        for directive in expected_directives:
            self.assertIn(directive, self.content, f"Missing critical systemd directive: {directive}")

    def test_sudo_compatibility_directives(self):
        """Directives that break sudo execution (like empty CapabilityBoundingSet or RestrictSUIDSGID) must not be set."""
        self.assertNotIn("CapabilityBoundingSet=", self.content)
        self.assertNotIn("RestrictSUIDSGID=true", self.content)
        self.assertIn("NoNewPrivileges=false", self.content)


if __name__ == "__main__":
    unittest.main()
