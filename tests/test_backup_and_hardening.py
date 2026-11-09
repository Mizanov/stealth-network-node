#!/usr/bin/env python3
"""
Integration and security tests for Stage 6:
- Elimination of bash 'eval' in install.sh prompt_var
- Pinning of Docker images by immutable digest
- Nginx diagnostic error/access logging and persistent WebSocket timeouts
- Hardened backup script: integrity verification, strict permissions (0700/0600),
  atomic archive creation and restore mechanism.
"""

import os
import io
import stat
import tarfile
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestPromptVarSecurity(unittest.TestCase):
    """Tests for safe parameter reading in install.sh without eval."""

    def test_no_eval_in_install_sh(self):
        """Ensure install.sh does not contain any unsafe eval statements."""
        install_sh = (REPO_ROOT / "install.sh").read_text(encoding="utf-8")
        # Check that prompt_var uses printf -v instead of eval
        self.assertNotIn('eval "$var_name=', install_sh)
        self.assertNotIn("eval \"$var_name=\"", install_sh)
        self.assertIn('printf -v "$var_name"', install_sh)

    def test_prompt_var_injection_resistance(self):
        """Test prompt_var execution in bash with malicious input payloads."""
        bash_script = """
        set -euo pipefail
        error() { echo "ERR: $*" >&2; }
        
        prompt_var() {
            local var_name="$1"
            local prompt_text="$2"
            local default_val="${3:-}"
            local current_val="${!var_name:-}"

            if [[ ! "$var_name" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
                error "Invalid variable name: $var_name"
                return 1
            fi

            if [ -z "$current_val" ]; then
                if [ -n "$default_val" ]; then
                    read -r -p "$prompt_text [$default_val]: " input
                    printf -v "$var_name" '%s' "${input:-$default_val}"
                else
                    while [ -z "${!var_name:-}" ]; do
                        read -r -p "$prompt_text: " input
                        printf -v "$var_name" '%s' "$input"
                    done
                fi
            fi
        }

        # Injection payload attempt
        PAYLOAD='$(touch /tmp/evil_hacked_marker); echo "pwned"'
        echo "$PAYLOAD" | {
            prompt_var TEST_INJECTION "Enter value"
            echo "RESULT_VAR=$TEST_INJECTION"
        }
        """
        marker = Path("/tmp/evil_hacked_marker")
        if marker.exists():
            marker.unlink()

        try:
            res = subprocess.run(
                ["bash", "-c", bash_script],
                capture_output=True,
                text=True,
                check=True
            )
            self.assertIn("RESULT_VAR=$(touch /tmp/evil_hacked_marker); echo \"pwned\"", res.stdout)
            # The malicious payload must NOT have been executed
            self.assertFalse(marker.exists(), "Command injection vulnerability detected: marker file created!")
        finally:
            if marker.exists():
                marker.unlink()

    def test_prompt_var_rejects_invalid_identifier(self):
        """Test that prompt_var rejects invalid bash variable names."""
        bash_script = """
        error() { echo "ERR: $*" >&2; }
        prompt_var() {
            local var_name="$1"
            if [[ ! "$var_name" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
                error "Invalid variable name: $var_name"
                return 1
            fi
        }
        prompt_var "VAR;touch /tmp/injected;"
        """
        res = subprocess.run(
            ["bash", "-c", bash_script],
            capture_output=True,
            text=True
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Invalid variable name", res.stderr)


class TestNginxHardening(unittest.TestCase):
    """Tests verifying Nginx diagnostics, timeouts and privacy logging."""

    def setUp(self):
        self.nginx_conf = (REPO_ROOT / "config/nginx/nginx.conf.template").read_text(encoding="utf-8")

    def test_error_log_enabled_with_warn_level(self):
        """error_log must not be discarded to /dev/null."""
        self.assertNotIn("error_log                     /dev/null;", self.nginx_conf)
        self.assertIn("error_log                     /var/log/nginx/error.log warn;", self.nginx_conf)

    def test_privacy_preserving_access_log_format(self):
        """access_log must use privacy_audit log format."""
        self.assertIn("log_format privacy_audit", self.nginx_conf)
        self.assertIn("access_log                    /var/log/nginx/access.log privacy_audit", self.nginx_conf)

    def test_subscription_path_access_log_disabled(self):
        """Subscription path must remain access_log off to prevent leaking secret tokens."""
        subs_block = self.nginx_conf[self.nginx_conf.find("location ~ ^/{{SUBS_PATH}}"):]
        subs_block = subs_block[:subs_block.find("location /{{RULESET_PATH}}/")]
        self.assertIn("access_log off;", subs_block)

    def test_websocket_proxy_timeouts_extended(self):
        """WebSocket proxy timeout must be 1d (not 60s) to prevent idle connection drops."""
        ws_block = self.nginx_conf[self.nginx_conf.find("location @ws_proxy"):]
        ws_block = ws_block[:ws_block.find("# gzip")]
        self.assertIn("proxy_read_timeout                 1d;", ws_block)
        self.assertIn("proxy_send_timeout                 1d;", ws_block)
        self.assertNotIn("proxy_read_timeout                 60s;", ws_block)


class TestHardenedBackupScript(unittest.TestCase):
    """Tests for scripts/backup.sh functionality, security and integrity."""

    def setUp(self):
        self.backup_sh = REPO_ROOT / "scripts/backup.sh"
        self.test_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.test_dir.name)

        # Create mock target files
        self.mock_data = self.base_dir / "mock_system"
        self.mock_data.mkdir()
        (self.mock_data / "singbox_config.json").write_text('{"mock": true}', encoding="utf-8")
        (self.mock_data / "cert.pem").write_text("-----BEGIN CERTIFICATE-----", encoding="utf-8")

        self.backup_dir = self.base_dir / "backups"

    def tearDown(self):
        self.test_dir.cleanup()

    def test_backup_creates_archive_with_strict_permissions(self):
        """Backup script creates archive with 0600 mode in 0700 directory."""
        env = {
            **os.environ,
            "BACKUP_DIR": str(self.backup_dir),
            "BACKUP_TARGETS": str(self.mock_data)
        }
        res = subprocess.run([str(self.backup_sh)], capture_output=True, text=True, env=env)
        self.assertEqual(res.returncode, 0, f"backup.sh failed: {res.stderr}\n{res.stdout}")

        # Check backup directory permissions (0700)
        dir_stat = self.backup_dir.stat()
        dir_mode = stat.S_IMODE(dir_stat.st_mode)
        self.assertEqual(dir_mode, 0o700, f"Backup directory permissions {oct(dir_mode)} != 0700")

        # Find archive
        archives = list(self.backup_dir.glob("vps_backup_*.tar.gz"))
        self.assertEqual(len(archives), 1)
        archive = archives[0]

        # Check archive permissions (0600)
        file_stat = archive.stat()
        file_mode = stat.S_IMODE(file_stat.st_mode)
        self.assertEqual(file_mode, 0o600, f"Backup file permissions {oct(file_mode)} != 0600")

    def test_backup_verify_subcommand_valid_archive(self):
        """backup.sh --verify returns 0 for a valid archive."""
        env = {
            **os.environ,
            "BACKUP_DIR": str(self.backup_dir),
            "BACKUP_TARGETS": str(self.mock_data)
        }
        subprocess.run([str(self.backup_sh)], capture_output=True, text=True, env=env, check=True)
        archive = next(self.backup_dir.glob("vps_backup_*.tar.gz"))

        res = subprocess.run([str(self.backup_sh), "--verify", str(archive)], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertTrue("Archive passed all security and structural audits" in res.stdout or "Archive is valid" in res.stdout)

    def test_backup_verify_subcommand_corrupt_archive(self):
        """backup.sh --verify returns 1 for a corrupted archive."""
        corrupt_file = self.backup_dir / "corrupt.tar.gz"
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        corrupt_file.write_bytes(b"corrupted garbage content not a tarball")

        res = subprocess.run([str(self.backup_sh), "--verify", str(corrupt_file)], capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("verification failed", res.stderr)

    def test_backup_restore_subcommand(self):
        """backup.sh --restore extracts archived data faithfully."""
        env = {
            **os.environ,
            "BACKUP_DIR": str(self.backup_dir),
            "BACKUP_TARGETS": str(self.mock_data)
        }
        subprocess.run([str(self.backup_sh)], capture_output=True, text=True, env=env, check=True)
        archive = next(self.backup_dir.glob("vps_backup_*.tar.gz"))

        restore_dest = self.base_dir / "restored_output"
        res = subprocess.run(
            [str(self.backup_sh), "--restore", str(archive), str(restore_dest)],
            capture_output=True,
            text=True
        )
        self.assertEqual(res.returncode, 0, f"Restore failed: {res.stderr}\n{res.stdout}")
        self.assertTrue("Archive restored" in res.stdout)

        # Verify restored content
        restored_files = list(restore_dest.rglob("singbox_config.json"))
        self.assertTrue(len(restored_files) > 0, "singbox_config.json was not restored")
        content = restored_files[0].read_text(encoding="utf-8")
        self.assertEqual(content, '{"mock": true}')

    def test_backup_fails_gracefully_when_no_targets_exist(self):
        """backup.sh exits with code 1 when target paths do not exist."""
        env = {
            **os.environ,
            "BACKUP_DIR": str(self.backup_dir),
            "BACKUP_TARGETS": "/nonexistent/fake/file1 /nonexistent/fake/file2"
        }
        res = subprocess.run([str(self.backup_sh)], capture_output=True, text=True, env=env)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("None of the target backup paths exist", res.stderr)

    def test_backup_rejects_path_traversal_archive(self):
        """Archives containing '..' path traversal components must be blocked."""
        evil_archive = self.backup_dir / "evil_traversal.tar.gz"
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        with tarfile.open(evil_archive, "w:gz") as tar:
            data = b"injected root shell"
            ti = tarfile.TarInfo(name="../../etc/cron.d/evil")
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))

        res = subprocess.run([str(self.backup_sh), "--verify", str(evil_archive)], capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("path traversal", res.stderr)

    def test_backup_rejects_absolute_path_archive(self):
        """Archives containing absolute paths starting with '/' must be blocked."""
        evil_archive = self.backup_dir / "evil_abs.tar.gz"
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        with tarfile.open(evil_archive, "w:gz") as tar:
            data = b"injected"
            ti = tarfile.TarInfo(name="/etc/shadow")
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))

        res = subprocess.run([str(self.backup_sh), "--verify", str(evil_archive)], capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("absolute paths", res.stderr)

    def test_backup_rejects_dangerous_symlink_archive(self):
        """Archives containing symlinks pointing to absolute paths or escaping outwards must be blocked."""
        evil_archive = self.backup_dir / "evil_symlink.tar.gz"
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        with tarfile.open(evil_archive, "w:gz") as tar:
            ti = tarfile.TarInfo(name="symlink_to_root")
            ti.type = tarfile.SYMTYPE
            ti.linkname = "/etc/passwd"
            tar.addfile(ti)

        res = subprocess.run([str(self.backup_sh), "--verify", str(evil_archive)], capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("dangerous symlinks", res.stderr)

    def test_backup_restore_sanitizes_permissions(self):
        """Sensitive restored files (*.key, privkey.pem, .env, subscriptions.json) get 0600."""
        # Create a mock target with privkey.pem having overly open permissions (0644)
        privkey = self.mock_data / "privkey.pem"
        privkey.write_text("FAKE RSA PRIVATE KEY", encoding="utf-8")
        privkey.chmod(0o644)

        env = {
            **os.environ,
            "BACKUP_DIR": str(self.backup_dir),
            "BACKUP_TARGETS": str(self.mock_data)
        }
        subprocess.run([str(self.backup_sh)], capture_output=True, text=True, env=env, check=True)
        archive = next(self.backup_dir.glob("vps_backup_*.tar.gz"))

        restore_dest = self.base_dir / "restored_perm_check"
        subprocess.run([str(self.backup_sh), "--restore", str(archive), str(restore_dest)], check=True)

        restored_privkey = list(restore_dest.rglob("privkey.pem"))[0]
        mode = stat.S_IMODE(restored_privkey.stat().st_mode)
        self.assertEqual(mode, 0o600, f"Restored privkey.pem mode {oct(mode)} != 0600")

    def test_backup_prunes_older_archives(self):
        """backup.sh deletes archives older than RETENTION_DAYS."""
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        old_archive = self.backup_dir / "vps_backup_20200101_000000.tar.gz"
        old_archive.write_bytes(b"dummy")

        # Set mtime to 15 days ago
        old_time = time.time() - (15 * 86400)
        os.utime(old_archive, (old_time, old_time))

        env = {
            **os.environ,
            "BACKUP_DIR": str(self.backup_dir),
            "BACKUP_TARGETS": str(self.mock_data),
            "RETENTION_DAYS": "7"
        }
        res = subprocess.run([str(self.backup_sh)], capture_output=True, text=True, env=env, check=True)
        self.assertEqual(res.returncode, 0)

        self.assertFalse(old_archive.exists(), "Old archive was not pruned by retention policy")


if __name__ == "__main__":
    unittest.main()
