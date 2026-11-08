#!/usr/bin/env python3
"""
Transactional Sing-box Configuration Manager
Ensures atomic mutations, syntax pre-validation, automatic rollback on failure,
and concurrency control via file locks.
"""

import os
import re
import json
import fcntl
import shutil
import tempfile
import logging
import subprocess
from contextlib import contextmanager
from typing import Callable, Tuple, Any, Optional, List, Dict

logger = logging.getLogger("config_manager")

# Regex for safe usernames: alphanumeric, underscore, hyphen, 1 to 32 characters
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_-]{1,32}$")

# Default lock file path
DEFAULT_LOCK_FILE = os.getenv("SINGBOX_LOCK_FILE", "/tmp/singbox_config.lock")


class ConfigManagerError(Exception):
    """Base exception for config manager errors."""
    pass


class InvalidUsernameError(ConfigManagerError):
    """Raised when username fails security validation."""
    pass


class UserAlreadyExistsError(ConfigManagerError):
    """Raised when attempting to add an existing username."""
    pass


class UserNotFoundError(ConfigManagerError):
    """Raised when requested user does not exist in configuration."""
    pass


class ConfigLoadError(ConfigManagerError):
    """Raised when configuration file cannot be read or parsed."""
    pass


class ConfigValidationError(ConfigManagerError):
    """Raised when proposed configuration fails sing-box check."""
    pass


class ConfigReloadError(ConfigManagerError):
    """Raised when sing-box reload fails and rollback is executed."""
    pass


def validate_username(username: Optional[str]) -> str:
    """
    Validates username against strict whitelist.
    Prevents path traversal, shell injection, and oversized strings.
    """
    if not username:
        raise InvalidUsernameError("Имя пользователя не может быть пустым.")

    username = username.strip()
    if not USERNAME_REGEX.match(username):
        raise InvalidUsernameError(
            f"Некорректное имя пользователя '{username}'. "
            "Разрешены только латинские буквы, цифры, знаки '-' и '_' (длина от 1 до 32 символов)."
        )

    # Explicit defense against path traversal substrings
    if ".." in username or "/" in username or "\\" in username:
        raise InvalidUsernameError("Обнаружены недопустимые символы пути.")

    return username


@contextmanager
def config_lock(lock_path: str = DEFAULT_LOCK_FILE):
    """
    Exclusive file lock to prevent race conditions during concurrent admin updates.
    """
    # Ensure directory exists
    lock_dir = os.path.dirname(lock_path)
    if lock_dir:
        os.makedirs(lock_dir, exist_ok=True)

    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(lock_fd)


def default_control_runner(action: str, target: Optional[str] = None) -> subprocess.CompletedProcess:
    """
    Default executor for privileged helper `/usr/local/bin/singbox-control`.
    """
    helper_bin = os.getenv("SINGBOX_CONTROL_BIN", "/usr/local/bin/singbox-control")
    cmd = []
    if os.geteuid() != 0:
        cmd.append("sudo")
    cmd.extend([helper_bin, action])
    if target:
        cmd.append(target)

    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=15,
        check=True
    )


def atomic_modify_singbox_config(
    mutator_fn: Callable[[Dict[str, Any]], Tuple[Dict[str, Any], Any]],
    config_path: str = "/etc/sing-box/config.json",
    backup_path: Optional[str] = None,
    control_runner: Callable[..., Any] = default_control_runner,
    lock_path: str = DEFAULT_LOCK_FILE
) -> Any:
    """
    Performs safe transactional mutation of sing-box configuration:
    1. Acquires exclusive lock.
    2. Reads current config.
    3. Runs in-memory mutator.
    4. Writes to secure temporary candidate file.
    5. Validates candidate config via singbox-control check.
    6. Creates backup (.bak).
    7. Atomically replaces config.json.
    8. Reloads sing-box core and verifies status.
    9. On reload/status failure: triggers automatic rollback from backup.
    10. Cleans up temporary resources.
    """
    if backup_path is None:
        backup_path = f"{config_path}.bak"

    with config_lock(lock_path):
        if not os.path.exists(config_path):
            raise ConfigLoadError(f"Конфигурационный файл '{config_path}' не найден.")

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                original_cfg = json.load(f)
        except Exception as e:
            raise ConfigLoadError(f"Не удалось прочитать JSON из '{config_path}': {e}")

        # Deep copy to ensure purity of mutator
        cfg_copy = json.loads(json.dumps(original_cfg))

        # Mutate in memory
        modified_cfg, result_payload = mutator_fn(cfg_copy)

        # Basic schema integrity check
        if not isinstance(modified_cfg, dict) or "inbounds" not in modified_cfg:
            raise ConfigValidationError("Некорректная структура конфигурации: отсутствует ключ 'inbounds'.")

        # Determine temp directory: prefer directory of config_path if writable, else /tmp
        cfg_dir = os.path.dirname(os.path.abspath(config_path))
        if os.access(cfg_dir, os.W_OK):
            temp_dir = cfg_dir
            temp_prefix = "config.json.tmp_"
        else:
            temp_dir = "/tmp"
            temp_prefix = "singbox_cand_"

        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=temp_dir,
                prefix=temp_prefix,
                suffix=".json",
                delete=False
            ) as tmp_file:
                tmp_path = tmp_file.name
                json.dump(modified_cfg, tmp_file, indent=2, ensure_ascii=False)
                tmp_file.flush()
                os.fsync(tmp_file.fileno())

            # Step 5: Syntax and schema pre-validation via singbox-control
            try:
                control_runner("check", tmp_path)
            except subprocess.CalledProcessError as e:
                err_detail = e.stderr.strip() if e.stderr else str(e)
                logger.error("Sing-box configuration pre-validation failed: %s", err_detail)
                raise ConfigValidationError(f"Проверка конфигурации sing-box завершилась ошибкой: {err_detail}")
            except Exception as e:
                logger.error("Failed to execute sing-box pre-validation: %s", e)
                raise ConfigValidationError(f"Не удалось выполнить проверку конфигурации: {e}")

            # Step 6: Create backup copy
            try:
                shutil.copy2(config_path, backup_path)
            except Exception as e:
                logger.warning("Could not create backup file '%s': %s", backup_path, e)

            # Step 7: Atomic replace
            try:
                os.replace(tmp_path, config_path)
            except OSError:
                # If across filesystem boundary (e.g. /tmp to /etc), atomic copy via same-dir temp file
                atomic_tmp = f"{config_path}.atomic_{os.getpid()}"
                shutil.copy2(tmp_path, atomic_tmp)
                os.replace(atomic_tmp, config_path)

            # Step 8: Reload sing-box core and verify health
            try:
                control_runner("reload")
                control_runner("status")
            except Exception as reload_err:
                logger.critical(
                    "FATAL: sing-box reload or health check failed! Initiating automatic rollback: %s",
                    reload_err
                )
                # Step 9: Automatic rollback to previous working state
                rollback_success = False
                if os.path.exists(backup_path):
                    try:
                        shutil.copy2(backup_path, config_path)
                        control_runner("reload")
                        rollback_success = True
                        logger.info("Automatic rollback succeeded. Previous working configuration restored.")
                    except Exception as rb_err:
                        logger.critical("CRITICAL: Automatic rollback failed to restore service: %s", rb_err)

                msg = (
                    f"Сбой перезагрузки Sing-box: {reload_err}. "
                    f"Предыдущая конфигурация {'успешно восстановлена из резервной копии.' if rollback_success else 'НЕ восстановлена!'}"
                )
                raise ConfigReloadError(msg)

            return result_payload

        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass


def add_user_to_config(
    username: str,
    new_uuid: str,
    new_pass: str,
    config_path: str = "/etc/sing-box/config.json",
    backup_path: Optional[str] = None,
    control_runner: Callable[..., Any] = default_control_runner,
    lock_path: str = DEFAULT_LOCK_FILE
) -> Dict[str, str]:
    """
    Safely adds a new user with UUID and Trojan password to sing-box configuration.
    """
    valid_user = validate_username(username)

    def _mutator(cfg: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, str]]:
        # Check if user already exists
        for ib in cfg.get("inbounds", []):
            if ib.get("tag") in ("vless-in", "trojan-in"):
                for u in ib.get("users", []):
                    if u.get("name") == valid_user:
                        raise UserAlreadyExistsError(f"Пользователь '{valid_user}' уже существует!")

        vless_added = False
        trojan_added = False

        for ib in cfg.get("inbounds", []):
            tag = ib.get("tag")
            ib_type = ib.get("type")
            if tag == "vless-in":
                ib.setdefault("users", []).append({"name": valid_user, "uuid": new_uuid})
                vless_added = True
            elif tag == "trojan-in":
                ib.setdefault("users", []).append({"name": valid_user, "password": new_pass})
                trojan_added = True
            elif tag == "hy2-in" or ib_type == "hysteria2":
                ib.setdefault("users", []).append({"name": valid_user, "password": new_pass})

        if not vless_added and not trojan_added:
            raise ConfigValidationError("В конфигурации отсутствуют секции 'vless-in' и 'trojan-in'.")

        return cfg, {"username": valid_user, "uuid": new_uuid, "password": new_pass}

    return atomic_modify_singbox_config(
        mutator_fn=_mutator,
        config_path=config_path,
        backup_path=backup_path,
        control_runner=control_runner,
        lock_path=lock_path
    )


def delete_user_from_config(
    username: str,
    config_path: str = "/etc/sing-box/config.json",
    backup_path: Optional[str] = None,
    control_runner: Callable[..., Any] = default_control_runner,
    lock_path: str = DEFAULT_LOCK_FILE
) -> bool:
    """
    Safely deletes a user from all inbound sections of sing-box configuration.
    """
    valid_user = validate_username(username)

    def _mutator(cfg: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
        found = False
        for ib in cfg.get("inbounds", []):
            if ib.get("tag") in ("vless-in", "trojan-in", "hy2-in") or ib.get("type") == "hysteria2":
                users = ib.get("users", [])
                new_users = [u for u in users if u.get("name") != valid_user]
                if len(new_users) != len(users):
                    ib["users"] = new_users
                    found = True

        if not found:
            raise UserNotFoundError(f"Пользователь '{valid_user}' не найден в конфигурации.")

        return cfg, True

    return atomic_modify_singbox_config(
        mutator_fn=_mutator,
        config_path=config_path,
        backup_path=backup_path,
        control_runner=control_runner,
        lock_path=lock_path
    )


def ensure_singbox_hy2_config(
    cfg: Dict[str, Any],
    domain: str,
    hy2_port: int = 443,
    obfs_password: str = "sal_sec_84729472",
    cert_dir: str = "/etc/letsencrypt/live"
) -> Dict[str, Any]:
    """
    Ensures sing-box configuration has a 'hy2-in' (Hysteria 2 with Salamander obfs) inbound.
    """
    inbounds = cfg.setdefault("inbounds", [])
    has_hy2 = any(ib.get("tag") == "hy2-in" or ib.get("type") == "hysteria2" for ib in inbounds)
    if not has_hy2:
        cert_path = f"{cert_dir}/{domain}/fullchain.pem"
        key_path = f"{cert_dir}/{domain}/privkey.pem"
        initial_users = []
        for ib in inbounds:
            if ib.get("tag") == "trojan-in":
                for u in ib.get("users", []):
                    if "name" in u and "password" in u:
                        initial_users.append({"name": u["name"], "password": u["password"]})
                break

        hy2_inbound = {
            "type": "hysteria2",
            "tag": "hy2-in",
            "listen": "::",
            "listen_port": hy2_port,
            "users": initial_users,
            "obfs": {
                "type": "salamander",
                "password": obfs_password
            },
            "tls": {
                "enabled": True,
                "server_name": domain,
                "certificate_path": cert_path,
                "key_path": key_path
            }
        }
        inbounds.append(hy2_inbound)
    else:
        for ib in inbounds:
            if ib.get("tag") == "hy2-in" or ib.get("type") == "hysteria2":
                ib["listen_port"] = hy2_port
                if "obfs" in ib and obfs_password:
                    ib["obfs"]["password"] = obfs_password
                break
    return cfg


def list_users_from_config(
    config_path: str = "/etc/sing-box/config.json",
    lock_path: str = DEFAULT_LOCK_FILE
) -> List[str]:
    """
    Reads existing user names safely using the shared lock.
    """
    if not os.path.exists(config_path):
        return []

    with config_lock(lock_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception as e:
            logger.error("Failed to read users from '%s': %s", config_path, e)
            return []

    users = set()
    for ib in cfg.get("inbounds", []):
        if ib.get("tag") in ("vless-in", "trojan-in"):
            for u in ib.get("users", []):
                name = u.get("name")
                if name:
                    users.add(name)

    return sorted(list(users))
