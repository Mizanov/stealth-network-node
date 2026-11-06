#!/usr/bin/env python3
"""
Xray Transactional Configuration Manager
Handles atomic mutations, validation, and user synchronization for Xray-core:
- VLESS + REALITY + Vision (TCP)
- VLESS + XHTTP + REALITY
"""

import os
import json
import fcntl
import shutil
import logging
from typing import Dict, Any, List, Optional, Callable

logger = logging.getLogger("xray_manager")

DEFAULT_XRAY_CONFIG = os.getenv("XRAY_CONFIG_JSON", "/etc/xray/config.json")
DEFAULT_XRAY_LOCK = os.getenv("XRAY_LOCK_FILE", "/tmp/xray_config.lock")


class XrayConfigError(Exception):
    """Base exception for Xray configuration management errors."""
    pass


class XrayValidationError(XrayConfigError):
    """Raised when Xray configuration fails pre-validation."""
    pass


class XrayReloadError(XrayConfigError):
    """Raised when Xray fails to reload."""
    pass


def load_xray_config(config_path: str = DEFAULT_XRAY_CONFIG) -> Dict[str, Any]:
    """Safely loads Xray configuration from JSON."""
    if not os.path.exists(config_path):
        raise XrayConfigError(f"Xray configuration file '{config_path}' does not exist.")
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        raise XrayConfigError(f"Failed to parse Xray JSON configuration: {e}")


def list_users_from_xray(config_path: str = DEFAULT_XRAY_CONFIG) -> List[str]:
    """Returns list of unique usernames (emails) registered in Xray inbounds."""
    try:
        data = load_xray_config(config_path)
    except Exception:
        return []

    users = set()
    for ib in data.get("inbounds", []):
        for c in ib.get("settings", {}).get("clients", []):
            email = c.get("email")
            if email:
                users.add(email)
    return sorted(list(users))


def add_user_to_xray(config_data: Dict[str, Any], username: str, user_uuid: str) -> Dict[str, Any]:
    """
    Adds user to both reality-vision and reality-xhttp inbounds in Xray config.
    """
    found_inbounds = False
    for ib in config_data.get("inbounds", []):
        tag = ib.get("tag", "")
        stream = ib.get("streamSettings", {})
        network = stream.get("network", "")
        security = stream.get("security", "")

        is_vision = (tag == "vless-reality-vision-in") or (network == "tcp" and security == "reality")
        is_xhttp = (tag == "vless-reality-xhttp-in") or (network == "xhttp" and security == "reality")

        if is_vision:
            found_inbounds = True
            clients = ib.setdefault("settings", {}).setdefault("clients", [])
            # Deduplicate by email or id
            if not any(c.get("id") == user_uuid or c.get("email") == username for c in clients):
                clients.append({
                    "id": user_uuid,
                    "flow": "xtls-rprx-vision",
                    "email": username
                })
        elif is_xhttp:
            found_inbounds = True
            clients = ib.setdefault("settings", {}).setdefault("clients", [])
            if not any(c.get("id") == user_uuid or c.get("email") == username for c in clients):
                clients.append({
                    "id": user_uuid,
                    "email": username
                })

    if not found_inbounds:
        logger.warning("No matching REALITY inbounds found in Xray configuration to add user '%s'.", username)

    return config_data


def delete_user_from_xray(config_data: Dict[str, Any], username: str) -> Dict[str, Any]:
    """
    Removes user from all inbounds in Xray config.
    """
    for ib in config_data.get("inbounds", []):
        clients = ib.get("settings", {}).get("clients", [])
        ib.setdefault("settings", {})["clients"] = [
            c for c in clients if c.get("email") != username
        ]
    return config_data


def atomic_modify_xray_config(
    mutation_fn: Callable[[Dict[str, Any]], Dict[str, Any]],
    config_path: str = DEFAULT_XRAY_CONFIG,
    lock_path: str = DEFAULT_XRAY_LOCK,
    control_runner: Optional[Callable[[str, Optional[str]], Any]] = None
) -> Dict[str, Any]:
    """
    Executes transactional modification of Xray configuration with flock,
    pre-validation via privileged helper, and auto-rollback on failure.
    """
    lock_dir = os.path.dirname(lock_path)
    if lock_dir:
        os.makedirs(lock_dir, exist_ok=True)

    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        current_config = load_xray_config(config_path)
        new_config = mutation_fn(current_config)

        # Write to temporary file for pre-validation
        tmp_dir = os.path.dirname(config_path) or "/tmp"
        tmp_path = os.path.join(tmp_dir, f"xray_cfg_tmp_{os.getpid()}.json")
        backup_path = f"{config_path}.bak"

        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(new_config, f, indent=2, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())

            # Validate temporary configuration
            if control_runner:
                try:
                    control_runner("xray-check", tmp_path)
                except Exception as val_err:
                    raise XrayValidationError(f"Xray validation rejected configuration: {val_err}")

            # Backup current config
            shutil.copy2(config_path, backup_path)

            # Atomic replace
            os.replace(tmp_path, config_path)
            try:
                os.chmod(config_path, 0o660)
            except OSError:
                pass

            # Reload Xray
            if control_runner:
                try:
                    control_runner("xray-reload", None)
                    control_runner("xray-status", None)
                except Exception as rel_err:
                    logger.critical("Xray reload failed! Rolling back from backup: %s", rel_err)
                    if os.path.exists(backup_path):
                        shutil.copy2(backup_path, config_path)
                        try:
                            control_runner("xray-reload", None)
                        except Exception:
                            pass
                    raise XrayReloadError(f"Failed to reload Xray: {rel_err}. Rolled back.")

            return new_config

        finally:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(lock_fd)
