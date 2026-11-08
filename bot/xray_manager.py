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
        for u in ib.get("settings", {}).get("users", []):
            email = u.get("email")
            if email:
                users.add(email)
    return sorted(list(users))


def add_user_to_xray(
    config_data: Dict[str, Any],
    username: str,
    user_uuid: str,
    user_pass: Optional[str] = None
) -> Dict[str, Any]:
    """
    Adds user to reality-vision, reality-xhttp, and masque inbounds in Xray config.
    """
    effective_pass = user_pass or user_uuid
    found_inbounds = False
    for ib in config_data.get("inbounds", []):
        tag = ib.get("tag", "")
        proto = ib.get("protocol", "")
        stream = ib.get("streamSettings", {})
        network = stream.get("network", "")
        security = stream.get("security", "")

        is_vision = (tag == "vless-reality-vision-in") or (network == "tcp" and security == "reality")
        is_xhttp = (tag == "vless-reality-xhttp-in") or (network == "xhttp" and security == "reality")
        is_masque = (tag == "masque-in") or (proto == "masque") or (network == "masque")

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
        elif is_masque:
            found_inbounds = True
            users = ib.setdefault("settings", {}).setdefault("users", [])
            if not any(u.get("email") == username for u in users):
                users.append({
                    "email": username,
                    "pass": effective_pass
                })

    if not found_inbounds:
        logger.warning("No matching inbounds found in Xray configuration to add user '%s'.", username)

    return config_data


def delete_user_from_xray(config_data: Dict[str, Any], username: str) -> Dict[str, Any]:
    """
    Removes user from all inbounds in Xray config (both clients and users arrays).
    """
    for ib in config_data.get("inbounds", []):
        settings = ib.setdefault("settings", {})
        if "clients" in settings:
            settings["clients"] = [
                c for c in settings["clients"] if c.get("email") != username
            ]
        if "users" in settings:
            settings["users"] = [
                u for u in settings["users"] if u.get("email") != username
            ]
    return config_data


def ensure_xray_masque_config(
    config_data: Dict[str, Any],
    domain: str,
    masque_port: int = 8445
) -> Dict[str, Any]:
    """
    Ensures that Xray configuration contains the MASQUE (CONNECT-IP over HTTP/3)
    inbound listening on the given port with Let's Encrypt TLS certificates.
    """
    inbounds = config_data.setdefault("inbounds", [])
    has_masque = any(ib.get("tag") == "masque-in" or ib.get("protocol") == "masque" for ib in inbounds)
    if not has_masque:
        inbounds.append({
            "tag": "masque-in",
            "port": masque_port,
            "listen": "0.0.0.0",
            "protocol": "masque",
            "settings": {
                "address": ["10.13.0.1/24"],
                "users": []
            },
            "streamSettings": {
                "network": "masque",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": f"/etc/letsencrypt/live/{domain}/fullchain.pem",
                            "keyFile": f"/etc/letsencrypt/live/{domain}/privkey.pem"
                        }
                    ]
                }
            }
        })
    return config_data


def ensure_xray_stats_config(config_data: Dict[str, Any], api_port: int = 10085) -> Dict[str, Any]:
    """
    Ensures Xray configuration contains stats service, stats policy,
    API inbound, and routing rules for per-user traffic tracking.
    """
    if "stats" not in config_data or not isinstance(config_data["stats"], dict):
        config_data["stats"] = {}

    api_cfg = config_data.setdefault("api", {})
    api_cfg["tag"] = "api"
    services = api_cfg.setdefault("services", [])
    if "StatsService" not in services:
        services.append("StatsService")

    policy = config_data.setdefault("policy", {})
    levels = policy.setdefault("levels", {})
    lvl0 = levels.setdefault("0", {})
    lvl0["statsUserUplink"] = True
    lvl0["statsUserDownlink"] = True

    system = policy.setdefault("system", {})
    system["statsInboundUplink"] = True
    system["statsInboundDownlink"] = True

    inbounds = config_data.setdefault("inbounds", [])
    has_api_inbound = any(ib.get("tag") == "api" for ib in inbounds)
    if not has_api_inbound:
        inbounds.insert(0, {
            "tag": "api",
            "port": api_port,
            "listen": "127.0.0.1",
            "protocol": "dokodemo-door",
            "settings": {
                "address": "127.0.0.1"
            }
        })

    routing = config_data.setdefault("routing", {})
    rules = routing.setdefault("rules", [])
    has_api_rule = any(
        isinstance(r, dict) and r.get("outboundTag") == "api" and "api" in r.get("inboundTag", [])
        for r in rules
    )
    if not has_api_rule:
        rules.insert(0, {
            "inboundTag": ["api"],
            "outboundTag": "api",
            "type": "field"
        })

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
            try:
                shutil.copyfile(config_path, backup_path)
            except Exception as b_err:
                logger.warning("Could not create Xray backup file '%s': %s", backup_path, b_err)

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
                        try:
                            shutil.copyfile(backup_path, config_path)
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
