#!/usr/bin/env python3
"""
VPN Subscription Security & Token Manager
Replaces predictable username-based subscription URLs with cryptographically secure,
unguessable tokens (128-bit entropy).
Supports token generation, rotation, revocation, and automated cleanup.
"""

import os
import json
import fcntl
import socket
import secrets
import logging
import base64
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple

logger = logging.getLogger("subscription_manager")

DEFAULT_REGISTRY_PATH = os.getenv("SUBSCRIPTIONS_REGISTRY", "/opt/incy-bot/subscriptions.json")
DEFAULT_LOCK_PATH = os.getenv("SUBSCRIPTIONS_LOCK", "/tmp/subscriptions.lock")


class SubscriptionError(Exception):
    """Base exception for subscription management errors."""
    pass


def generate_token() -> str:
    """
    Generates a cryptographically secure, URL-safe random token.
    16 bytes = 128 bits of entropy, giving 22 URL-safe characters.
    """
    return secrets.token_urlsafe(16)


def _lock_and_load_registry(registry_path: str, lock_path: str) -> Tuple[Dict[str, Any], int]:
    """
    Acquires exclusive file lock and loads subscription registry JSON.
    Returns (data, lock_fd). Caller MUST close lock_fd in finally block!
    """
    lock_dir = os.path.dirname(lock_path)
    if lock_dir:
        os.makedirs(lock_dir, exist_ok=True)

    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(lock_fd, fcntl.LOCK_EX)

    registry = {}
    if os.path.exists(registry_path):
        try:
            with open(registry_path, "r", encoding="utf-8") as f:
                registry = json.load(f)
        except Exception as e:
            logger.warning("Could not read registry '%s', initializing empty: %s", registry_path, e)
            registry = {}

    return registry, lock_fd


def _save_registry_and_unlock(registry: Dict[str, Any], registry_path: str, lock_fd: int):
    """
    Saves registry JSON with atomic replacement and releases lock.
    """
    try:
        reg_dir = os.path.dirname(registry_path)
        if reg_dir:
            os.makedirs(reg_dir, exist_ok=True)

        tmp_path = f"{registry_path}.tmp_{os.getpid()}"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(registry, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())

        os.replace(tmp_path, registry_path)
        os.chmod(registry_path, 0o600)
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(lock_fd)


def _sanitize_client_template(client_data: dict, domain: str) -> dict:
    """
    Sanitizes client JSON configuration:
    Resolves any {{SERVER_IP}} placeholders or missing /32 prefix in ip_cidr rules,
    preventing Go netip.ParsePrefix errors in Sing-box clients.
    """
    resolved_ip = None
    try:
        resolved_ip = socket.gethostbyname(domain)
    except Exception:
        pass

    route_rules = client_data.get("route", {}).get("rules", [])
    sanitized_rules = []
    for r in route_rules:
        if "ip_cidr" in r and isinstance(r["ip_cidr"], list):
            new_cidrs = []
            for cidr in r["ip_cidr"]:
                if "{{SERVER_IP" in cidr:
                    if resolved_ip:
                        new_cidrs.append(f"{resolved_ip}/32")
                elif "/" not in cidr:
                    new_cidrs.append(f"{cidr}/32")
                else:
                    new_cidrs.append(cidr)
            if new_cidrs:
                r["ip_cidr"] = new_cidrs
                sanitized_rules.append(r)
        else:
            sanitized_rules.append(r)

    if "route" in client_data and "rules" in client_data["route"]:
        client_data["route"]["rules"] = sanitized_rules
    return client_data


def create_or_update_subscription(
    username: str,
    vless_uuid: str,
    trojan_pass: str,
    domain: str,
    subs_path: str,
    vless_path: str,
    trojan_path: str,
    www_dir: str,
    reality_port: int = 8443,
    xhttp_port: int = 8444,
    masque_port: int = 8445,
    reality_public_key: str = "",
    reality_short_id: str = "",
    reality_sni: str = "",
    xhttp_path: str = "xhttp",
    vless_template: str = "/opt/incy-bot/template-vless.json",
    trojan_template: str = "/opt/incy-bot/template-trj.json",
    masque_template: str = "/opt/incy-bot/template-masque.json",
    registry_path: str = DEFAULT_REGISTRY_PATH,
    lock_path: str = DEFAULT_LOCK_PATH
) -> Dict[str, Any]:
    """
    Creates or updates subscription files using a secure token.
    Cleans up any previous tokenized files for this user.
    Supports dual-transport modern VPN:
    - Primary: VLESS + REALITY + Vision (TCP)
    - Backup: VLESS + XHTTP + REALITY
    - Legacy: VLESS WS + TLS & Trojan WS + TLS
    """
    registry, lock_fd = _lock_and_load_registry(registry_path, lock_path)
    try:
        old_entry = registry.get(username)
        if old_entry and "token" in old_entry:
            old_token = old_entry["token"]
            _cleanup_token_files(old_token, www_dir)

        # Generate fresh token
        token = generate_token()

        # Build subscription links
        vless_link = f"vless://{vless_uuid}@{domain}:443?security=tls&encryption=none&type=ws&path=%2F{vless_path}#{domain}-VLESS-{username}"
        trojan_link = f"trojan://{trojan_pass}@{domain}:443?security=tls&type=ws&path=%2F{trojan_path}#{domain}-Trojan-{username}"

        vless_reality_link = ""
        vless_xhttp_link = ""
        vless_ws_link = vless_link
        trojan_ws_link = trojan_link

        effective_sni = reality_sni.strip() if reality_sni else domain

        if reality_public_key:
            vless_reality_link = (
                f"vless://{vless_uuid}@{domain}:{reality_port}?"
                f"security=reality&encryption=none&pbk={reality_public_key}&"
                f"headerType=none&fp=chrome&spx=%2F&type=tcp&flow=xtls-rprx-vision&"
                f"sni={effective_sni}&sid={reality_short_id}#⚡ [Основной] VLESS-REALITY-Vision"
            )
            vless_xhttp_link = (
                f"vless://{vless_uuid}@{domain}:{xhttp_port}?"
                f"security=reality&encryption=none&pbk={reality_public_key}&"
                f"headerType=none&fp=chrome&type=xhttp&path=%2F{xhttp_path}&"
                f"sni={effective_sni}&sid={reality_short_id}#🛡️ [Резерв] VLESS-XHTTP-REALITY"
            )
            vless_ws_link = (
                f"vless://{vless_uuid}@{domain}:443?"
                f"security=tls&encryption=none&type=ws&path=%2F{vless_path}#🌐 [WS] VLESS-WS-TLS"
            )
            trojan_ws_link = (
                f"trojan://{trojan_pass}@{domain}:443?"
                f"security=tls&type=ws&path=%2F{trojan_path}#🔒 [WS] Trojan-WS-TLS"
            )
            masque_link = (
                f"masque://{username}:{trojan_pass}@{domain}:{masque_port}?"
                f"sni={domain}#🌐 [IETF] MASQUE-TLS"
            )
            sub_body = f"{vless_reality_link}\n{vless_xhttp_link}\n{masque_link}\n{vless_ws_link}\n{trojan_ws_link}\n"
        else:
            masque_link = f"masque://{username}:{trojan_pass}@{domain}:{masque_port}?sni={domain}#🌐 [IETF] MASQUE-TLS"
            sub_body = f"{vless_link}\n{trojan_link}\n{masque_link}\n"

        sub_b64 = base64.b64encode(sub_body.encode("utf-8")).decode("utf-8")

        os.makedirs(www_dir, exist_ok=True)

        # 1. Base64 subscription (.txt)
        txt_path = os.path.join(www_dir, f"{token}.txt")
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write(sub_b64)
        os.chmod(txt_path, 0o644)

        # 2. Sing-box VLESS client template
        vless_json_path = os.path.join(www_dir, f"{token}-vless.json")
        if os.path.exists(vless_template):
            try:
                with open(vless_template, "r", encoding="utf-8") as f:
                    vless_client = json.load(f)
                for ob in vless_client.get("outbounds", []):
                    if ob.get("type") == "vless" or (ob.get("tag") == "proxy" and ob.get("type") != "selector"):
                        ob["uuid"] = vless_uuid
                vless_client = _sanitize_client_template(vless_client, domain)
                with open(vless_json_path, "w", encoding="utf-8") as f:
                    json.dump(vless_client, f, indent=2, ensure_ascii=False)
                os.chmod(vless_json_path, 0o644)
            except Exception as e:
                logger.error("Failed to generate VLESS client json: %s", e)

        # 3. Trojan client template
        trj_json_path = os.path.join(www_dir, f"{token}-trj.json")
        if os.path.exists(trojan_template):
            try:
                with open(trojan_template, "r", encoding="utf-8") as f:
                    trj_client = json.load(f)
                for ob in trj_client.get("outbounds", []):
                    if ob.get("tag") == "proxy":
                        ob["password"] = trojan_pass
                trj_client = _sanitize_client_template(trj_client, domain)
                with open(trj_json_path, "w", encoding="utf-8") as f:
                    json.dump(trj_client, f, indent=2, ensure_ascii=False)
                os.chmod(trj_json_path, 0o644)
            except Exception as e:
                logger.error("Failed to generate Trojan client json: %s", e)

        # 4. MASQUE client template
        masque_json_path = os.path.join(www_dir, f"{token}-masque.json")
        if os.path.exists(masque_template):
            try:
                with open(masque_template, "r", encoding="utf-8") as f:
                    masque_content = f.read()
                masque_content = masque_content.replace("{{DOMAIN}}", domain)
                masque_content = masque_content.replace("{{MASQUE_PORT}}", str(masque_port))
                masque_content = masque_content.replace("{{USER_NAME}}", username)
                masque_content = masque_content.replace("{{USER_PASS}}", trojan_pass)
                with open(masque_json_path, "w", encoding="utf-8") as f:
                    f.write(masque_content)
                os.chmod(masque_json_path, 0o644)
            except Exception as e:
                logger.error("Failed to generate MASQUE client json: %s", e)
        else:
            try:
                fallback_masque = {
                    "log": {"loglevel": "warning"},
                    "inbounds": [
                        {"tag": "socks-in", "port": 10808, "listen": "127.0.0.1", "protocol": "socks", "settings": {"auth": "noauth", "udp": True}},
                        {"tag": "http-in", "port": 10809, "listen": "127.0.0.1", "protocol": "http"}
                    ],
                    "outbounds": [
                        {
                            "tag": "proxy-masque",
                            "protocol": "masque",
                            "settings": {
                                "address": domain,
                                "port": masque_port,
                                "email": username,
                                "pass": trojan_pass
                            },
                            "streamSettings": {
                                "network": "masque",
                                "security": "tls",
                                "tlsSettings": {"serverName": domain}
                            }
                        },
                        {"tag": "direct", "protocol": "freedom"}
                    ]
                }
                with open(masque_json_path, "w", encoding="utf-8") as f:
                    json.dump(fallback_masque, f, indent=2, ensure_ascii=False)
                os.chmod(masque_json_path, 0o644)
            except Exception as e:
                logger.error("Failed to generate fallback MASQUE client json: %s", e)

        # Save to registry
        registry[username] = {
            "token": token,
            "vless_uuid": vless_uuid,
            "trojan_pass": trojan_pass,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        _save_registry_and_unlock(registry, registry_path, lock_fd)

        sub_url = f"https://{domain}/{subs_path}/{token}.txt"
        singbox_json_url = f"https://{domain}/{subs_path}/{token}-vless.json"
        masque_json_url = f"https://{domain}/{subs_path}/{token}-masque.json"
        deeplink = f"incy://add/{sub_url}"

        return {
            "username": username,
            "token": token,
            "vless_uuid": vless_uuid,
            "sub_url": sub_url,
            "singbox_json_url": singbox_json_url,
            "masque_json_url": masque_json_url,
            "deeplink": deeplink,
            "vless_link": vless_reality_link if reality_public_key else vless_link,
            "vless_reality_link": vless_reality_link,
            "vless_xhttp_link": vless_xhttp_link,
            "masque_link": masque_link,
            "vless_ws_link": vless_ws_link,
            "trojan_link": trojan_ws_link
        }
    except Exception:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(lock_fd)
        raise


def get_subscription_info(
    username: str,
    domain: str,
    subs_path: str,
    registry_path: str = DEFAULT_REGISTRY_PATH,
    lock_path: str = DEFAULT_LOCK_PATH
) -> Optional[Dict[str, Any]]:
    """
    Retrieves current active subscription details for user.
    """
    registry, lock_fd = _lock_and_load_registry(registry_path, lock_path)
    try:
        entry = registry.get(username)
        if not entry:
            return None

        token = entry["token"]
        sub_url = f"https://{domain}/{subs_path}/{token}.txt"
        singbox_json_url = f"https://{domain}/{subs_path}/{token}-vless.json"
        masque_json_url = f"https://{domain}/{subs_path}/{token}-masque.json"
        deeplink = f"incy://add/{sub_url}"

        return {
            "username": username,
            "token": token,
            "vless_uuid": entry.get("vless_uuid", ""),
            "sub_url": sub_url,
            "singbox_json_url": singbox_json_url,
            "masque_json_url": masque_json_url,
            "deeplink": deeplink,
            "updated_at": entry.get("updated_at", "")
        }
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(lock_fd)


def rotate_subscription_token(
    username: str,
    domain: str,
    subs_path: str,
    vless_path: str,
    trojan_path: str,
    www_dir: str,
    reality_port: int = 8443,
    xhttp_port: int = 8444,
    masque_port: int = 8445,
    reality_public_key: str = "",
    reality_short_id: str = "",
    reality_sni: str = "",
    xhttp_path: str = "xhttp",
    vless_template: str = "/opt/incy-bot/template-vless.json",
    trojan_template: str = "/opt/incy-bot/template-trj.json",
    masque_template: str = "/opt/incy-bot/template-masque.json",
    config_path: Optional[str] = None,
    registry_path: str = DEFAULT_REGISTRY_PATH,
    lock_path: str = DEFAULT_LOCK_PATH
) -> Dict[str, Any]:
    """
    Rotates a user's subscription token:
    Revokes the old token, invalidates old files, and generates a new secret URL.
    If user is missing from registry but exists in sing-box config, migrates automatically.
    """
    info = get_subscription_info(username, domain, subs_path, registry_path, lock_path)
    vless_uuid = None
    trojan_pass = None

    if info:
        # Get UUID and password from existing entry
        registry, lock_fd = _lock_and_load_registry(registry_path, lock_path)
        try:
            entry = registry.get(username, {})
            vless_uuid = entry.get("vless_uuid")
            trojan_pass = entry.get("trojan_pass")
        finally:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(lock_fd)
    elif config_path and os.path.exists(config_path):
        # Fallback to reading credentials from sing-box config (migration support)
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            for ib in cfg.get("inbounds", []):
                if ib.get("tag") == "vless-in" or ib.get("type") == "vless":
                    for u in ib.get("users", []):
                        if u.get("name") == username:
                            vless_uuid = u.get("uuid")
                elif ib.get("tag") == "trojan-in" or ib.get("type") == "trojan":
                    for u in ib.get("users", []):
                        if u.get("name") == username:
                            trojan_pass = u.get("password")
        except Exception as e:
            logger.error("Failed to read credentials from %s for user %s: %s", config_path, username, e)

    if not vless_uuid or not trojan_pass:
        raise SubscriptionError(f"Не удалось получить реквизиты пользователя '{username}' для ротации.")

    return create_or_update_subscription(
        username=username,
        vless_uuid=vless_uuid,
        trojan_pass=trojan_pass,
        domain=domain,
        subs_path=subs_path,
        vless_path=vless_path,
        trojan_path=trojan_path,
        www_dir=www_dir,
        reality_port=reality_port,
        xhttp_port=xhttp_port,
        masque_port=masque_port,
        reality_public_key=reality_public_key,
        reality_short_id=reality_short_id,
        reality_sni=reality_sni,
        xhttp_path=xhttp_path,
        vless_template=vless_template,
        trojan_template=trojan_template,
        masque_template=masque_template,
        registry_path=registry_path,
        lock_path=lock_path
    )


def sync_subscriptions_from_config(
    config_path: str,
    domain: str,
    subs_path: str,
    vless_path: str,
    trojan_path: str,
    www_dir: str,
    reality_port: int = 8443,
    xhttp_port: int = 8444,
    masque_port: int = 8445,
    reality_public_key: str = "",
    reality_short_id: str = "",
    reality_sni: str = "",
    xhttp_path: str = "xhttp",
    vless_template: str = "/opt/incy-bot/template-vless.json",
    trojan_template: str = "/opt/incy-bot/template-trj.json",
    masque_template: str = "/opt/incy-bot/template-masque.json",
    registry_path: str = DEFAULT_REGISTRY_PATH,
    lock_path: str = DEFAULT_LOCK_PATH
) -> int:
    """
    Synchronizes users from sing-box config.json with the subscriptions registry:
    - Automatically migrates existing users missing from subscriptions.json
    - Generates 128-bit secure tokens for them
    - Cleans up legacy un-tokenized files (<username>.txt) from www_dir
    Returns count of migrated users.
    """
    if not os.path.exists(config_path):
        logger.warning("Config path '%s' not found for subscription sync.", config_path)
        return 0

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception as e:
        logger.error("Failed to read config for subscription sync: %s", e)
        return 0

    vless_users = {}
    trojan_users = {}
    for ib in cfg.get("inbounds", []):
        tag = ib.get("tag", "")
        if tag == "vless-in" or ib.get("type") == "vless":
            for u in ib.get("users", []):
                name = u.get("name")
                uuid = u.get("uuid")
                if name and uuid:
                    vless_users[name] = uuid
        elif tag == "trojan-in" or ib.get("type") == "trojan":
            for u in ib.get("users", []):
                name = u.get("name")
                pw = u.get("password")
                if name and pw:
                    trojan_users[name] = pw

    active_config_users = set(vless_users.keys()) | set(trojan_users.keys())
    migrated_count = 0

    for user in active_config_users:
        uuid = vless_users.get(user, "")
        pw = trojan_users.get(user, "")
        if not uuid or not pw:
            continue

        existing_info = get_subscription_info(user, domain, subs_path, registry_path, lock_path)
        if not existing_info:
            logger.info("Migrating legacy user '%s' to tokenized subscription...", user)
            create_or_update_subscription(
                username=user,
                vless_uuid=uuid,
                trojan_pass=pw,
                domain=domain,
                subs_path=subs_path,
                vless_path=vless_path,
                trojan_path=trojan_path,
                www_dir=www_dir,
                reality_port=reality_port,
                xhttp_port=xhttp_port,
                masque_port=masque_port,
                reality_public_key=reality_public_key,
                reality_short_id=reality_short_id,
                reality_sni=reality_sni,
                xhttp_path=xhttp_path,
                vless_template=vless_template,
                trojan_template=trojan_template,
                masque_template=masque_template,
                registry_path=registry_path,
                lock_path=lock_path
            )
            # Remove legacy files
            for legacy_name in (f"{user}.txt", f"{user}-VLESS-CLIENT.json", f"{user}-TRJ-CLIENT.json"):
                legacy_file = os.path.join(www_dir, legacy_name)
                if os.path.exists(legacy_file):
                    try:
                        os.remove(legacy_file)
                    except OSError:
                        pass
            migrated_count += 1
        else:
            # Refresh client JSON configs to ensure latest template fixes are applied
            token = existing_info.get("token")
            if token:
                if os.path.exists(vless_template):
                    try:
                        vless_json_path = os.path.join(www_dir, f"{token}-vless.json")
                        with open(vless_template, "r", encoding="utf-8") as f:
                            vless_client = json.load(f)
                        for ob in vless_client.get("outbounds", []):
                            if ob.get("type") == "vless" or (ob.get("tag") == "proxy" and ob.get("type") != "selector"):
                                ob["uuid"] = uuid
                        vless_client = _sanitize_client_template(vless_client, domain)
                        with open(vless_json_path, "w", encoding="utf-8") as f:
                            json.dump(vless_client, f, indent=2, ensure_ascii=False)
                        os.chmod(vless_json_path, 0o644)
                    except Exception as e:
                        logger.warning("Could not refresh VLESS client json for %s: %s", user, e)

                if os.path.exists(trojan_template):
                    try:
                        trj_json_path = os.path.join(www_dir, f"{token}-trj.json")
                        with open(trojan_template, "r", encoding="utf-8") as f:
                            trj_client = json.load(f)
                        for ob in trj_client.get("outbounds", []):
                            if ob.get("tag") == "proxy":
                                ob["password"] = pw
                        trj_client = _sanitize_client_template(trj_client, domain)
                        with open(trj_json_path, "w", encoding="utf-8") as f:
                            json.dump(trj_client, f, indent=2, ensure_ascii=False)
                        os.chmod(trj_json_path, 0o644)
                    except Exception as e:
                        logger.warning("Could not refresh Trojan client json for %s: %s", user, e)

                if os.path.exists(masque_template):
                    try:
                        masque_json_path = os.path.join(www_dir, f"{token}-masque.json")
                        with open(masque_template, "r", encoding="utf-8") as f:
                            masque_content = f.read()
                        masque_content = masque_content.replace("{{DOMAIN}}", domain)
                        masque_content = masque_content.replace("{{MASQUE_PORT}}", str(masque_port))
                        masque_content = masque_content.replace("{{USER_NAME}}", user)
                        masque_content = masque_content.replace("{{USER_PASS}}", pw)
                        with open(masque_json_path, "w", encoding="utf-8") as f:
                            f.write(masque_content)
                        os.chmod(masque_json_path, 0o644)
                    except Exception as e:
                        logger.warning("Could not refresh MASQUE client json for %s: %s", user, e)

                # Refresh {token}.txt subscription file with latest profiles
                try:
                    txt_path = os.path.join(www_dir, f"{token}.txt")
                    vless_link = f"vless://{uuid}@{domain}:443?security=tls&encryption=none&type=ws&path=%2F{vless_path}#🌐 [WS] VLESS-WS-TLS"
                    trojan_link = f"trojan://{pw}@{domain}:443?security=tls&type=ws&path=%2F{trojan_path}#🔒 [WS] Trojan-WS-TLS"
                    masque_link = f"masque://{user}:{pw}@{domain}:{masque_port}?sni={domain}#🌐 [IETF] MASQUE-TLS"

                    if reality_public_key:
                        vless_reality_link = (
                            f"vless://{uuid}@{domain}:{reality_port}?"
                            f"security=reality&encryption=none&pbk={reality_public_key}&"
                            f"headerType=none&fp=chrome&spx=%2F&type=tcp&flow=xtls-rprx-vision&"
                            f"sni={reality_sni or domain}&sid={reality_short_id}#⚡ [Основной] VLESS-REALITY-Vision"
                        )
                        vless_xhttp_link = (
                            f"vless://{uuid}@{domain}:{xhttp_port}?"
                            f"security=reality&encryption=none&pbk={reality_public_key}&"
                            f"headerType=none&fp=chrome&type=xhttp&path=%2F{xhttp_path}&"
                            f"sni={reality_sni or domain}&sid={reality_short_id}#🛡️ [Резерв] VLESS-XHTTP-REALITY"
                        )
                        sub_body = f"{vless_reality_link}\n{vless_xhttp_link}\n{masque_link}\n{vless_link}\n{trojan_link}\n"
                    else:
                        sub_body = f"{vless_link}\n{trojan_link}\n{masque_link}\n"

                    sub_b64 = base64.b64encode(sub_body.encode("utf-8")).decode("utf-8")
                    with open(txt_path, "w", encoding="utf-8") as f:
                        f.write(sub_b64)
                    os.chmod(txt_path, 0o644)
                except Exception as e:
                    logger.warning("Could not refresh subscription txt for %s: %s", user, e)

    return migrated_count


def revoke_subscription(
    username: str,
    www_dir: str,
    registry_path: str = DEFAULT_REGISTRY_PATH,
    lock_path: str = DEFAULT_LOCK_PATH
) -> bool:
    """
    Revokes a user's subscription:
    Deletes all tokenized files from www_dir and deletes the entry from registry.
    """
    registry, lock_fd = _lock_and_load_registry(registry_path, lock_path)
    try:
        entry = registry.pop(username, None)
        if not entry:
            return False

        token = entry.get("token")
        if token:
            _cleanup_token_files(token, www_dir)

        _save_registry_and_unlock(registry, registry_path, lock_fd)
        return True
    except Exception:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(lock_fd)
        raise


def _cleanup_token_files(token: str, www_dir: str):
    """Safely removes all files matching the token in www_dir."""
    if not token or not www_dir or not os.path.exists(www_dir):
        return

    for suffix in (".txt", "-vless.json", "-trj.json", "-masque.json", "-VLESS-CLIENT.json", "-TRJ-CLIENT.json"):
        path = os.path.join(www_dir, f"{token}{suffix}")
        if os.path.exists(path):
            try:
                os.remove(path)
            except OSError as e:
                logger.warning("Could not delete token file '%s': %s", path, e)
