#!/usr/bin/env python3
"""
Traffic Statistics Manager for Incy / Sing-Box / Xray.

Handles:
1. Querying live per-user traffic counters from Xray API (gRPC/statsquery).
2. Delta accumulation with persistent JSON storage (/opt/incy-bot/traffic_stats.json).
3. Resilient against server reboots and Xray service restarts.
4. Concurrency control via file locks.
5. Human-readable byte formatting (B, KB, MB, GB, TB).
6. Per-user query, full dashboard statistics, and per-user stats reset.
"""

import os
import re
import json
import fcntl
import shutil
import logging
import subprocess
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Callable

logger = logging.getLogger("stats_manager")

DEFAULT_STATS_PATH = os.getenv("TRAFFIC_STATS_PATH", "/opt/incy-bot/traffic_stats.json")
DEFAULT_LOCK_PATH = os.getenv("TRAFFIC_STATS_LOCK", "/tmp/traffic_stats.lock")
XRAY_API_SERVER = os.getenv("XRAY_API_SERVER", "127.0.0.1:10085")
SINGBOX_CONTROL_BIN = os.getenv("SINGBOX_CONTROL_BIN", "/usr/local/bin/singbox-control")


def format_bytes(num_bytes: int) -> str:
    """
    Formats a byte count into a human-readable string (B, KB, MB, GB, TB).
    """
    if not isinstance(num_bytes, (int, float)) or num_bytes <= 0:
        return "0 B"

    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    val = float(num_bytes)
    unit_idx = 0

    while val >= 1024.0 and unit_idx < len(units) - 1:
        val /= 1024.0
        unit_idx += 1

    if unit_idx == 0:
        return f"{int(val)} B"
    elif unit_idx == 1:
        return f"{val:.1f} KB"
    elif unit_idx == 2:
        return f"{val:.1f} MB"
    else:
        return f"{val:.2f} {units[unit_idx]}"


def parse_xray_stats_output(raw_json_str: str) -> Dict[str, int]:
    """
    Parses JSON output from `xray api statsquery` into a mapping of {name: int(value)}.
    Supports both integer and string values in the JSON output.
    """
    if not raw_json_str or not raw_json_str.strip():
        return {}

    try:
        data = json.loads(raw_json_str)
    except Exception as e:
        logger.warning("Failed to parse xray stats JSON: %s", e)
        return {}

    stat_list = data.get("stat", [])
    if not isinstance(stat_list, list):
        return {}

    result = {}
    for item in stat_list:
        if isinstance(item, dict):
            name = item.get("name")
            val = item.get("value", 0)
            if name:
                try:
                    result[name] = int(val)
                except (ValueError, TypeError):
                    continue
    return result


def fetch_xray_raw_stats(
    server: str = XRAY_API_SERVER,
    control_bin: str = SINGBOX_CONTROL_BIN,
    timeout: int = 5
) -> Dict[str, int]:
    """
    Executes stats query command via singbox-control helper or direct xray CLI.
    Returns mapping of stat name to raw byte counter.
    """
    # 1. Try privileged helper if available
    if os.path.exists(control_bin):
        try:
            cmd = []
            if os.geteuid() != 0 and shutil.which("sudo"):
                cmd.append("sudo")
            cmd.extend([control_bin, "xray-stats"])
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if res.returncode == 0 and res.stdout.strip():
                parsed = parse_xray_stats_output(res.stdout)
                if parsed:
                    return parsed
        except Exception as e:
            logger.debug("singbox-control xray-stats failed: %s, falling back to direct xray CLI", e)

    # 2. Fallback to direct xray CLI
    xray_bin = shutil.which("xray") or "/usr/local/bin/xray"
    if os.path.exists(xray_bin) and os.access(xray_bin, os.X_OK):
        try:
            res = subprocess.run(
                [xray_bin, "api", "statsquery", f"--server={server}", "-pattern", "user>>>"],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            if res.returncode == 0 and res.stdout.strip():
                return parse_xray_stats_output(res.stdout)
        except Exception as e:
            logger.debug("Direct xray statsquery execution failed: %s", e)

    return {}


def _load_stats_file(path: str) -> Dict[str, Any]:
    """Safely loads persistent stats JSON file."""
    if not os.path.exists(path):
        return {"version": 1, "users": {}, "_raw_last": {}, "updated_at": None}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.error("Failed to load traffic stats file '%s': %s", path, e)
        return {"version": 1, "users": {}, "_raw_last": {}, "updated_at": None}


def _save_stats_file(data: Dict[str, Any], path: str):
    """Atomically writes persistent stats file using fsync and replace."""
    p_dir = os.path.dirname(path)
    if p_dir:
        os.makedirs(p_dir, exist_ok=True)
    tmp_path = f"{path}.tmp.{os.getpid()}"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, path)
    try:
        os.chmod(path, 0o660)
    except OSError:
        pass


def sync_traffic_stats(
    stats_path: str = DEFAULT_STATS_PATH,
    lock_path: str = DEFAULT_LOCK_PATH,
    raw_stats_provider: Optional[Callable[[], Dict[str, int]]] = None
) -> Dict[str, Any]:
    """
    Synchronizes traffic statistics:
    1. Fetches current raw stats from Xray.
    2. Acquires file lock.
    3. Loads existing persistent state.
    4. Computes monotonic deltas per user direction (handling service restarts).
    5. Saves state atomically to disk.
    6. Returns updated persistent state.
    """
    lock_dir = os.path.dirname(lock_path)
    if lock_dir:
        os.makedirs(lock_dir, exist_ok=True)

    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)

        state = _load_stats_file(stats_path)
        raw_stats = raw_stats_provider() if raw_stats_provider else fetch_xray_raw_stats()

        raw_last = state.setdefault("_raw_last", {})
        users = state.setdefault("users", {})
        now_iso = datetime.now(timezone.utc).isoformat()

        # Update per-user stats
        for stat_name, current_val in raw_stats.items():
            # Example: user>>>username>>>traffic>>>downlink
            parts = stat_name.split(">>>")
            if len(parts) == 4 and parts[0] == "user" and parts[2] == "traffic":
                username = parts[1]
                direction = parts[3]  # "uplink" or "downlink"
                if direction not in ("uplink", "downlink"):
                    continue

                prev_val = raw_last.get(stat_name, 0)
                if current_val >= prev_val:
                    delta = current_val - prev_val
                else:
                    # Service restarted / counters reset in Xray
                    delta = current_val

                u_entry = users.setdefault(username, {
                    "uplink": 0,
                    "downlink": 0,
                    "total": 0,
                    "last_seen": None
                })

                if delta > 0:
                    u_entry[direction] = u_entry.get(direction, 0) + delta
                    u_entry["total"] = u_entry.get("uplink", 0) + u_entry.get("downlink", 0)
                    u_entry["last_seen"] = now_iso

                raw_last[stat_name] = current_val

        state["updated_at"] = now_iso
        _save_stats_file(state, stats_path)
        return state

    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(lock_fd)


def get_user_traffic(
    username: str,
    stats_path: str = DEFAULT_STATS_PATH,
    sync: bool = True
) -> Dict[str, Any]:
    """
    Returns user traffic statistics:
    uplink, downlink, total, formatted strings, and last_seen.
    """
    if sync:
        try:
            state = sync_traffic_stats(stats_path=stats_path)
        except Exception as e:
            logger.warning("Failed to sync traffic stats: %s", e)
            state = _load_stats_file(stats_path)
    else:
        state = _load_stats_file(stats_path)

    u_data = state.get("users", {}).get(username, {})
    uplink = u_data.get("uplink", 0)
    downlink = u_data.get("downlink", 0)
    total = u_data.get("total", uplink + downlink)
    last_seen = u_data.get("last_seen")

    return {
        "username": username,
        "uplink": uplink,
        "downlink": downlink,
        "total": total,
        "formatted_uplink": format_bytes(uplink),
        "formatted_downlink": format_bytes(downlink),
        "formatted_total": format_bytes(total),
        "last_seen": last_seen
    }


def get_all_traffic_stats(
    known_users: Optional[List[str]] = None,
    stats_path: str = DEFAULT_STATS_PATH,
    sync: bool = True
) -> Dict[str, Any]:
    """
    Returns structured stats for all users and overall server totals.
    If known_users is provided, guarantees all registered users appear even with 0 B.
    """
    if sync:
        try:
            state = sync_traffic_stats(stats_path=stats_path)
        except Exception as e:
            logger.warning("Failed to sync traffic stats: %s", e)
            state = _load_stats_file(stats_path)
    else:
        state = _load_stats_file(stats_path)

    stored_users = state.get("users", {})
    all_names = set(stored_users.keys())
    if known_users:
        all_names.update(known_users)

    users_list = []
    server_uplink = 0
    server_downlink = 0

    for uname in sorted(all_names):
        u_data = stored_users.get(uname, {})
        ul = u_data.get("uplink", 0)
        dl = u_data.get("downlink", 0)
        tot = u_data.get("total", ul + dl)
        server_uplink += ul
        server_downlink += dl

        users_list.append({
            "username": uname,
            "uplink": ul,
            "downlink": dl,
            "total": tot,
            "formatted_uplink": format_bytes(ul),
            "formatted_downlink": format_bytes(dl),
            "formatted_total": format_bytes(tot),
            "last_seen": u_data.get("last_seen")
        })

    # Sort users by total traffic descending
    users_list.sort(key=lambda x: x["total"], reverse=True)

    server_total = server_uplink + server_downlink
    return {
        "users": users_list,
        "server_total": {
            "uplink": server_uplink,
            "downlink": server_downlink,
            "total": server_total,
            "formatted_uplink": format_bytes(server_uplink),
            "formatted_downlink": format_bytes(server_downlink),
            "formatted_total": format_bytes(server_total)
        },
        "updated_at": state.get("updated_at")
    }


def reset_user_traffic(
    username: str,
    stats_path: str = DEFAULT_STATS_PATH,
    lock_path: str = DEFAULT_LOCK_PATH
) -> bool:
    """
    Resets traffic counters for a specific user to 0 B while preserving _raw_last
    so subsequent Xray increments measure from this reset point.
    """
    lock_dir = os.path.dirname(lock_path)
    if lock_dir:
        os.makedirs(lock_dir, exist_ok=True)

    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        state = _load_stats_file(stats_path)
        users = state.setdefault("users", {})
        users[username] = {
            "uplink": 0,
            "downlink": 0,
            "total": 0,
            "last_seen": None
        }
        state["updated_at"] = datetime.now(timezone.utc).isoformat()
        _save_stats_file(state, stats_path)
        return True
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(lock_fd)


def remove_user_traffic(
    username: str,
    stats_path: str = DEFAULT_STATS_PATH,
    lock_path: str = DEFAULT_LOCK_PATH
) -> bool:
    """
    Removes user entry and associated _raw_last keys from persistent storage.
    Called when a user is deleted from VPN configuration.
    """
    lock_dir = os.path.dirname(lock_path)
    if lock_dir:
        os.makedirs(lock_dir, exist_ok=True)

    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        state = _load_stats_file(stats_path)
        users = state.get("users", {})
        removed = False
        if username in users:
            del users[username]
            removed = True

        raw_last = state.get("_raw_last", {})
        keys_to_del = [k for k in list(raw_last.keys()) if f">>>{username}>>>" in k]
        for k in keys_to_del:
            del raw_last[k]

        if removed:
            state["updated_at"] = datetime.now(timezone.utc).isoformat()
            _save_stats_file(state, stats_path)
        return removed
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(lock_fd)
