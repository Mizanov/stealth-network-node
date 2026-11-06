#!/usr/bin/env python3
"""
Unit and Integration Tests for Traffic Statistics Manager.
Covers:
1. format_bytes human-readable byte formatting.
2. parse_xray_stats_output JSON parser robustness.
3. sync_traffic_stats delta accumulation, monotonic growth, service restart recovery.
4. get_user_traffic and get_all_traffic_stats reporting.
5. reset_user_traffic and remove_user_traffic mutations.
6. File locking and atomic persistence.
"""

import os
import sys
import json
import tempfile
import shutil
import unittest
from unittest.mock import patch, MagicMock

# Ensure bot directory is in sys.path
BOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bot"))
if BOT_DIR not in sys.path:
    sys.path.insert(0, BOT_DIR)

from stats_manager import (
    format_bytes,
    parse_xray_stats_output,
    sync_traffic_stats,
    get_user_traffic,
    get_all_traffic_stats,
    reset_user_traffic,
    remove_user_traffic
)


class TestFormatBytes(unittest.TestCase):
    """Verifies byte size human-readable formatting."""

    def test_zero_and_negative(self):
        self.assertEqual(format_bytes(0), "0 B")
        self.assertEqual(format_bytes(-50), "0 B")
        self.assertEqual(format_bytes(None), "0 B")
        self.assertEqual(format_bytes("invalid"), "0 B")

    def test_bytes(self):
        self.assertEqual(format_bytes(1), "1 B")
        self.assertEqual(format_bytes(512), "512 B")
        self.assertEqual(format_bytes(1023), "1023 B")

    def test_kilobytes(self):
        self.assertEqual(format_bytes(1024), "1.0 KB")
        self.assertEqual(format_bytes(1536), "1.5 KB")
        self.assertEqual(format_bytes(1024 * 500), "500.0 KB")

    def test_megabytes(self):
        self.assertEqual(format_bytes(1024 * 1024), "1.0 MB")
        self.assertEqual(format_bytes(int(1024 * 1024 * 142.5)), "142.5 MB")

    def test_gigabytes(self):
        self.assertEqual(format_bytes(1024 * 1024 * 1024), "1.00 GB")
        self.assertEqual(format_bytes(int(1024 * 1024 * 1024 * 1.38)), "1.38 GB")

    def test_terabytes(self):
        self.assertEqual(format_bytes(1024 * 1024 * 1024 * 1024), "1.00 TB")
        self.assertEqual(format_bytes(int(1024 * 1024 * 1024 * 1024 * 2.5)), "2.50 TB")


class TestParseXrayStatsOutput(unittest.TestCase):
    """Verifies parsing of Xray api statsquery JSON output."""

    def test_empty_or_invalid_string(self):
        self.assertEqual(parse_xray_stats_output(""), {})
        self.assertEqual(parse_xray_stats_output("   "), {})
        self.assertEqual(parse_xray_stats_output("{not_json"), {})
        self.assertEqual(parse_xray_stats_output("{}"), {})

    def test_valid_json_output(self):
        raw = json.dumps({
            "stat": [
                {"name": "user>>>alice>>>traffic>>>downlink", "value": 1048576},
                {"name": "user>>>alice>>>traffic>>>uplink", "value": "524288"},
                {"name": "inbound>>>api>>>traffic>>>downlink", "value": 100}
            ]
        })
        parsed = parse_xray_stats_output(raw)
        self.assertEqual(parsed["user>>>alice>>>traffic>>>downlink"], 1048576)
        self.assertEqual(parsed["user>>>alice>>>traffic>>>uplink"], 524288)
        self.assertEqual(parsed["inbound>>>api>>>traffic>>>downlink"], 100)


class TestStatsManagerLifecycle(unittest.TestCase):
    """Tests delta calculation, persistence, reset, and user deletion."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="stats_test_")
        self.stats_file = os.path.join(self.tmp_dir, "traffic_stats.json")
        self.lock_file = os.path.join(self.tmp_dir, "traffic_stats.lock")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_initial_sync_creates_state(self):
        mock_raw = {
            "user>>>user1>>>traffic>>>downlink": 1000,
            "user>>>user1>>>traffic>>>uplink": 500,
        }

        state = sync_traffic_stats(
            stats_path=self.stats_file,
            lock_path=self.lock_file,
            raw_stats_provider=lambda: mock_raw
        )

        self.assertIn("user1", state["users"])
        self.assertEqual(state["users"]["user1"]["downlink"], 1000)
        self.assertEqual(state["users"]["user1"]["uplink"], 500)
        self.assertEqual(state["users"]["user1"]["total"], 1500)
        self.assertTrue(os.path.exists(self.stats_file))

    def test_monotonic_growth(self):
        # 1. First sync
        mock1 = {
            "user>>>bob>>>traffic>>>downlink": 1000,
            "user>>>bob>>>traffic>>>uplink": 200,
        }
        sync_traffic_stats(
            stats_path=self.stats_file,
            lock_path=self.lock_file,
            raw_stats_provider=lambda: mock1
        )

        # 2. Second sync: user downloads 500 more, uploads 100 more
        mock2 = {
            "user>>>bob>>>traffic>>>downlink": 1500,
            "user>>>bob>>>traffic>>>uplink": 300,
        }
        state = sync_traffic_stats(
            stats_path=self.stats_file,
            lock_path=self.lock_file,
            raw_stats_provider=lambda: mock2
        )

        self.assertEqual(state["users"]["bob"]["downlink"], 1500)
        self.assertEqual(state["users"]["bob"]["uplink"], 300)
        self.assertEqual(state["users"]["bob"]["total"], 1800)

    def test_service_restart_recovery(self):
        """When Xray restarts, counters drop to 0, then increase; total must accumulate monotonically."""
        # Baseline: 10000 DL
        sync_traffic_stats(
            stats_path=self.stats_file,
            lock_path=self.lock_file,
            raw_stats_provider=lambda: {"user>>>charlie>>>traffic>>>downlink": 10000}
        )

        # Xray restarted! Counter reset to 500
        sync_traffic_stats(
            stats_path=self.stats_file,
            lock_path=self.lock_file,
            raw_stats_provider=lambda: {"user>>>charlie>>>traffic>>>downlink": 500}
        )

        user_info = get_user_traffic("charlie", stats_path=self.stats_file, sync=False)
        # Total should be 10000 + 500 = 10500!
        self.assertEqual(user_info["downlink"], 10500)
        self.assertEqual(user_info["total"], 10500)

        # Further traffic after restart: counter increases to 800
        sync_traffic_stats(
            stats_path=self.stats_file,
            lock_path=self.lock_file,
            raw_stats_provider=lambda: {"user>>>charlie>>>traffic>>>downlink": 800}
        )
        user_info = get_user_traffic("charlie", stats_path=self.stats_file, sync=False)
        # Total should be 10500 + (800 - 500) = 10800!
        self.assertEqual(user_info["downlink"], 10800)

    def test_get_all_traffic_stats_sorting_and_known_users(self):
        mock_raw = {
            "user>>>low_user>>>traffic>>>downlink": 100,
            "user>>>high_user>>>traffic>>>downlink": 50000,
        }
        sync_traffic_stats(
            stats_path=self.stats_file,
            lock_path=self.lock_file,
            raw_stats_provider=lambda: mock_raw
        )

        # high_user, low_user, and zero_user (never transferred traffic)
        res = get_all_traffic_stats(
            known_users=["low_user", "high_user", "zero_user"],
            stats_path=self.stats_file,
            sync=False
        )

        users = res["users"]
        self.assertEqual(len(users), 3)
        self.assertEqual(users[0]["username"], "high_user")
        self.assertEqual(users[1]["username"], "low_user")
        self.assertEqual(users[2]["username"], "zero_user")
        self.assertEqual(users[2]["total"], 0)
        self.assertEqual(users[2]["formatted_total"], "0 B")

        # Server total
        srv = res["server_total"]
        self.assertEqual(srv["total"], 50100)
        self.assertEqual(srv["downlink"], 50100)

    def test_reset_user_traffic(self):
        mock_raw = {
            "user>>>dave>>>traffic>>>downlink": 2048,
            "user>>>dave>>>traffic>>>uplink": 1024,
        }
        sync_traffic_stats(
            stats_path=self.stats_file,
            lock_path=self.lock_file,
            raw_stats_provider=lambda: mock_raw
        )

        res = reset_user_traffic("dave", stats_path=self.stats_file, lock_path=self.lock_file)
        self.assertTrue(res)

        u = get_user_traffic("dave", stats_path=self.stats_file, sync=False)
        self.assertEqual(u["downlink"], 0)
        self.assertEqual(u["uplink"], 0)
        self.assertEqual(u["total"], 0)
        self.assertEqual(u["formatted_total"], "0 B")

    def test_remove_user_traffic(self):
        mock_raw = {
            "user>>>eva>>>traffic>>>downlink": 2048,
        }
        sync_traffic_stats(
            stats_path=self.stats_file,
            lock_path=self.lock_file,
            raw_stats_provider=lambda: mock_raw
        )

        res = remove_user_traffic("eva", stats_path=self.stats_file, lock_path=self.lock_file)
        self.assertTrue(res)

        u = get_user_traffic("eva", stats_path=self.stats_file, sync=False)
        self.assertEqual(u["total"], 0)

        # Check file does not contain eva in users or _raw_last
        with open(self.stats_file, "r") as f:
            data = json.load(f)
        self.assertNotIn("eva", data["users"])
        self.assertFalse(any("eva" in k for k in data["_raw_last"]))


if __name__ == "__main__":
    unittest.main()
