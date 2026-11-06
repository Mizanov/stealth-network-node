#!/usr/bin/env python3
"""
Unit tests for Sing-Box Routing and DNS Rules Logic (Stage 5).
Verifies:
1. No accidental logical AND combining mixed condition fields in a single rule.
2. Proper sequential rule ordering (Specific Proxy before Broad Direct before Fallback).
3. Test domains route to expected outbounds:
   - Server: Russian domains, keywords (habr, rutracker), and AI rule_sets (OpenAI, Anthropic, xAI) -> warp
   - Client: Blocked exceptions (tvrain, theins) -> proxy
   - Client: Keywords (habr, animego) -> proxy
   - Client: Telegram / Google -> proxy
   - Client: Russian services (yandex, vk, gosuslugi, wildberries) -> direct
   - Client: Server IP -> direct
   - Client: Foreign non-blocked traffic -> fallback proxy
   - Client: Ads -> reject
"""

import os
import json
import unittest
import ipaddress


def match_route_rule(rule: dict, domain: str, ip: str = None, matched_rulesets: set = None) -> bool:
    """
    Simulates Sing-box rule matching. All conditions within a single rule object
    are combined via logical AND.
    """
    if matched_rulesets is None:
        matched_rulesets = set()

    # If action is sniff or hijack-dns or resolve, ignore for outbound decision
    if "action" in rule and rule["action"] in ("sniff", "hijack-dns", "resolve"):
        return False

    conditions = []

    if "domain_suffix" in rule:
        matched = any(domain.endswith(sfx) for sfx in rule["domain_suffix"])
        conditions.append(matched)

    if "domain_keyword" in rule:
        matched = any(kw.lower() in domain.lower() for kw in rule["domain_keyword"])
        conditions.append(matched)

    if "rule_set" in rule:
        matched = any(rs in matched_rulesets for rs in rule["rule_set"])
        conditions.append(matched)

    if "ip_cidr" in rule and ip:
        matched = False
        target_ip = ipaddress.ip_address(ip)
        for cidr in rule["ip_cidr"]:
            if cidr.startswith("{{"):
                # Template placeholder
                if ip == "187.55.163.81" or ip == "127.0.0.1":
                    matched = True
                    break
            else:
                net = ipaddress.ip_network(cidr, strict=False)
                if target_ip in net:
                    matched = True
                    break
        conditions.append(matched)

    if "inbound" in rule:
        # Default inbound match
        conditions.append(True)

    if not conditions:
        return False

    # In Sing-box, ALL conditions in the same rule must be true (AND logic)
    return all(conditions)


def evaluate_route(rules: list, domain: str, ip: str = None, matched_rulesets: set = None) -> str:
    """Evaluates sequential rules and returns outbound or action of first matching rule."""
    for rule in rules:
        if match_route_rule(rule, domain, ip, matched_rulesets):
            if "action" in rule:
                return rule["action"]
            if "outbound" in rule:
                return rule["outbound"]
    return "direct"  # Default fallthrough


class TestServerRoutingLogic(unittest.TestCase):
    """Verifies route rules in config/sing-box/config.json.template."""

    def setUp(self):
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        cfg_path = os.path.join(repo_root, "config", "sing-box", "config.json.template")
        with open(cfg_path, "r", encoding="utf-8") as f:
            self.cfg = json.load(f)
        self.rules = self.cfg["route"]["rules"]

    def test_no_mixed_conditions_in_server_rules(self):
        """No server rule may mix domain_suffix, domain_keyword, or rule_set in the same rule."""
        condition_keys = {"domain_suffix", "domain_keyword", "rule_set", "ip_cidr"}
        for i, r in enumerate(self.rules):
            mixed = condition_keys.intersection(r.keys())
            self.assertLessEqual(
                len(mixed), 1,
                f"Server rule index {i} mixes multiple condition fields {mixed}! Must use separate rules."
            )

    def test_russian_domains_route_to_warp(self):
        """Russian domains route to warp."""
        self.assertEqual(evaluate_route(self.rules, "yandex.ru"), "warp")
        self.assertEqual(evaluate_route(self.rules, "gosuslugi.ru"), "warp")
        self.assertEqual(evaluate_route(self.rules, "kremlin.ru"), "warp")
        self.assertEqual(evaluate_route(self.rules, "sber.ru"), "warp")

    def test_keywords_route_to_warp(self):
        """Domain keywords like habr, rutracker route to warp independently."""
        self.assertEqual(evaluate_route(self.rules, "habr.com"), "warp")
        self.assertEqual(evaluate_route(self.rules, "rutracker.org"), "warp")

    def test_ai_services_route_to_warp(self):
        """OpenAI, Anthropic, xAI route to warp independently."""
        self.assertEqual(evaluate_route(self.rules, "api.openai.com", matched_rulesets={"openai"}), "warp")
        self.assertEqual(evaluate_route(self.rules, "claude.ai", matched_rulesets={"anthropic"}), "warp")
        self.assertEqual(evaluate_route(self.rules, "grok.com", matched_rulesets={"xai"}), "warp")

    def test_russian_ip_routes_to_warp(self):
        """Russian IPs route to warp via geoip-ru ruleset."""
        self.assertEqual(evaluate_route(self.rules, "random-host.net", ip="95.173.136.1", matched_rulesets={"geoip-ru"}), "warp")

    def test_ads_are_dropped(self):
        """Ads matching category-ads-all are dropped."""
        self.assertEqual(evaluate_route(self.rules, "ad.example.com", matched_rulesets={"category-ads-all"}), "reject")


class TestClientRoutingLogic(unittest.TestCase):
    """Verifies route and dns rules in client templates (template-vless.json / template-trj.json)."""

    def setUp(self):
        self.repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.templates = [
            os.path.join(self.repo_root, "config", "templates", "template-vless.json"),
            os.path.join(self.repo_root, "config", "templates", "template-trj.json")
        ]

    def test_no_mixed_conditions_in_client_templates(self):
        """Client templates must NOT mix condition fields in a single rule."""
        condition_keys = {"domain_suffix", "domain_keyword", "rule_set", "ip_cidr"}
        for path in self.templates:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            for i, r in enumerate(data["route"]["rules"]):
                mixed = condition_keys.intersection(r.keys())
                self.assertLessEqual(
                    len(mixed), 1,
                    f"Template {os.path.basename(path)} route rule {i} mixes {mixed}!"
                )

            for i, r in enumerate(data.get("dns", {}).get("rules", [])):
                mixed = condition_keys.intersection(r.keys())
                self.assertLessEqual(
                    len(mixed), 1,
                    f"Template {os.path.basename(path)} dns rule {i} mixes {mixed}!"
                )

    def test_client_rule_evaluation_precedence(self):
        """Tests that client rules correctly route traffic to expected outbounds."""
        for path in self.templates:
            with open(path, "r", encoding="utf-8") as f:
                rules = json.load(f)["route"]["rules"]

            # 1. Blocked exceptions must route to proxy
            self.assertEqual(evaluate_route(rules, "tvrain.ru"), "proxy")
            self.assertEqual(evaluate_route(rules, "theins.ru"), "proxy")
            self.assertEqual(evaluate_route(rules, "echo.msk.ru"), "proxy")

            # 2. Keywords must route to proxy
            self.assertEqual(evaluate_route(rules, "habr.com"), "proxy")
            self.assertEqual(evaluate_route(rules, "animego.org"), "proxy")

            # 3. Telegram and Google must route to proxy
            self.assertEqual(evaluate_route(rules, "t.me", matched_rulesets={"telegram"}), "proxy")
            self.assertEqual(evaluate_route(rules, "google.com", matched_rulesets={"google"}), "proxy")

            # 4. Russian domestic services must route to direct
            self.assertEqual(evaluate_route(rules, "yandex.ru"), "direct")
            self.assertEqual(evaluate_route(rules, "vk.com", matched_rulesets={"vk"}), "direct")
            self.assertEqual(evaluate_route(rules, "ozon.ru", matched_rulesets={"ozon"}), "direct")
            self.assertEqual(evaluate_route(rules, "wildberries.ru"), "direct")

            # 5. Torrent clients must route to direct
            self.assertEqual(evaluate_route(rules, "tracker.torrent.org", matched_rulesets={"torrent-clients"}), "direct")

            # 6. Server IP bypass
            self.assertEqual(evaluate_route(rules, "server-direct", ip="187.55.163.81"), "direct")

            # 7. Unmatched foreign sites from TUN fall through to proxy
            self.assertEqual(evaluate_route(rules, "instagram.com"), "proxy")
            self.assertEqual(evaluate_route(rules, "bbc.co.uk"), "proxy")


if __name__ == "__main__":
    unittest.main()
