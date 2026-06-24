"""leakguard engine tests (stdlib unittest; run: python -m unittest)."""
import json
import os
import tempfile
import unittest

from leakguard.engine import load_rules, scan_text, severity_at_least


class TestBuiltin(unittest.TestCase):
    def setUp(self):
        self.rules, self.allow = load_rules()

    def test_detects_common_secrets_and_private_ips(self):
        bad = (
            "key AKIA1234567890ABCDEF\n"
            "gcp AIza" + "a" * 35 + "\n"
            "lan 10.1.2.3 and 192.168.0.5 and 172.16.9.9\n"
            "tailnet 100.64.0.1\n"
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "host node.tailabc.ts.net\n"
        )
        ids = {f.rule_id for f in scan_text(bad, self.rules, self.allow)}
        for expect in ("aws-access-key-id", "gcp-api-key", "private-ip",
                       "cgnat-ip", "private-key-block", "tailscale-magicdns"):
            self.assertIn(expect, ids)

    def test_rfc5737_examples_do_not_trip(self):
        clean = "docs use 203.0.113.5 and 192.0.2.1 and 198.51.100.7 and v1.10.0.0"
        ids = {f.rule_id for f in scan_text(clean, self.rules, self.allow)}
        self.assertNotIn("private-ip", ids)
        self.assertNotIn("cgnat-ip", ids)

    def test_example_emails_not_flagged(self):
        ids = {f.rule_id for f in scan_text("a@example.com b@example.org",
                                            self.rules, self.allow)}
        self.assertNotIn("email-address", ids)


class TestPrivateRules(unittest.TestCase):
    def test_private_rules_and_allow_list(self):
        cfg = {
            "rules": [{"id": "host", "pattern": r"\bacme-\w+\b", "severity": "high",
                       "message": "internal host", "suggestion": "codename"}],
            "allow": ["acme-public"],
        }
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "r.json")
            with open(p, "w") as fh:
                json.dump(cfg, fh)
            rules, allow = load_rules(extra_paths=[p], use_builtin=False)
            matches = [f.match for f in scan_text("acme-secret and acme-public",
                                                  rules, allow)]
        self.assertIn("acme-secret", matches)
        self.assertNotIn("acme-public", matches)

    def test_autoload_local_file(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, ".leakguard.local.json"), "w") as fh:
                json.dump({"rules": [{"id": "x", "pattern": r"SEKRET",
                                      "severity": "high"}]}, fh)
            rules, allow = load_rules(use_builtin=False, scan_root=d)
            self.assertTrue(any(f.rule_id == "x"
                                for f in scan_text("a SEKRET b", rules, allow)))


class TestSeverity(unittest.TestCase):
    def test_threshold(self):
        self.assertTrue(severity_at_least("high", "medium"))
        self.assertTrue(severity_at_least("medium", "medium"))
        self.assertFalse(severity_at_least("low", "medium"))


if __name__ == "__main__":
    unittest.main()
