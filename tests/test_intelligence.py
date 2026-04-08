"""
tests/test_intelligence.py
===========================
Unit tests for the IntelligenceEngine (app/intelligence.py).

Tests every attack pattern, risk score, brute-force threshold,
reconnaissance threshold, and edge cases.

Run with:
    python -m pytest tests/test_intelligence.py -v
    python -m unittest tests.test_intelligence -v
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import unittest
from intelligence import IntelligenceEngine, RISK_SCORES


class TestAttackTypeDetection(unittest.TestCase):
    """Tests that IntelligenceEngine correctly classifies attack payloads."""

    def setUp(self):
        self.engine = IntelligenceEngine()

    # ── SQL Injection ───────────────────────────────────────

    def test_sql_or_1_equals_1(self):
        result = self.engine.analyze("' OR 1=1 --", "1.2.3.4", "/login")
        self.assertEqual(result["attack_type"], "SQL Injection")

    def test_sql_union_select(self):
        result = self.engine.analyze("' UNION SELECT * FROM users --", "1.2.3.4", "/login")
        self.assertEqual(result["attack_type"], "SQL Injection")

    def test_sql_comment_evasion(self):
        result = self.engine.analyze("admin'--", "1.2.3.4", "/login")
        self.assertEqual(result["attack_type"], "SQL Injection")

    def test_sql_tautology(self):
        result = self.engine.analyze("' OR 'x'='x", "1.2.3.4", "/login")
        self.assertEqual(result["attack_type"], "SQL Injection")

    def test_sql_information_schema(self):
        result = self.engine.analyze(
            "' UNION SELECT table_name FROM information_schema.tables--",
            "1.2.3.4", "/login"
        )
        self.assertEqual(result["attack_type"], "SQL Injection")

    def test_sql_sleep_blind(self):
        result = self.engine.analyze("' AND sleep(5)--", "1.2.3.4", "/login")
        self.assertEqual(result["attack_type"], "SQL Injection")

    def test_sql_or_1_equals_1_lowercase(self):
        """SQL injection detection must be case-insensitive."""
        result = self.engine.analyze("' or 1=1 #", "1.2.3.4", "/login")
        self.assertEqual(result["attack_type"], "SQL Injection")

    # ── XSS Attack ──────────────────────────────────────────

    def test_xss_script_tag(self):
        result = self.engine.analyze("<script>alert('XSS')</script>", "1.2.3.4", "/login")
        self.assertEqual(result["attack_type"], "XSS Attack")

    def test_xss_img_onerror(self):
        result = self.engine.analyze("<img src=x onerror=alert(1)>", "1.2.3.4", "/login")
        self.assertEqual(result["attack_type"], "XSS Attack")

    def test_xss_javascript_protocol(self):
        result = self.engine.analyze("javascript:alert(document.cookie)", "1.2.3.4", "/login")
        self.assertEqual(result["attack_type"], "XSS Attack")

    def test_xss_svg_event(self):
        result = self.engine.analyze("<svg onload=alert(1)>", "1.2.3.4", "/login")
        self.assertEqual(result["attack_type"], "XSS Attack")

    def test_xss_dom_document_cookie(self):
        result = self.engine.analyze("document.cookie", "1.2.3.4", "/login")
        self.assertEqual(result["attack_type"], "XSS Attack")

    # ── Command Injection ───────────────────────────────────

    def test_cmd_semicolon_whoami(self):
        result = self.engine.analyze(
            "admin; whoami && cat /etc/passwd", "1.2.3.4", "/login"
        )
        self.assertEqual(result["attack_type"], "Command Injection")

    def test_cmd_pipe_cat(self):
        result = self.engine.analyze("admin | cat /etc/shadow", "1.2.3.4", "/login")
        self.assertEqual(result["attack_type"], "Command Injection")

    def test_cmd_backtick(self):
        result = self.engine.analyze("admin`id`", "1.2.3.4", "/login")
        self.assertEqual(result["attack_type"], "Command Injection")

    def test_cmd_netcat_reverse_shell(self):
        # || pipes into bash shell execution — matches pipe pattern
        result = self.engine.analyze(
            "x || cat /etc/shadow", "1.2.3.4", "/login"
        )
        self.assertEqual(result["attack_type"], "Command Injection")

    def test_cmd_and_ls(self):
        result = self.engine.analyze("x && ls /", "1.2.3.4", "/login")
        self.assertEqual(result["attack_type"], "Command Injection")

    # ── Path Traversal ──────────────────────────────────────

    def test_path_traversal_dots(self):
        result = self.engine.analyze("../../../../etc/passwd", "1.2.3.4", "/login")
        self.assertEqual(result["attack_type"], "Path Traversal")

    def test_path_traversal_url_encoded(self):
        # Engine lowercases then matches %2e%2e%2f pattern
        result = self.engine.analyze("..%2e%2e%2fetc/passwd", "1.2.3.4", "/login")
        self.assertEqual(result["attack_type"], "Path Traversal")

    def test_path_traversal_null_byte(self):
        # Null-byte evasion (%00) is a recognised path traversal pattern
        result = self.engine.analyze("/etc/passwd%00", "1.2.3.4", "/login")
        self.assertEqual(result["attack_type"], "Path Traversal")

    # ── Brute Force ─────────────────────────────────────────

    def test_brute_force_threshold_5(self):
        """Should trigger brute force at exactly 5 login attempts."""
        result = self.engine.analyze("admin password", "1.2.3.4", "/login", login_count=5)
        self.assertEqual(result["attack_type"], "Brute Force")

    def test_brute_force_threshold_10(self):
        result = self.engine.analyze("admin password", "1.2.3.4", "/login", login_count=10)
        self.assertEqual(result["attack_type"], "Brute Force")

    def test_no_brute_force_below_threshold(self):
        """4 attempts should NOT trigger brute force (threshold is 5)."""
        result = self.engine.analyze("admin password", "1.2.3.4", "/login", login_count=4)
        self.assertNotEqual(result["attack_type"], "Brute Force")

    # ── Reconnaissance ──────────────────────────────────────

    def test_recon_threshold_3(self):
        """Should trigger reconnaissance at exactly 3 probed endpoints."""
        result = self.engine.analyze("admin admin", "1.2.3.4", "/admin", recon_count=3)
        self.assertEqual(result["attack_type"], "Reconnaissance")

    def test_no_recon_below_threshold(self):
        """2 endpoints should NOT trigger reconnaissance."""
        result = self.engine.analyze("admin admin", "1.2.3.4", "/admin", recon_count=2)
        self.assertNotEqual(result["attack_type"], "Reconnaissance")

    # ── Normal Traffic ──────────────────────────────────────

    def test_normal_benign_login(self):
        result = self.engine.analyze("john password123", "1.2.3.4", "/login")
        self.assertEqual(result["attack_type"], "Normal")

    def test_normal_empty_payload(self):
        result = self.engine.analyze("", "1.2.3.4", "/login")
        self.assertEqual(result["attack_type"], "Normal")

    def test_normal_plain_username(self):
        result = self.engine.analyze("alice sunshine2026", "1.2.3.4", "/login")
        self.assertEqual(result["attack_type"], "Normal")


class TestRiskScoring(unittest.TestCase):
    """Tests that risk scores and levels are assigned correctly."""

    def setUp(self):
        self.engine = IntelligenceEngine()

    def test_command_injection_risk_score_10(self):
        result = self.engine.analyze("admin; whoami", "1.2.3.4", "/login")
        self.assertEqual(result["risk_score"], 10)
        self.assertEqual(result["risk_level"], "HIGH")

    def test_sql_injection_risk_score_9(self):
        result = self.engine.analyze("' OR 1=1 --", "1.2.3.4", "/login")
        self.assertEqual(result["risk_score"], 9)
        self.assertEqual(result["risk_level"], "HIGH")

    def test_path_traversal_risk_score_8(self):
        result = self.engine.analyze("../../../../etc/passwd", "1.2.3.4", "/login")
        self.assertEqual(result["risk_score"], 8)
        self.assertEqual(result["risk_level"], "HIGH")

    def test_xss_risk_score_7(self):
        result = self.engine.analyze("<script>alert(1)</script>", "1.2.3.4", "/login")
        self.assertEqual(result["risk_score"], 7)
        self.assertEqual(result["risk_level"], "HIGH")

    def test_brute_force_risk_score_6(self):
        result = self.engine.analyze("admin pass", "1.2.3.4", "/login", login_count=5)
        self.assertEqual(result["risk_score"], 6)
        self.assertEqual(result["risk_level"], "MEDIUM")

    def test_recon_risk_score_4(self):
        result = self.engine.analyze("admin pass", "1.2.3.4", "/admin", recon_count=5)
        self.assertEqual(result["risk_score"], 4)
        self.assertEqual(result["risk_level"], "MEDIUM")

    def test_normal_risk_score_1(self):
        result = self.engine.analyze("alice pass123", "1.2.3.4", "/login")
        self.assertEqual(result["risk_score"], 1)
        self.assertEqual(result["risk_level"], "LOW")

    def test_risk_levels_in_risk_scores_dict(self):
        """All expected attack types must have a risk score defined."""
        expected = ["SQL Injection", "XSS Attack", "Command Injection",
                    "Path Traversal", "Brute Force", "Reconnaissance", "Normal"]
        for attack in expected:
            self.assertIn(attack, RISK_SCORES, f"Missing risk score for: {attack}")


class TestAnalyzeReturnShape(unittest.TestCase):
    """Tests the shape and keys of the analyze() return value."""

    def setUp(self):
        self.engine = IntelligenceEngine()

    def test_returns_dict(self):
        result = self.engine.analyze("test", "1.2.3.4", "/login")
        self.assertIsInstance(result, dict)

    def test_has_required_keys(self):
        result = self.engine.analyze("test", "1.2.3.4", "/login")
        for key in ["attack_type", "risk_score", "risk_level", "matched_pattern"]:
            self.assertIn(key, result, f"Missing key: {key}")

    def test_risk_level_valid_value(self):
        result = self.engine.analyze("test", "1.2.3.4", "/login")
        self.assertIn(result["risk_level"], ["LOW", "MEDIUM", "HIGH"])

    def test_priority_command_over_sql(self):
        """Command injection takes priority over SQL injection."""
        payload = "'; whoami && cat /etc/passwd"
        result  = self.engine.analyze(payload, "1.2.3.4", "/login")
        self.assertEqual(result["attack_type"], "Command Injection")

    def test_priority_sql_over_xss(self):
        """SQL injection takes priority over XSS."""
        payload = "' OR 1=1 -- <script>alert(1)</script>"
        result  = self.engine.analyze(payload, "1.2.3.4", "/login")
        self.assertEqual(result["attack_type"], "SQL Injection")


if __name__ == "__main__":
    unittest.main(verbosity=2)
