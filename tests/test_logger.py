"""
tests/test_logger.py
====================
Unit tests for AttackLogger (app/logger.py).

Uses temporary files and mocking to test log writing, stats,
sessions, timeline, and heatmap — without touching the real attack.log.

Run with:
    python -m pytest tests/test_logger.py -v
    python -m unittest tests.test_logger -v
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import unittest
import tempfile
import json
import datetime
from unittest.mock import patch, MagicMock


def make_entry(attack_type="Normal", risk_score=1, risk_level="LOW",
               country="United Kingdom", ip="127.0.0.1",
               endpoint="/login", honeypot_type="WEB",
               timestamp=None):
    """Create a minimal valid log entry dict."""
    return {
        "ip":               ip,
        "username":         "testuser",
        "password":         "testpass",
        "payload":          "testuser testpass",
        "user_agent":       "TestAgent/1.0",
        "browser":          "Test",
        "operating_system": "Linux",
        "referrer":         "Direct",
        "origin":           "None",
        "x_forwarded_for":  "None",
        "accept_language":  "en-US",
        "endpoint":         endpoint,
        "attack_type":      attack_type,
        "risk_score":       risk_score,
        "risk_level":       risk_level,
        "honeypot_type":    honeypot_type,
        "country":          country,
        "city":             "London",
        "isp":              "BT",
        "lat":              51.5,
        "lon":              -0.1,
        **({"timestamp": timestamp} if timestamp else {}),
    }


class TestAttackLoggerIO(unittest.TestCase):
    """Tests that AttackLogger writes and reads log entries correctly."""

    def setUp(self):
        # Temporary log file per test
        self._tmp = tempfile.NamedTemporaryFile(
            suffix=".log", delete=False, mode="w"
        )
        self._tmp.close()
        self.tmp_path = self._tmp.name

        # Patch LOG_FILE in logger module; disable ML + blockchain side-effects
        patcher_log  = patch("logger.LOG_FILE",         self.tmp_path)
        patcher_anom = patch("logger.ANOMALY_ENABLED",  False)
        patcher_bc   = patch("logger.BLOCKCHAIN_ENABLED", False)

        self.mock_log  = patcher_log.start()
        self.mock_anom = patcher_anom.start()
        self.mock_bc   = patcher_bc.start()

        self.addCleanup(patcher_log.stop)
        self.addCleanup(patcher_anom.stop)
        self.addCleanup(patcher_bc.stop)

        from logger import AttackLogger
        self.logger = AttackLogger()

    def tearDown(self):
        try:
            os.unlink(self.tmp_path)
        except OSError:
            pass

    # ── log() ──────────────────────────────────────────────

    def test_log_creates_file_entry(self):
        self.logger.log(make_entry())
        with open(self.tmp_path) as f:
            lines = [l.strip() for l in f if l.strip()]
        self.assertEqual(len(lines), 1)

    def test_log_entry_is_valid_json(self):
        self.logger.log(make_entry())
        with open(self.tmp_path) as f:
            line = f.readline().strip()
        parsed = json.loads(line)
        self.assertIsInstance(parsed, dict)

    def test_log_adds_timestamp(self):
        entry = make_entry()
        self.logger.log(entry)
        with open(self.tmp_path) as f:
            parsed = json.loads(f.readline())
        self.assertIn("timestamp", parsed)
        ts = parsed["timestamp"]
        # Should be parseable as ISO datetime
        datetime.datetime.fromisoformat(ts)

    def test_log_preserves_attack_type(self):
        self.logger.log(make_entry(attack_type="SQL Injection"))
        with open(self.tmp_path) as f:
            parsed = json.loads(f.readline())
        self.assertEqual(parsed["attack_type"], "SQL Injection")

    def test_log_multiple_entries(self):
        for _ in range(5):
            self.logger.log(make_entry())
        with open(self.tmp_path) as f:
            lines = [l.strip() for l in f if l.strip()]
        self.assertEqual(len(lines), 5)

    # ── _load_all() ────────────────────────────────────────

    def test_load_all_returns_list(self):
        self.logger.log(make_entry())
        result = self.logger._load_all()
        self.assertIsInstance(result, list)

    def test_load_all_returns_empty_for_new_file(self):
        result = self.logger._load_all()
        self.assertEqual(result, [])

    def test_load_all_count_matches_writes(self):
        for _ in range(7):
            self.logger.log(make_entry())
        result = self.logger._load_all()
        self.assertEqual(len(result), 7)

    def test_load_all_graceful_on_corrupt_line(self):
        """A corrupt JSON line should be skipped, not crash."""
        with open(self.tmp_path, "a") as f:
            f.write("this is not json\n")
            f.write(json.dumps(make_entry()) + "\n")
        result = self.logger._load_all()
        self.assertEqual(len(result), 1)

    # ── get_recent() ───────────────────────────────────────

    def test_get_recent_returns_n_entries(self):
        for _ in range(10):
            self.logger.log(make_entry())
        recent = self.logger.get_recent(5)
        self.assertEqual(len(recent), 5)

    def test_get_recent_returns_most_recent_first(self):
        """get_recent reverses the log — newest entries first."""
        for i in range(5):
            self.logger.log(make_entry(ip=f"10.0.0.{i}"))
        recent = self.logger.get_recent(5)
        # Last written entry (ip=10.0.0.4) should be first returned
        self.assertEqual(recent[0]["ip"], "10.0.0.4")

    def test_get_recent_fewer_than_n(self):
        """If only 3 entries exist and we ask for 10, we get 3."""
        for _ in range(3):
            self.logger.log(make_entry())
        recent = self.logger.get_recent(10)
        self.assertEqual(len(recent), 3)

    # ── get_stats() ────────────────────────────────────────

    def test_get_stats_empty_returns_zero_total(self):
        stats = self.logger.get_stats()
        self.assertEqual(stats["total"], 0)

    def test_get_stats_total_count(self):
        for _ in range(8):
            self.logger.log(make_entry())
        stats = self.logger.get_stats()
        self.assertEqual(stats["total"], 8)

    def test_get_stats_has_required_keys(self):
        stats = self.logger.get_stats()
        for key in ["total", "attack_types", "risk_levels",
                    "top_countries", "top_ips", "recent_count"]:
            self.assertIn(key, stats, f"Missing stats key: {key}")

    def test_get_stats_attack_type_counts(self):
        self.logger.log(make_entry(attack_type="SQL Injection"))
        self.logger.log(make_entry(attack_type="SQL Injection"))
        self.logger.log(make_entry(attack_type="XSS Attack"))
        stats = self.logger.get_stats()
        self.assertEqual(stats["attack_types"].get("SQL Injection"), 2)
        self.assertEqual(stats["attack_types"].get("XSS Attack"), 1)

    def test_get_stats_risk_levels(self):
        self.logger.log(make_entry(risk_level="HIGH"))
        self.logger.log(make_entry(risk_level="HIGH"))
        self.logger.log(make_entry(risk_level="LOW"))
        stats = self.logger.get_stats()
        self.assertEqual(stats["risk_levels"].get("HIGH"), 2)
        self.assertEqual(stats["risk_levels"].get("LOW"), 1)

    def test_get_stats_top_countries(self):
        self.logger.log(make_entry(country="China"))
        self.logger.log(make_entry(country="China"))
        self.logger.log(make_entry(country="Russia"))
        stats = self.logger.get_stats()
        self.assertEqual(stats["top_countries"].get("China"), 2)

    # ── get_timeline() ─────────────────────────────────────

    def test_get_timeline_returns_24_entries(self):
        timeline = self.logger.get_timeline()
        self.assertEqual(len(timeline), 24)

    def test_get_timeline_each_has_hour_and_count(self):
        timeline = self.logger.get_timeline()
        for item in timeline:
            self.assertIn("hour", item)
            self.assertIn("count", item)

    def test_get_timeline_counts_are_non_negative(self):
        self.logger.log(make_entry())
        timeline = self.logger.get_timeline()
        for item in timeline:
            self.assertGreaterEqual(item["count"], 0)

    # ── get_hourly_heatmap() ───────────────────────────────

    def test_get_hourly_heatmap_has_24_keys(self):
        heatmap = self.logger.get_hourly_heatmap()
        self.assertEqual(len(heatmap), 24)

    def test_get_hourly_heatmap_keys_are_hour_strings(self):
        heatmap = self.logger.get_hourly_heatmap()
        for key in heatmap:
            self.assertIn(int(key), range(24))

    def test_get_hourly_heatmap_counts_non_negative(self):
        heatmap = self.logger.get_hourly_heatmap()
        for count in heatmap.values():
            self.assertGreaterEqual(count, 0)

    # ── get_honeypot_stats() ───────────────────────────────

    def test_get_honeypot_stats_returns_dict(self):
        self.logger.log(make_entry(honeypot_type="WEB"))
        self.logger.log(make_entry(honeypot_type="SSH"))
        stats = self.logger.get_honeypot_stats()
        self.assertIsInstance(stats, dict)

    def test_get_honeypot_stats_correct_counts(self):
        for _ in range(3):
            self.logger.log(make_entry(honeypot_type="WEB"))
        for _ in range(2):
            self.logger.log(make_entry(honeypot_type="SSH"))
        stats = self.logger.get_honeypot_stats()
        self.assertEqual(stats.get("WEB"), 3)
        self.assertEqual(stats.get("SSH"), 2)

    # ── get_sessions() ────────────────────────────────────

    def test_get_sessions_groups_by_ip(self):
        self.logger.log(make_entry(ip="10.0.0.1"))
        self.logger.log(make_entry(ip="10.0.0.1"))
        self.logger.log(make_entry(ip="10.0.0.2"))
        sessions = self.logger.get_sessions()
        ips = [s["ip"] for s in sessions]
        self.assertIn("10.0.0.1", ips)
        self.assertIn("10.0.0.2", ips)
        # Only 2 unique IPs
        self.assertEqual(len(sessions), 2)

    def test_get_sessions_event_count(self):
        for _ in range(4):
            self.logger.log(make_entry(ip="10.0.0.1"))
        sessions = self.logger.get_sessions()
        session = next(s for s in sessions if s["ip"] == "10.0.0.1")
        self.assertEqual(session["total_events"], 4)

    def test_get_sessions_overall_risk_high_when_any_high(self):
        self.logger.log(make_entry(ip="10.0.0.1", risk_level="LOW"))
        self.logger.log(make_entry(ip="10.0.0.1", risk_level="HIGH"))
        sessions = self.logger.get_sessions()
        session = sessions[0]
        self.assertEqual(session["overall_risk"], "HIGH")

    def test_get_sessions_has_required_fields(self):
        self.logger.log(make_entry(ip="10.0.0.5"))
        sessions = self.logger.get_sessions()
        session = sessions[0]
        for field in ["ip", "country", "city", "first_seen",
                      "last_seen", "total_events", "overall_risk", "top_attack"]:
            self.assertIn(field, session, f"Session missing field: {field}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
