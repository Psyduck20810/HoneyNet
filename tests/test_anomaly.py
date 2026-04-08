"""
tests/test_anomaly.py
=====================
Unit tests for the ML anomaly detection engine (app/anomaly_detector.py).

Tests feature extraction (all 15 features), helper functions,
detect_anomaly() correctness, DBSCAN clustering, and model metadata.

Run with:
    python -m pytest tests/test_anomaly.py -v
    python -m unittest tests.test_anomaly -v
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import unittest
from anomaly_detector import (
    extract_features,
    detect_anomaly,
    cluster_attacks,
    get_model_info,
    shannon_entropy,
    count_special_chars,
    has_url_encoding,
    is_multi_vector,
    FEATURE_NAMES,
    DANGEROUS_ATTACKS,
)

# ── Sample log entries for reuse ───────────────────────────
NORMAL_ENTRY = {
    "timestamp":    "2026-03-10T14:30:00",
    "ip":           "192.168.1.1",
    "username":     "alice",
    "password":     "pass123",
    "payload":      "alice pass123",
    "attack_type":  "Normal",
    "risk_score":   1,
    "risk_level":   "LOW",
    "country":      "United Kingdom",
    "endpoint":     "/login",
    "honeypot_type":"WEB",
}

SQL_ENTRY = {
    "timestamp":    "2026-03-10T14:31:00",
    "ip":           "103.21.58.12",
    "username":     "' OR 1=1 --",
    "password":     "anything",
    "payload":      "' OR 1=1 -- anything",
    "attack_type":  "SQL Injection",
    "risk_score":   9,
    "risk_level":   "HIGH",
    "country":      "China",
    "endpoint":     "/login",
    "honeypot_type":"WEB",
}

NIGHT_ENTRY = {
    "timestamp":    "2026-03-10T03:15:00",
    "ip":           "185.220.101.5",
    "username":     "root",
    "password":     "toor",
    "payload":      "' OR 1=1 -- toor",
    "attack_type":  "SQL Injection",
    "risk_score":   9,
    "risk_level":   "HIGH",
    "country":      "Germany",
    "endpoint":     "/login",
    "honeypot_type":"WEB",
}

SSH_ENTRY = {
    "timestamp":    "2026-03-10T02:00:00",
    "ip":           "95.142.46.35",
    "username":     "root",
    "password":     "toor",
    "payload":      "SSH login attempt: root:toor",
    "attack_type":  "SSH Brute Force",
    "risk_score":   8,
    "risk_level":   "HIGH",
    "country":      "Russia",
    "endpoint":     "/ssh",
    "honeypot_type":"SSH",
}


class TestShannonEntropy(unittest.TestCase):
    """Tests for the Shannon entropy helper function."""

    def test_empty_string_returns_zero(self):
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_single_char_returns_zero(self):
        """Single character has zero entropy."""
        self.assertEqual(shannon_entropy("aaaa"), 0.0)

    def test_normal_text_entropy_range(self):
        """Normal text should have entropy roughly 3–5."""
        h = shannon_entropy("hello world this is a normal sentence")
        self.assertGreater(h, 2.5)
        self.assertLess(h, 5.5)

    def test_high_entropy_encoded_payload(self):
        """Base64-like strings should have higher entropy."""
        b64 = "SGVsbG8gV29ybGQhIFRoaXMgaXMgYmFzZTY0IGVuY29kZWQ="
        h = shannon_entropy(b64)
        self.assertGreater(h, 4.0)

    def test_sql_injection_entropy(self):
        """SQL injection payloads should have moderate-to-high entropy."""
        h = shannon_entropy("' UNION SELECT username, password FROM users WHERE '1'='1")
        self.assertGreater(h, 3.5)

    def test_returns_float(self):
        h = shannon_entropy("test string")
        self.assertIsInstance(h, float)


class TestSpecialCharCount(unittest.TestCase):
    """Tests for special character counting."""

    def test_empty_string_returns_zero(self):
        self.assertEqual(count_special_chars(""), 0)

    def test_normal_username_low_count(self):
        self.assertEqual(count_special_chars("alice123"), 0)

    def test_sql_injection_high_count(self):
        count = count_special_chars("' OR 1=1 -- ; SELECT * FROM users")
        self.assertGreaterEqual(count, 3)  # must have at least: ', --, ;

    def test_xss_payload_high_count(self):
        count = count_special_chars("<script>alert('XSS')</script>")
        self.assertGreaterEqual(count, 4)  # at least: <, >, (, ), '

    def test_returns_int(self):
        self.assertIsInstance(count_special_chars("test!"), int)


class TestUrlEncoding(unittest.TestCase):
    """Tests for URL-encoding detection."""

    def test_plain_text_not_encoded(self):
        self.assertEqual(has_url_encoding("admin password"), 0)

    def test_url_encoded_dots(self):
        self.assertEqual(has_url_encoding("..%2F..%2Fetc%2Fpasswd"), 1)

    def test_null_byte_encoded(self):
        self.assertEqual(has_url_encoding("/etc/passwd%00"), 1)

    def test_url_encoded_path(self):
        self.assertEqual(has_url_encoding("..%2F..%2Fshadow"), 1)

    def test_returns_int_0_or_1(self):
        result = has_url_encoding("test string")
        self.assertIn(result, [0, 1])


class TestMultiVector(unittest.TestCase):
    """Tests for multi-vector attack detection."""

    def test_normal_payload_not_multi_vector(self):
        self.assertEqual(is_multi_vector("Normal", "alice password"), 0)

    def test_sql_plus_xss_is_multi_vector(self):
        payload = "' OR 1=1 -- <script>alert(1)</script>"
        self.assertEqual(is_multi_vector("SQL Injection", payload), 1)

    def test_single_attack_not_multi_vector(self):
        self.assertEqual(is_multi_vector("SQL Injection", "' OR 1=1 --"), 0)


class TestExtractFeatures(unittest.TestCase):
    """Tests for the 15-feature extraction pipeline."""

    def test_returns_list_of_15_features(self):
        features = extract_features(NORMAL_ENTRY)
        self.assertIsInstance(features, list)
        self.assertEqual(len(features), 15,
            f"Expected 15 features, got {len(features)}: {features}")

    def test_all_features_numeric(self):
        """Every feature value must be a number (int or float)."""
        features = extract_features(SQL_ENTRY)
        for i, f in enumerate(features):
            self.assertIsInstance(f, (int, float),
                f"Feature {i} ('{FEATURE_NAMES[i]}') is not numeric: {f!r}")

    def test_hour_correct_for_afternoon(self):
        features = extract_features(NORMAL_ENTRY)  # 14:30
        self.assertEqual(features[0], 14)

    def test_hour_correct_for_night(self):
        features = extract_features(NIGHT_ENTRY)   # 03:15
        self.assertEqual(features[0], 3)

    def test_odd_hour_flag_set_at_night(self):
        features = extract_features(NIGHT_ENTRY)   # 03:15 → odd_hour = 1
        self.assertEqual(features[6], 1)

    def test_odd_hour_flag_not_set_in_afternoon(self):
        features = extract_features(NORMAL_ENTRY)  # 14:30 → odd_hour = 0
        self.assertEqual(features[6], 0)

    def test_risk_score_carried_through(self):
        features = extract_features(SQL_ENTRY)     # risk_score = 9
        self.assertEqual(features[1], 9.0)

    def test_payload_length_positive(self):
        features = extract_features(SQL_ENTRY)
        self.assertGreater(features[5], 0)

    def test_payload_entropy_positive(self):
        """Entropy of a non-trivial payload should be > 0."""
        features = extract_features(SQL_ENTRY)
        self.assertGreater(features[7], 0.0)

    def test_ssh_honeypot_code_different_from_web(self):
        """SSH honeypot should produce a different encoded value than WEB."""
        web_features = extract_features(NORMAL_ENTRY)
        ssh_features = extract_features(SSH_ENTRY)
        self.assertNotEqual(web_features[9], ssh_features[9])

    def test_high_risk_country_china(self):
        features = extract_features(SQL_ENTRY)  # country = China
        self.assertEqual(features[14], 1)

    def test_not_high_risk_country_uk(self):
        features = extract_features(NORMAL_ENTRY)  # country = United Kingdom
        self.assertEqual(features[14], 0)

    def test_safe_fallback_on_empty_entry(self):
        """Empty entry should return 15 numeric values without raising."""
        features = extract_features({})
        self.assertEqual(len(features), 15)
        for f in features:
            self.assertIsInstance(f, (int, float))

    def test_safe_fallback_on_bad_timestamp(self):
        bad_entry = {**NORMAL_ENTRY, "timestamp": "not-a-date"}
        features = extract_features(bad_entry)
        self.assertEqual(len(features), 15)  # must not raise
        self.assertEqual(features[0], 12)    # falls back to noon


class TestDetectAnomaly(unittest.TestCase):
    """Tests for the main detect_anomaly() function."""

    def test_returns_dict(self):
        result = detect_anomaly(NORMAL_ENTRY)
        self.assertIsInstance(result, dict)

    def test_has_all_required_keys(self):
        result = detect_anomaly(SQL_ENTRY)
        for key in ["is_anomaly", "anomaly_score", "label", "reasons",
                    "confidence", "features"]:
            self.assertIn(key, result, f"Missing key: {key}")

    def test_is_anomaly_is_bool(self):
        result = detect_anomaly(SQL_ENTRY)
        self.assertIsInstance(result["is_anomaly"], bool)

    def test_anomaly_score_in_range(self):
        result = detect_anomaly(SQL_ENTRY)
        score = result["anomaly_score"]
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 100.0)

    def test_label_matches_is_anomaly(self):
        result = detect_anomaly(SQL_ENTRY)
        expected_label = "ANOMALY" if result["is_anomaly"] else "NORMAL"
        self.assertEqual(result["label"], expected_label)

    def test_reasons_is_nonempty_list(self):
        result = detect_anomaly(SQL_ENTRY)
        self.assertIsInstance(result["reasons"], list)
        self.assertGreater(len(result["reasons"]), 0)

    def test_sql_injection_flagged_as_anomaly(self):
        """SQL Injection is in DANGEROUS_ATTACKS — always flagged."""
        result = detect_anomaly(SQL_ENTRY)
        self.assertTrue(result["is_anomaly"])
        self.assertGreaterEqual(result["anomaly_score"], 60.0)

    def test_xss_attack_flagged_as_anomaly(self):
        xss_entry = {**NORMAL_ENTRY, "attack_type": "XSS Attack",
                     "risk_score": 7, "risk_level": "HIGH",
                     "payload": "<script>alert(1)</script>"}
        result = detect_anomaly(xss_entry)
        self.assertTrue(result["is_anomaly"])

    def test_ssh_brute_force_flagged_as_anomaly(self):
        result = detect_anomaly(SSH_ENTRY)
        self.assertTrue(result["is_anomaly"])

    def test_critical_risk_score_boosts_to_85(self):
        """Risk score >= 9 should push anomaly_score to at least 85."""
        result = detect_anomaly(SQL_ENTRY)  # risk_score = 9
        self.assertGreaterEqual(result["anomaly_score"], 85.0)

    def test_features_dict_has_expected_keys(self):
        result = detect_anomaly(SQL_ENTRY)
        features = result.get("features", {})
        for key in ["Risk Score", "Payload Length", "Payload Entropy"]:
            self.assertIn(key, features, f"Feature '{key}' missing from feature dict")

    def test_all_dangerous_attacks_flagged(self):
        """Every attack type in DANGEROUS_ATTACKS must be flagged as anomaly."""
        for attack in DANGEROUS_ATTACKS:
            entry = {**NORMAL_ENTRY, "attack_type": attack,
                     "risk_score": 8, "risk_level": "HIGH"}
            result = detect_anomaly(entry)
            self.assertTrue(result["is_anomaly"],
                f"DANGEROUS_ATTACKS member '{attack}' was NOT flagged as anomaly")

    def test_high_entropy_flagged(self):
        """A real base64-encoded payload should trigger entropy reason."""
        high_entropy_entry = {
            **NORMAL_ENTRY,
            "payload": "SGVsbG8gV29ybGQhIFRoaXMgaXMgYmFzZTY0IGVuY29kZWQ=" * 3,
            "attack_type": "Normal",
            "risk_score": 1,
        }
        result = detect_anomaly(high_entropy_entry)
        all_reasons = " ".join(result["reasons"]).lower()
        self.assertIn("entropy", all_reasons)


class TestClusterAttacks(unittest.TestCase):
    """Tests for DBSCAN clustering."""

    def test_empty_list_returns_no_clusters(self):
        result = cluster_attacks([])
        self.assertEqual(result["cluster_count"], 0)
        self.assertEqual(result["clusters"], [])

    def test_too_few_entries_returns_insufficient_status(self):
        result = cluster_attacks([SQL_ENTRY, NORMAL_ENTRY])
        self.assertEqual(result["status"], "insufficient_data")

    def test_sufficient_entries_returns_ok(self):
        """10+ similar entries should result in at least one cluster."""
        entries = [SQL_ENTRY] * 10 + [SSH_ENTRY] * 5 + [NORMAL_ENTRY] * 5
        result = cluster_attacks(entries)
        self.assertEqual(result["status"], "ok")

    def test_result_has_required_keys(self):
        entries = [SQL_ENTRY] * 10
        result = cluster_attacks(entries)
        for key in ["cluster_count", "clusters", "noise_count",
                    "algorithm", "status"]:
            self.assertIn(key, result, f"Missing key: {key}")

    def test_clusters_contain_required_fields(self):
        entries = [SQL_ENTRY] * 10 + [NORMAL_ENTRY] * 5
        result = cluster_attacks(entries)
        if result["cluster_count"] > 0:
            cluster = result["clusters"][0]
            for field in ["cluster_id", "size", "dominant_attack",
                          "avg_risk_score", "severity", "ips"]:
                self.assertIn(field, cluster, f"Cluster missing field: {field}")

    def test_severity_valid_values(self):
        entries = [SQL_ENTRY] * 15
        result = cluster_attacks(entries)
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        for cluster in result["clusters"]:
            self.assertIn(cluster["severity"], valid,
                f"Invalid severity: {cluster['severity']}")


class TestModelInfo(unittest.TestCase):
    """Tests for model metadata endpoint."""

    def test_get_model_info_returns_dict(self):
        info = get_model_info()
        self.assertIsInstance(info, dict)

    def test_has_15_features(self):
        info = get_model_info()
        self.assertEqual(info["n_features"], 15)

    def test_feature_names_length(self):
        info = get_model_info()
        self.assertEqual(len(info["feature_names"]), 15)
        # Must match the global FEATURE_NAMES list
        self.assertEqual(info["feature_names"], FEATURE_NAMES)

    def test_algorithm_is_isolation_forest(self):
        info = get_model_info()
        self.assertEqual(info["algorithm"], "Isolation Forest")

    def test_has_enhancements_list(self):
        info = get_model_info()
        self.assertIn("enhancements", info)
        self.assertIsInstance(info["enhancements"], list)
        self.assertGreater(len(info["enhancements"]), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
