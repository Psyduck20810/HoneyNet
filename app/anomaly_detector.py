import numpy as np
import json
import os
import math
import datetime
from collections import Counter
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import LabelEncoder, StandardScaler
import pickle

# ── Paths ─────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(__file__)
MODEL_FILE  = os.path.join(BASE_DIR, "anomaly_model.pkl")
LOG_FILE    = os.path.join(BASE_DIR, "../logs/attack.log")

# ── Encoders ──────────────────────────────────────────────
country_enc   = LabelEncoder()
endpoint_enc  = LabelEncoder()
attack_enc    = LabelEncoder()
honeypot_enc  = LabelEncoder()

KNOWN_COUNTRIES = [
    "China","Russia","Nigeria","Brazil","Iran","Ukraine","Ethiopia",
    "Vietnam","Germany","Netherlands","Pakistan","South Africa","Romania",
    "Thailand","India","Venezuela","Kenya","Indonesia","Turkey","Morocco",
    "Local Network","Unknown","United States","United Kingdom","France"
]
KNOWN_ENDPOINTS = [
    "/login","/admin","/wp-login.php","/phpmyadmin","/config.php",
    "/backup.zip","/server-status","/api/users","/aws-console",
    "/bookings","/flights","/hotels","/payments","/",
    "/ssh","/ssh/command","/mongodb","/email","/download"
]
KNOWN_ATTACKS = [
    "SQL Injection","XSS Attack","Command Injection","Path Traversal",
    "Brute Force","Reconnaissance","Normal","Cloud Credential Theft",
    "Phishing Email","Spam Email","Database Probe","SSH Brute Force",
    "SSH Command Execution","MongoDB Probe","MongoDB List Databases",
    "MongoDB Data Dump Attempt","Suspicious Email"
]
KNOWN_HONEYPOTS = ["WEB", "SSH", "DATABASE", "EMAIL"]

# High-risk origin countries (historically high attack traffic)
HIGH_RISK_COUNTRIES = {
    "China", "Russia", "Nigeria", "Iran", "Ukraine",
    "North Korea", "Romania", "Brazil", "Vietnam"
}

country_enc.fit(KNOWN_COUNTRIES)
endpoint_enc.fit(KNOWN_ENDPOINTS)
attack_enc.fit(KNOWN_ATTACKS)
honeypot_enc.fit(KNOWN_HONEYPOTS)

# ── Feature names (for display / explainability) ──────────
FEATURE_NAMES = [
    "Hour of Day",
    "Risk Score",
    "Country (encoded)",
    "Endpoint (encoded)",
    "Attack Type (encoded)",
    "Payload Length",
    "Odd Hour (1–5 am)",
    "Payload Entropy",
    "Is Weekend",
    "Honeypot Type (encoded)",
    "Special Char Count",
    "Username Length",
    "Has URL Encoding",
    "Multi-Vector Attack",
    "High-Risk Country",
]

def safe_encode(encoder, value, known_list):
    if value not in known_list:
        value = known_list[0]
    return int(encoder.transform([value])[0])


# ── Feature 7: Shannon Entropy ────────────────────────────
def shannon_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of a string.
    High entropy → obfuscated / encoded payload (e.g. base64, URL encoding).
    Normal text has entropy ~3.5; encoded attacks often exceed 4.5.
    """
    if not text:
        return 0.0
    text = str(text)
    freq = Counter(text)
    length = len(text)
    entropy = -sum((count / length) * math.log2(count / length)
                   for count in freq.values() if count > 0)
    return round(entropy, 4)


# ── Feature 10: Special character count ──────────────────
SPECIAL_CHARS = set("'\";<>(){}[]|&!@#$%^*`~\\")

def count_special_chars(text: str) -> int:
    return sum(1 for c in str(text) if c in SPECIAL_CHARS)


# ── Feature 12: URL-encoding detection ───────────────────
def has_url_encoding(text: str) -> int:
    """Return 1 if payload contains %XX URL-encoded characters."""
    import re
    return int(bool(re.search(r'%[0-9a-fA-F]{2}', str(text))))


# ── Feature 13: Multi-vector detection ────────────────────
def is_multi_vector(attack_type: str, payload: str) -> int:
    """
    Return 1 if multiple attack signatures are present in one request.
    e.g. SQLi payload that also contains XSS markers = multi-vector.
    """
    import re
    payload_lower = str(payload).lower()
    hits = 0
    patterns = [
        r"('|\").*or.*=",            # SQLi
        r"<script|onerror=|alert\(", # XSS
        r"\.\./|%2e%2e",             # Path traversal
        r";\s*(ls|cat|whoami|id)",   # Command injection
        r"(select|union|drop)\s",    # SQLi keywords
    ]
    for p in patterns:
        if re.search(p, payload_lower):
            hits += 1
    return int(hits >= 2)


# ── Feature extraction (15 features) ─────────────────────
def extract_features(entry: dict) -> list:
    """
    Extract 15 numerical features from a log entry.

    Features:
      0  hour              — hour of day (0–23)
      1  risk_score        — raw risk score (1–10)
      2  country_code      — label-encoded country
      3  endpoint_code     — label-encoded endpoint
      4  attack_code       — label-encoded attack type
      5  payload_len       — character length of payload
      6  odd_hour          — 1 if hour is 1–5 am (suspicious)
      7  payload_entropy   — Shannon entropy of payload string
      8  is_weekend        — 1 if Saturday or Sunday
      9  honeypot_code     — label-encoded honeypot type
      10 special_char_count — count of special chars in payload
      11 username_len      — length of username field
      12 has_url_encoding  — 1 if %XX patterns present
      13 multi_vector      — 1 if multiple attack patterns detected
      14 is_high_risk_country — 1 if origin is a known high-risk country
    """
    try:
        # ── Feature 0: Hour of day ──────────────────────
        ts = entry.get("timestamp", "2026-01-01T00:00:00")
        try:
            dt   = datetime.datetime.fromisoformat(ts.replace(" ", "T"))
            hour = dt.hour
        except Exception:
            hour = 12

        # ── Feature 1: Risk score ───────────────────────
        risk_score = float(entry.get("risk_score", 5))

        # ── Feature 2: Country ──────────────────────────
        country_code = safe_encode(country_enc, entry.get("country", "Unknown"), KNOWN_COUNTRIES)

        # ── Feature 3: Endpoint ─────────────────────────
        endpoint_code = safe_encode(endpoint_enc, entry.get("endpoint", "/login"), KNOWN_ENDPOINTS)

        # ── Feature 4: Attack type ──────────────────────
        attack_code = safe_encode(attack_enc, entry.get("attack_type", "Normal"), KNOWN_ATTACKS)

        # ── Feature 5: Payload length ───────────────────
        payload = str(entry.get("payload", ""))
        payload_len = min(len(payload), 2000)  # cap to avoid outlier skew

        # ── Feature 6: Odd hour (1 am–5 am) ─────────────
        odd_hour = int(hour in range(1, 6))

        # ── Feature 7: Shannon entropy ──────────────────
        payload_entropy = shannon_entropy(payload)

        # ── Feature 8: Weekend ──────────────────────────
        try:
            is_weekend = int(dt.weekday() >= 5)
        except Exception:
            is_weekend = 0

        # ── Feature 9: Honeypot type ────────────────────
        htype = entry.get("honeypot_type", "WEB")
        if htype not in KNOWN_HONEYPOTS:
            htype = "WEB"
        honeypot_code = safe_encode(honeypot_enc, htype, KNOWN_HONEYPOTS)

        # ── Feature 10: Special char count ──────────────
        special_char_count = min(count_special_chars(payload), 50)

        # ── Feature 11: Username length ─────────────────
        username_len = min(len(str(entry.get("username", ""))), 200)

        # ── Feature 12: URL encoding ────────────────────
        has_url_enc = has_url_encoding(payload)

        # ── Feature 13: Multi-vector ────────────────────
        attack_type = entry.get("attack_type", "Normal")
        multi_vec   = is_multi_vector(attack_type, payload)

        # ── Feature 14: High-risk country ───────────────
        country          = entry.get("country", "Unknown")
        is_high_risk_cty = int(country in HIGH_RISK_COUNTRIES)

        return [
            hour, risk_score, country_code, endpoint_code, attack_code,
            payload_len, odd_hour, payload_entropy, is_weekend, honeypot_code,
            special_char_count, username_len, has_url_enc, multi_vec, is_high_risk_cty
        ]

    except Exception:
        # Safe fallback: return neutral values
        return [12, 5, 0, 0, 0, 0, 0, 3.0, 0, 0, 0, 0, 0, 0, 0]


# ── Load training data ────────────────────────────────────
def load_training_data():
    entries = []
    try:
        with open(LOG_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except Exception:
                        pass
    except Exception:
        pass
    return entries


# ── Train model ───────────────────────────────────────────
def train_model():
    entries = load_training_data()

    if len(entries) < 10:
        print("[ML] Not enough real data — using synthetic training set")
        # Synthetic baseline: (hour, risk, country, endpoint, attack,
        #   payload_len, odd_hour, entropy, weekend, htype,
        #   special_chars, user_len, url_enc, multi_vec, high_risk_country)
        synthetic = []
        # Normal daytime traffic
        for _ in range(60):
            synthetic.append([10, 3, 0, 0, 6, 20, 0, 3.2, 0, 0, 1, 5,  0, 0, 0])
            synthetic.append([14, 4, 1, 0, 0, 30, 0, 3.5, 1, 0, 2, 6,  0, 0, 0])
            synthetic.append([ 9, 5, 2, 1, 1, 25, 0, 3.8, 0, 0, 3, 8,  0, 0, 1])
        # Anomalies: late night, high risk, long payload, high entropy
        for _ in range(15):
            synthetic.append([ 3, 10, 4, 3, 3, 500, 1, 5.8, 0, 1, 18, 35, 1, 1, 1])
            synthetic.append([ 2,  9, 5, 4, 2, 400, 1, 5.5, 0, 0, 15, 30, 1, 0, 1])
            synthetic.append([ 4, 10, 0, 2, 0, 600, 1, 6.0, 0, 1, 20, 40, 1, 1, 0])
        X = np.array(synthetic)
    else:
        X = np.array([extract_features(e) for e in entries])

    model = IsolationForest(
        n_estimators=200,         # more trees = more stable predictions
        contamination=0.25,       # realistic: ~25% of honeypot traffic is anomalous
        max_features=0.85,        # feature subsampling for better generalisation
        random_state=42
    )
    model.fit(X)

    with open(MODEL_FILE, "wb") as f:
        pickle.dump(model, f)

    print(f"[ML] ✅ Model trained on {len(X)} samples, 15 features — saved to {MODEL_FILE}")
    return model


# ── Load or train model ───────────────────────────────────
def load_model():
    if os.path.exists(MODEL_FILE):
        try:
            with open(MODEL_FILE, "rb") as f:
                model = pickle.load(f)
            # Verify model was trained with 15 features (not old 7-feature model)
            # Do a quick test prediction; old model will raise ValueError
            test = np.array([[extract_features({})]])
            model.predict(test)
            print("[ML] Anomaly model loaded from disk (15 features)")
            return model
        except Exception as e:
            print(f"[ML] Old model incompatible ({e}) — retraining with 15 features")
    return train_model()

_model = load_model()

# ── Always-anomalous attack types ────────────────────────
DANGEROUS_ATTACKS = {
    "SQL Injection", "XSS Attack", "Command Injection", "Path Traversal",
    "Brute Force", "Cloud Credential Theft", "Database Probe",
    "Phishing Email", "Spam Email", "SSH Brute Force",
    "SSH Command Execution", "MongoDB Data Dump Attempt",
}


# ── Main detection function ───────────────────────────────
def detect_anomaly(entry: dict) -> dict:
    """
    Analyse a single log entry and return anomaly verdict.
    Uses IsolationForest (ML) + rule-based overrides.

    Returns:
        is_anomaly    (bool)
        anomaly_score (float, 0–100)
        label         (str: "ANOMALY" | "NORMAL")
        reasons       (list[str]: human-readable explanations)
        confidence    (str: "XX.X%")
        features      (dict: named feature values for dashboard display)
    """
    try:
        features    = extract_features(entry)
        X           = np.array([features])
        pred        = _model.predict(X)[0]        # -1 = anomaly, 1 = normal
        raw_score   = _model.score_samples(X)[0]  # lower = more anomalous

        attack_type = entry.get("attack_type", "Normal")
        risk_score  = float(entry.get("risk_score", 0))

        # ── Base ML verdict ─────────────────────────────
        is_anomaly    = pred == -1
        # Map raw score (typically -0.5 to 0.1) to 0–100 scale
        anomaly_score = round((1 - (raw_score + 0.5)) * 100, 1)
        anomaly_score = max(0.0, min(100.0, anomaly_score))

        # ── Rule-based overrides ─────────────────────────
        if attack_type in DANGEROUS_ATTACKS:
            is_anomaly    = True
            anomaly_score = max(anomaly_score, 60.0)

        if risk_score >= 9:
            is_anomaly    = True
            anomaly_score = max(anomaly_score, 85.0)
        elif risk_score >= 7:
            is_anomaly    = True
            anomaly_score = max(anomaly_score, 55.0)

        # ── Entropy boost ────────────────────────────────
        entropy = features[7]
        if entropy >= 5.0:
            is_anomaly    = True
            anomaly_score = max(anomaly_score, 70.0)

        # ── Multi-vector boost ───────────────────────────
        if features[13] == 1:
            is_anomaly    = True
            anomaly_score = max(anomaly_score, 75.0)

        # ── Human-readable reasons ───────────────────────
        reasons = []
        hour = features[0]
        if hour in range(1, 6):
            reasons.append(f"Odd hour ({hour}:00 am — suspicious time window)")
        if risk_score >= 9:
            reasons.append(f"Critical risk score ({int(risk_score)}/10)")
        elif risk_score >= 7:
            reasons.append(f"High risk score ({int(risk_score)}/10)")
        if features[5] > 200:
            reasons.append(f"Unusually long payload ({features[5]} chars)")
        if entropy >= 5.0:
            reasons.append(f"High payload entropy ({entropy:.2f}) — possible obfuscation")
        elif entropy >= 4.5:
            reasons.append(f"Elevated payload entropy ({entropy:.2f})")
        if features[8] == 1:
            reasons.append("Weekend attack — unusual timing")
        if features[10] >= 10:
            reasons.append(f"High special char density ({features[10]} chars) — injection indicator")
        if features[12] == 1:
            reasons.append("URL-encoded payload — evasion attempt")
        if features[13] == 1:
            reasons.append("Multi-vector payload — combined attack signatures detected")
        if features[14] == 1:
            reasons.append(f"High-risk origin country: {entry.get('country','Unknown')}")
        if attack_type in DANGEROUS_ATTACKS:
            reasons.append(f"Dangerous attack type: {attack_type}")
        if entry.get("honeypot_type") in ("SSH", "DATABASE", "EMAIL"):
            reasons.append(f"Non-web vector: {entry.get('honeypot_type')} honeypot targeted")
        if not reasons and is_anomaly:
            reasons.append("Unusual behavioural pattern detected by Isolation Forest")
        if not reasons:
            reasons.append("Normal traffic pattern")

        # ── Named feature dict for dashboard display ─────
        named_features = {
            "Hour of Day":           hour,
            "Risk Score":            risk_score,
            "Payload Length":        features[5],
            "Payload Entropy":       round(entropy, 2),
            "Is Weekend":            bool(features[8]),
            "Honeypot Type":         entry.get("honeypot_type", "WEB"),
            "Special Chars":         features[10],
            "Username Length":       features[11],
            "URL-Encoded":           bool(features[12]),
            "Multi-Vector":          bool(features[13]),
            "High-Risk Country":     bool(features[14]),
            "Country":               entry.get("country", "Unknown"),
        }

        return {
            "is_anomaly":    bool(is_anomaly),
            "anomaly_score": float(anomaly_score),
            "reasons":       reasons,
            "label":         "ANOMALY" if is_anomaly else "NORMAL",
            "confidence":    f"{float(anomaly_score):.1f}%",
            "features":      named_features,
        }

    except Exception as e:
        print(f"[ML] detect_anomaly error: {e}")
        return {
            "is_anomaly":    False,
            "anomaly_score": 0.0,
            "reasons":       ["Detection error"],
            "label":         "NORMAL",
            "confidence":    "0%",
            "features":      {},
        }


# ── DBSCAN attack clustering ──────────────────────────────
def cluster_attacks(entries: list) -> dict:
    """
    Group attack entries into behavioural clusters using DBSCAN.
    Clusters reveal coordinated attack campaigns that share similar
    patterns (same time-of-day, attack type, origin region, etc.)

    Returns a dict with cluster_count, clusters (list), noise_count.
    """
    if len(entries) < 5:
        return {"cluster_count": 0, "clusters": [], "noise_count": 0,
                "algorithm": "DBSCAN", "status": "insufficient_data"}

    try:
        X_raw = np.array([extract_features(e) for e in entries], dtype=float)

        # Normalise features before DBSCAN (distance-sensitive)
        scaler  = StandardScaler()
        X_scaled = scaler.fit_transform(X_raw)

        db = DBSCAN(eps=1.2, min_samples=3, metric="euclidean")
        labels = db.fit_predict(X_scaled)

        unique_labels = set(labels)
        noise_count   = int(np.sum(labels == -1))
        cluster_ids   = [l for l in unique_labels if l != -1]

        clusters = []
        for cid in sorted(cluster_ids):
            mask    = labels == cid
            members = [e for e, m in zip(entries, mask) if m]

            attack_types = Counter(e.get("attack_type", "Unknown") for e in members)
            countries    = Counter(e.get("country", "Unknown") for e in members)
            honeypots    = Counter(e.get("honeypot_type", "WEB") for e in members)
            risk_scores  = [float(e.get("risk_score", 0)) for e in members]
            avg_risk     = round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else 0

            timestamps   = [e.get("timestamp", "") for e in members if e.get("timestamp")]
            timestamps.sort()

            clusters.append({
                "cluster_id":       int(cid),
                "size":             len(members),
                "dominant_attack":  attack_types.most_common(1)[0][0] if attack_types else "Unknown",
                "dominant_country": countries.most_common(1)[0][0] if countries else "Unknown",
                "dominant_honeypot":honeypots.most_common(1)[0][0] if honeypots else "WEB",
                "attack_types":     dict(attack_types),
                "countries":        dict(countries),
                "avg_risk_score":   avg_risk,
                "ips":              list({e.get("ip", "") for e in members})[:5],
                "first_seen":       timestamps[0][:16] if timestamps else "—",
                "last_seen":        timestamps[-1][:16] if timestamps else "—",
                "severity":         "CRITICAL" if avg_risk >= 9 else
                                    "HIGH"     if avg_risk >= 7 else
                                    "MEDIUM"   if avg_risk >= 4 else "LOW",
            })

        # Sort clusters by severity
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        clusters.sort(key=lambda c: (sev_order.get(c["severity"], 9), -c["size"]))

        return {
            "algorithm":     "DBSCAN (eps=1.2, min_samples=3, StandardScaler)",
            "cluster_count": len(clusters),
            "noise_count":   noise_count,
            "total_entries": len(entries),
            "clusters":      clusters,
            "status":        "ok",
        }

    except Exception as e:
        print(f"[ML] Clustering error: {e}")
        return {"cluster_count": 0, "clusters": [], "noise_count": 0,
                "algorithm": "DBSCAN", "status": f"error: {e}"}


# ── Model metadata for dashboard ─────────────────────────
def get_model_info() -> dict:
    entries = load_training_data()
    return {
        "algorithm":       "Isolation Forest",
        "library":         "scikit-learn",
        "n_estimators":    200,
        "contamination":   0.25,
        "max_features":    0.85,
        "n_features":      15,
        "feature_names":   FEATURE_NAMES,
        "training_samples":len(entries),
        "model_file":      os.path.basename(MODEL_FILE),
        "detection_mode":  "Unsupervised (no labelled data required)",
        "enhancements":    [
            "Shannon entropy analysis (payload obfuscation detection)",
            "Weekend / off-hours temporal analysis",
            "URL-encoding evasion detection",
            "Multi-vector attack pattern detection",
            "High-risk country origin scoring",
            "Cross-honeypot type feature",
            "DBSCAN attack campaign clustering",
        ],
    }


# ── Retrain ───────────────────────────────────────────────
def retrain() -> dict:
    global _model
    _model = train_model()
    entries = load_training_data()
    return {
        "status":   "retrained",
        "samples":  len(entries),
        "features": 15,
        "algorithm":"Isolation Forest",
    }
