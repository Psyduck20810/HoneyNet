import os
import requests
import time
from collections import defaultdict

# Simple in-memory cache so we don't re-check same IP
_cache = {}
_cache_ttl = 3600  # 1 hour

def check_ip(ip: str) -> dict:
    """Check an IP against multiple threat intelligence sources."""

    # Skip private/local IPs
    if ip.startswith(("127.", "10.", "192.168.", "172.", "0.")):
        return {
            "ip": ip,
            "is_threat": False,
            "threat_score": 0,
            "flags": ["Local/Private IP — not checked"],
            "sources_checked": 0,
            "is_tor":   False,
            "is_proxy": False,
            "is_vpn":   False,
            "isp":      "Local Network",
            "org":      "Local Network",
        }

    # Return cached result if available
    now = time.time()
    if ip in _cache and now - _cache[ip]["_cached_at"] < _cache_ttl:
        return _cache[ip]

    result = {
        "ip":             ip,
        "is_threat":      False,
        "threat_score":   0,
        "flags":          [],
        "sources_checked":0,
        "is_tor":         False,
        "is_proxy":       False,
        "is_vpn":         False,
        "isp":            "Unknown",
        "org":            "Unknown",
        "abuse_reports":  0,
        "databases_found":0,
    }

    # ── Source 1: ip-api.com (free, no key needed) ───────
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,proxy,hosting,isp,org,as,country,city",
            timeout=4
        )
        data = r.json()
        result["sources_checked"] += 1

        if data.get("proxy"):
            result["is_proxy"] = True
            result["flags"].append("⚠️ Detected as Proxy/VPN by ip-api.com")
            result["threat_score"] += 30
            result["databases_found"] += 1

        if data.get("hosting"):
            result["flags"].append("🖥️ Hosting/Datacenter IP — likely automated attack")
            result["threat_score"] += 20
            result["databases_found"] += 1

        result["isp"] = data.get("isp", "Unknown")
        result["org"] = data.get("org", "Unknown")

        # Check for suspicious ISPs
        suspicious_isps = [
            "tor", "bulletproof", "njalla", "frantech",
            "serverius", "sharktech", "psychz", "vpn",
            "mullvad", "nordvpn", "expressvpn", "hide.me"
        ]
        isp_lower = result["isp"].lower()
        for s_isp in suspicious_isps:
            if s_isp in isp_lower:
                result["flags"].append(f"🚨 Suspicious ISP detected: {result['isp']}")
                result["threat_score"] += 25
                result["databases_found"] += 1
                break

    except Exception as e:
        print(f"[ThreatIntel] ip-api error for {ip}: {e}")

    # ── Source 2: AbuseIPDB (free tier, no key needed for basic) ─
    try:
        r = requests.get(
            f"https://api.abuseipdb.com/api/v2/check",
            headers={
                "Key": os.environ.get("ABUSEIPDB_KEY", ""),
                "Accept": "application/json"
            },
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=4
        )
        if r.status_code == 200:
            data = r.json().get("data", {})
            result["sources_checked"] += 1
            abuse_score = data.get("abuseConfidenceScore", 0)
            total_reports = data.get("totalReports", 0)
            result["abuse_reports"] = total_reports

            if abuse_score > 0:
                result["threat_score"] += min(abuse_score, 50)
                result["databases_found"] += 1
                result["flags"].append(
                    f"🔴 AbuseIPDB: {abuse_score}% confidence, {total_reports} reports"
                )
            if data.get("isTor"):
                result["is_tor"] = True
                result["flags"].append("🧅 Confirmed Tor Exit Node (AbuseIPDB)")
                result["threat_score"] += 40
    except Exception as e:
        print(f"[ThreatIntel] AbuseIPDB error for {ip}: {e}")

    # ── Source 3: Check against known bad IP ranges ──────
    try:
        known_bad_ranges = [
            ("185.220.", "Known Tor Exit Range"),
            ("185.130.", "Known Bulletproof Hosting"),
            ("46.166.",  "Known Spam/Attack Range"),
            ("91.108.",  "Known Malicious Range"),
            ("194.165.", "Known Attack Range"),
            ("45.142.",  "Known Bulletproof Hosting"),
            ("185.56.",  "Known Attack Range"),
            ("179.43.",  "Known Bulletproof Hosting"),
        ]
        for prefix, label in known_bad_ranges:
            if ip.startswith(prefix):
                result["flags"].append(f"🚨 {label} ({prefix}x.x)")
                result["threat_score"] += 35
                result["databases_found"] += 1
                break
    except Exception as e:
        print(f"[ThreatIntel] Range check error: {e}")

    # ── Source 4: GreyNoise community API ────────────────
    try:
        r = requests.get(
            f"https://api.greynoise.io/v3/community/{ip}",
            headers={"key": os.environ.get("GREYNOISE_KEY", "")},
            timeout=4
        )
        if r.status_code == 200:
            data = r.json()
            result["sources_checked"] += 1
            classification = data.get("classification", "")
            noise          = data.get("noise", False)
            riot           = data.get("riot", False)

            if classification == "malicious":
                result["flags"].append("🔴 GreyNoise: Confirmed MALICIOUS scanner")
                result["threat_score"] += 50
                result["databases_found"] += 1
            elif noise:
                result["flags"].append("⚠️ GreyNoise: Known internet scanner")
                result["threat_score"] += 20
                result["databases_found"] += 1
            if riot:
                result["flags"].append("✅ GreyNoise: Known benign service (RIOT)")
                result["threat_score"] = max(0, result["threat_score"] - 20)

    except Exception as e:
        print(f"[ThreatIntel] GreyNoise error for {ip}: {e}")

    # ── Final threat level ───────────────────────────────
    score = result["threat_score"]
    if score >= 70:
        result["threat_level"] = "CRITICAL"
        result["is_threat"]    = True
    elif score >= 40:
        result["threat_level"] = "HIGH"
        result["is_threat"]    = True
    elif score >= 20:
        result["threat_level"] = "MEDIUM"
        result["is_threat"]    = True
    elif score > 0:
        result["threat_level"] = "LOW"
    else:
        result["threat_level"] = "CLEAN"

    if not result["flags"]:
        result["flags"].append("✅ No threat indicators found")

    # Cache the result
    result["_cached_at"] = time.time()
    _cache[ip] = result
    return result


def check_multiple_ips(ips: list) -> dict:
    """Check multiple IPs and return results dict."""
    results = {}
    for ip in ips[:10]:  # Max 10 IPs to avoid rate limits
        results[ip] = check_ip(ip)
        time.sleep(0.3)  # Be polite to APIs
    return results
