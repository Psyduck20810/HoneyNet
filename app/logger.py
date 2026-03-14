
import json
import os
import datetime
from collections import defaultdict, Counter

LOG_FILE = os.path.join(os.path.dirname(__file__), "../logs/attack.log")

# Load .env
_env_path = os.path.join(os.path.dirname(__file__), '../.env')
if os.path.exists(_env_path):
    with open(_env_path) as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith('#') and '=' in _line:
                _k, _v = _line.split('=', 1)
                os.environ.setdefault(_k.strip(), _v.strip())

# Try MongoDB
try:
    from pymongo import MongoClient
    MONGO_URI = os.environ.get("MONGO_URI", "")
    if MONGO_URI:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
        db = client["honeypot_db"]
        collection = db["attacks"]
        MONGO_ENABLED = True
    else:
        MONGO_ENABLED = False
except Exception:
    MONGO_ENABLED = False


class AttackLogger:

    def log(self, entry: dict):
        entry["timestamp"] = datetime.datetime.utcnow().isoformat()
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
        if MONGO_ENABLED:
            try:
                collection.insert_one({k: v for k, v in entry.items()})
            except Exception as e:
                print(f"[MongoDB] Write failed: {e}")
        print(f"[{entry['timestamp']}] {entry['risk_level']} | {entry['attack_type']} | {entry['ip']} | {entry['country']}")

    def _load_all(self):
        entries = []
        if not os.path.exists(LOG_FILE):
            return entries
        with open(LOG_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except Exception:
                        pass
        return entries

    def get_recent(self, n=20):
        entries = self._load_all()
        return entries[-n:][::-1]

    def get_honeypot_stats(self):
        """Get breakdown by honeypot type."""
        entries = self._load_all()
        types = {}
        for e in entries:
            htype = e.get("honeypot_type", "WEB")
            types[htype] = types.get(htype, 0) + 1
        return types

    def get_stats(self):
        entries = self._load_all()
        if not entries:
            return {
                "total": 0,
                "attack_types": {},
                "risk_levels": {},
                "top_countries": {},
                "top_ips": {},
                "recent_count": 0,
            }
        attack_types = Counter(e.get("attack_type", "Unknown") for e in entries)
        risk_levels  = Counter(e.get("risk_level", "LOW") for e in entries)
        countries    = Counter(e.get("country", "Unknown") for e in entries)
        ips          = Counter(e.get("ip", "Unknown") for e in entries)
        now = datetime.datetime.utcnow()
        one_hour_ago = (now - datetime.timedelta(hours=1)).isoformat()
        recent = [e for e in entries if e.get("timestamp", "") >= one_hour_ago]
        return {
            "total": len(entries),
            "attack_types": dict(attack_types.most_common(10)),
            "risk_levels": dict(risk_levels),
            "top_countries": dict(countries.most_common(10)),
            "top_ips": dict(ips.most_common(10)),
            "recent_count": len(recent),
        }

    def get_timeline(self):
        entries = self._load_all()
        now = datetime.datetime.utcnow()
        hourly = defaultdict(int)
        for e in entries:
            ts = e.get("timestamp", "")
            try:
                dt = datetime.datetime.fromisoformat(ts)
                diff_hours = int((now - dt).total_seconds() / 3600)
                if 0 <= diff_hours < 24:
                    label = dt.strftime("%H:00")
                    hourly[label] += 1
            except Exception:
                pass
        result = []
        for h in range(23, -1, -1):
            dt = now - datetime.timedelta(hours=h)
            label = dt.strftime("%H:00")
            result.append({"hour": label, "count": hourly.get(label, 0)})
        return result

    def get_hourly_heatmap(self):
        hourly = {str(h): 0 for h in range(24)}
        try:
            entries = self._load_all()
            for entry in entries:
                ts = entry.get("timestamp", "")
                if "T" in ts:
                    try:
                        hour = int(ts.split("T")[1].split(":")[0])
                        hourly[str(hour)] = hourly.get(str(hour), 0) + 1
                    except Exception:
                        pass
        except Exception as e:
            print(f"[Logger] Hourly heatmap error: {e}")
        return hourly
    def get_sessions(self):
        """Group attacks by IP and build attacker sessions."""
        entries  = self._load_all()
        sessions = {}

        for e in entries:
            ip = e.get("ip", "Unknown")
            if ip not in sessions:
                sessions[ip] = {
                    "ip":          ip,
                    "country":     e.get("country",  "Unknown"),
                    "city":        e.get("city",     "Unknown"),
                    "isp":         e.get("isp",      "Unknown"),
                    "browser":     e.get("browser",  "Unknown"),
                    "os":          e.get("operating_system", "Unknown"),
                    "lat":         e.get("lat", 0),
                    "lon":         e.get("lon", 0),
                    "events":      [],
                    "first_seen":  e.get("timestamp", ""),
                    "last_seen":   e.get("timestamp", ""),
                    "risk_levels": [],
                    "attack_types":[],
                }

            sessions[ip]["events"].append({
                "timestamp":   e.get("timestamp",   ""),
                "endpoint":    e.get("endpoint",    "/"),
                "attack_type": e.get("attack_type", "Unknown"),
                "risk_level":  e.get("risk_level",  "LOW"),
                "risk_score":  e.get("risk_score",  0),
                "username":    e.get("username",    ""),
                "payload":     e.get("payload",     ""),
            })

            sessions[ip]["last_seen"]  = e.get("timestamp", "")
            sessions[ip]["risk_levels"].append(e.get("risk_level", "LOW"))
            sessions[ip]["attack_types"].append(e.get("attack_type", "Unknown"))

        # Build summary for each session
        result = []
        for ip, s in sessions.items():
            risk_levels  = s["risk_levels"]
            if "HIGH"   in risk_levels: overall = "HIGH"
            elif "MEDIUM" in risk_levels: overall = "MEDIUM"
            else:                         overall = "LOW"

            from collections import Counter
            top_attack = Counter(s["attack_types"]).most_common(1)
            top_attack = top_attack[0][0] if top_attack else "Unknown"

            result.append({
                "ip":           ip,
                "country":      s["country"],
                "city":         s["city"],
                "isp":          s["isp"],
                "browser":      s["browser"],
                "os":           s["os"],
                "lat":          s["lat"],
                "lon":          s["lon"],
                "first_seen":   s["first_seen"],
                "last_seen":    s["last_seen"],
                "total_events": len(s["events"]),
                "overall_risk": overall,
                "top_attack":   top_attack,
                "events":       s["events"],
            })

        # Sort by most recent first
        result.sort(key=lambda x: x["last_seen"], reverse=True)
        return result[:20]