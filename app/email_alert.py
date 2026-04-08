import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from utils import load_env

load_env()

EMAIL_SENDER   = os.environ.get("EMAIL_SENDER", "")
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD", "")
EMAIL_RECEIVER = os.environ.get("EMAIL_RECEIVER", "")


def send_email_alert(entry: dict):
    """Send Gmail alert for HIGH risk attacks."""

    if not EMAIL_SENDER or not EMAIL_PASSWORD or not EMAIL_RECEIVER:
        print("[Email] Not configured — skipping.")
        return

    risk_color = {
        "HIGH":   "#ff3b3b",
        "MEDIUM": "#ff8c42",
        "LOW":    "#00e599"
    }.get(entry.get("risk_level", "LOW"), "#cccccc")

    risk_emoji = {
        "HIGH":   "🔴",
        "MEDIUM": "🟠",
        "LOW":    "🟡"
    }.get(entry.get("risk_level", "LOW"), "⚪")

    # ── HTML Email Body ──────────────────────────────────
    html = f"""
<!DOCTYPE html>
<html>
<head>
<style>
  body {{ font-family: Arial, sans-serif; background: #f4f4f4; margin: 0; padding: 20px; }}
  .container {{ max-width: 600px; margin: 0 auto; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }}
  .header {{ background: #0a0c10; padding: 24px; text-align: center; }}
  .header h1 {{ color: white; font-size: 20px; margin: 0; }}
  .risk-banner {{ background: {risk_color}; padding: 14px 24px; text-align: center; }}
  .risk-banner h2 {{ color: white; margin: 0; font-size: 18px; letter-spacing: 0.05em; }}
  .body {{ padding: 24px; }}
  .section {{ margin-bottom: 20px; }}
  .section-title {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.1em; color: #999; margin-bottom: 10px; border-bottom: 1px solid #eee; padding-bottom: 6px; }}
  .row {{ display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #f4f4f4; }}
  .label {{ font-size: 13px; color: #666; font-weight: 600; }}
  .value {{ font-size: 13px; color: #222; text-align: right; max-width: 320px; word-break: break-all; }}
  .value.danger {{ color: {risk_color}; font-weight: 700; }}
  .payload-box {{ background: #1a1a2e; color: #00ff88; font-family: monospace; font-size: 13px; padding: 14px; border-radius: 6px; word-break: break-all; margin-top: 8px; }}
  .footer {{ background: #f4f4f4; padding: 16px 24px; text-align: center; font-size: 11px; color: #999; }}
</style>
</head>
<body>
<div class="container">

  <div class="header">
    <h1>🛡️ Honeypot Intelligence System</h1>
    <p style="color:#666;margin:4px 0 0;font-size:13px;">Thomas Cook Travel — Security Monitor</p>
  </div>

  <div class="risk-banner">
    <h2>{risk_emoji} {entry.get('risk_level','UNKNOWN')} RISK ATTACK DETECTED</h2>
  </div>

  <div class="body">

    <div class="section">
      <div class="section-title">⚔ Attack Details</div>
      <div class="row">
        <span class="label">Attack Type</span>
        <span class="value danger">{entry.get('attack_type','Unknown')}</span>
      </div>
      <div class="row">
        <span class="label">Risk Score</span>
        <span class="value danger">{entry.get('risk_score',0)} / 10</span>
      </div>
      <div class="row">
        <span class="label">Risk Level</span>
        <span class="value danger">{entry.get('risk_level','Unknown')}</span>
      </div>
      <div class="row">
        <span class="label">Endpoint</span>
        <span class="value">{entry.get('endpoint','/')}</span>
      </div>
      <div class="row">
        <span class="label">Timestamp</span>
        <span class="value">{entry.get('timestamp','Unknown')}</span>
      </div>
    </div>

    <div class="section">
      <div class="section-title">🌍 Attacker Location</div>
      <div class="row">
        <span class="label">IP Address</span>
        <span class="value danger">{entry.get('ip','Unknown')}</span>
      </div>
      <div class="row">
        <span class="label">Country</span>
        <span class="value">{entry.get('country','Unknown')}</span>
      </div>
      <div class="row">
        <span class="label">City</span>
        <span class="value">{entry.get('city','Unknown')}</span>
      </div>
      <div class="row">
        <span class="label">ISP</span>
        <span class="value">{entry.get('isp','Unknown')}</span>
      </div>
    </div>

    <div class="section">
      <div class="section-title">🖥 Attacker Device</div>
      <div class="row">
        <span class="label">Browser</span>
        <span class="value">{entry.get('browser','Unknown')}</span>
      </div>
      <div class="row">
        <span class="label">Operating System</span>
        <span class="value">{entry.get('operating_system','Unknown')}</span>
      </div>
      <div class="row">
        <span class="label">Referrer</span>
        <span class="value">{entry.get('referrer','Direct')}</span>
      </div>
      <div class="row">
        <span class="label">User Agent</span>
        <span class="value">{entry.get('user_agent','Unknown')[:80]}</span>
      </div>
    </div>

    <div class="section">
      <div class="section-title">👤 Login Attempt</div>
      <div class="row">
        <span class="label">Username Tried</span>
        <span class="value danger">{entry.get('username','-')}</span>
      </div>
      <div class="row">
        <span class="label">Password Tried</span>
        <span class="value danger">{entry.get('password','-')}</span>
      </div>
    </div>

    <div class="section">
      <div class="section-title">💉 Attack Payload</div>
      <div class="payload-box">{entry.get('payload','-')[:200]}</div>
    </div>

  </div>

  <div class="footer">
    This alert was generated automatically by your Honeypot Intelligence System.<br>
    Thomas Cook Travel Security · Do not reply to this email.
  </div>

</div>
</body>
</html>
"""

    # ── Plain text fallback ──────────────────────────────
    plain = f"""
HONEYPOT ALERT — {entry.get('risk_level')} RISK

Attack Type : {entry.get('attack_type')}
Risk Score  : {entry.get('risk_score')}/10
IP Address  : {entry.get('ip')}
Country     : {entry.get('country')}
City        : {entry.get('city')}
Browser     : {entry.get('browser')}
OS          : {entry.get('operating_system')}
Endpoint    : {entry.get('endpoint')}
Username    : {entry.get('username')}
Payload     : {entry.get('payload','')[:100]}
Time        : {entry.get('timestamp')}
""".strip()

    # ── Send email ───────────────────────────────────────
    try:
        def _safe(val):
            """Strip newlines to prevent email header injection."""
            return str(val or '').replace('\r', '').replace('\n', '')

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"🔴 [{_safe(entry.get('risk_level'))}] Honeypot Alert — {_safe(entry.get('attack_type'))} from {_safe(entry.get('ip'))}"
        msg["From"]    = EMAIL_SENDER
        msg["To"]      = EMAIL_RECEIVER

        msg.attach(MIMEText(plain, "plain"))
        msg.attach(MIMEText(html,  "html"))

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())

        print(f"[Email] ✅ Alert sent to {EMAIL_RECEIVER}")

    except Exception as e:
        print(f"[Email] ❌ Failed: {e}")
