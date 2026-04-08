import os
import requests
from utils import load_env

load_env()

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID   = os.environ.get("TELEGRAM_CHAT_ID", "")


def send_alert(entry: dict):
    """Send a Telegram alert for high-risk attacks."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("[Alert] Telegram not configured — skipping alert.")
        return

    risk_emoji = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}.get(
        entry.get("risk_level", "LOW"), "⚪"
    )

    message = f"""
{risk_emoji} *HONEYPOT ALERT — {entry.get('risk_level', 'UNKNOWN')} RISK*

🎯 *Attack Type:* `{entry.get('attack_type', 'Unknown')}`
⚡ *Risk Score:* `{entry.get('risk_score', 0)}/10`

🌍 *IP Address:* `{entry.get('ip', 'Unknown')}`
📍 *Location:* {entry.get('city', '?')}, {entry.get('country', '?')}
🏢 *ISP:* {entry.get('isp', 'Unknown')}

🖥 *OS:* {entry.get('operating_system', 'Unknown')}
🌐 *Browser:* {entry.get('browser', 'Unknown')}
🔗 *Endpoint:* `{entry.get('endpoint', '/')}`
📎 *Referrer:* {entry.get('referrer', 'Direct')}

👤 *Username tried:* `{entry.get('username', '-')}`
💉 *Payload:* `{entry.get('payload', '-')[:100]}`
🕐 *Time:* {entry.get('timestamp', 'Unknown')}
""".strip()

    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        response = requests.post(url, json={
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "Markdown"
        }, timeout=5)
        result = response.json()
        if result.get("ok"):
            print(f"[Alert] ✅ Telegram alert sent for {entry.get('attack_type')}")
        else:
            print(f"[Alert] ❌ Telegram error: {result}")
    except Exception as e:
        print(f"[Alert] Failed: {e}")
