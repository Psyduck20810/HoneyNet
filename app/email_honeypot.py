import asyncio
import logging
import os
import sys
import time
import threading
from aiosmtpd.controller import Controller

# ── Suppress aiosmtpd logs ────────────────────────────────
logging.getLogger("mail.log").setLevel(logging.CRITICAL)
logging.getLogger("aiosmtpd").setLevel(logging.CRITICAL)

# ── Fake email addresses planted on website ───────────────
HONEYPOT_EMAILS = [
    "admin@thomascook-internal.com",
    "backup@thomascook-internal.com",
    "noreply@thomascook-internal.com",
    "security@thomascook-internal.com",
    "hr@thomascook-internal.com",
]

# ── Spam/Phishing keywords ────────────────────────────────
PHISHING_KEYWORDS = [
    "click here", "verify your account", "confirm your password",
    "urgent", "suspended", "limited time", "act now",
    "congratulations you won", "free money", "bank account",
    "credit card", "social security", "bitcoin", "crypto",
    "wire transfer", "western union", "lottery", "inheritance",
    "nigerian prince", "million dollars", "100% free",
]

SPAM_KEYWORDS = [
    "unsubscribe", "opt out", "bulk mail", "mass email",
    "marketing", "advertisement", "promotion", "discount",
    "sale", "offer expires", "limited offer",
]


def detect_email_type(subject: str, content: str) -> tuple:
    """Detect if email is phishing, spam, or unknown."""
    text = (subject + " " + content).lower()

    phishing_hits = [k for k in PHISHING_KEYWORDS if k in text]
    spam_hits     = [k for k in SPAM_KEYWORDS if k in text]

    if phishing_hits:
        return "Phishing Email", 10, "HIGH", phishing_hits
    elif spam_hits:
        return "Spam Email", 6, "MEDIUM", spam_hits
    else:
        return "Suspicious Email", 7, "HIGH", []


class HoneypotEmailHandler:
    """Handle incoming emails to the honeypot."""

    def __init__(self, logger):
        self.logger = logger

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        """Accept all incoming emails."""
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        """Process received email."""
        try:
            # Extract email details
            mail_from   = envelope.mail_from or "unknown@unknown.com"
            rcpt_tos    = envelope.rcpt_tos or []
            raw_content = envelope.content

            # Decode content
            if isinstance(raw_content, bytes):
                content = raw_content.decode("utf-8", errors="ignore")
            else:
                content = str(raw_content)

            # Extract subject
            subject = "No Subject"
            for line in content.split("\n"):
                if line.lower().startswith("subject:"):
                    subject = line[8:].strip()
                    break

            # Extract sender IP from session
            peer = session.peer
            sender_ip = peer[0] if peer else "Unknown"

            print(f"[Email Honeypot] 📧 Email from {mail_from} ({sender_ip})")
            print(f"[Email Honeypot] Subject: {subject}")
            print(f"[Email Honeypot] To: {', '.join(rcpt_tos)}")

            # Detect email type
            attack_type, risk_score, risk_level, keywords = detect_email_type(
                subject, content
            )

            print(f"[Email Honeypot] Type: {attack_type} — {risk_level}")

            # Get geolocation
            try:
                from geoip import get_location
                location = get_location(sender_ip)
            except:
                location = {}

            # Build log entry
            entry = {
                "ip":               sender_ip,
                "username":         mail_from,
                "password":         "",
                "payload":          f"Subject: {subject} | From: {mail_from} | Keywords: {keywords[:3]}",
                "user_agent":       "Email Client",
                "browser":          "SMTP",
                "operating_system": "Unknown",
                "referrer":         "Email",
                "origin":           "SMTP",
                "x_forwarded_for":  "None",
                "accept_language":  "N/A",
                "endpoint":         "/email",
                "attack_type":      attack_type,
                "risk_score":       risk_score,
                "risk_level":       risk_level,
                "honeypot_type":    "EMAIL",
                "email_from":       mail_from,
                "email_to":         ", ".join(rcpt_tos),
                "email_subject":    subject,
                "country":          location.get("country",  "Unknown"),
                "city":             location.get("city",     "Unknown"),
                "isp":              location.get("isp",      "Unknown"),
                "lat":              location.get("lat",      0),
                "lon":              location.get("lon",      0),
            }

            self.logger.log(entry)

            # Send Telegram + Email alert
            try:
                import sys, os
                sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
                from alerts import send_alert
                from email_alert import send_email_alert
                send_alert(entry)
                send_email_alert(entry)
                print(f"[Email Honeypot] Alerts sent!")
            except Exception as e:
                print(f"[Email Honeypot] Alert error: {e}")

        except Exception as e:
            print(f"[Email Honeypot] Error processing email: {e}")

        return "250 Message accepted for delivery"


def start_email_honeypot(logger, host="0.0.0.0", port=2525):
    """Start the fake SMTP honeypot server."""

    async def run():
        handler    = HoneypotEmailHandler(logger)
        controller = Controller(
            handler,
            hostname=host,
            port=port,
        )
        controller.start()
        print(f"[Email Honeypot] 📧 Listening on port {port}...")

        # Keep running forever
        try:
            while True:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            controller.stop()

    try:
        # Run in new event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(run())
    except Exception as e:
        print(f"[Email Honeypot] Failed to start: {e}")
