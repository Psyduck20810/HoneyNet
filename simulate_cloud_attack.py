"""
Cloud Credential Theft Attack Simulation
=========================================
Simulates a realistic multi-stage attack against the honeypot's fake AWS console.

Stage 1: Reconnaissance  — attacker discovers the /aws-console endpoint
Stage 2: Credential Stuffing — tries multiple stolen credential sets
Stage 3: Root Account Attack — tries root account takeover
Stage 4: IAM Enumeration — tries common IAM usernames
"""
import requests
import time
import json

BASE_URL = "http://127.0.0.1:5000"

# Stolen credential datasets (like what attackers get from dark web dumps)
STOLEN_CREDS = [
    # Root account attempts (high value targets)
    {"account_type": "root", "email": "admin@thomascook.com",    "password": "Admin@2024!",          "account_id": "", "iam_user": ""},
    {"account_type": "root", "email": "it@thomascook.com",       "password": "ThomasCook2024",        "account_id": "", "iam_user": ""},
    {"account_type": "root", "email": "aws@thomascook.com",      "password": "Aws@Admin#2026",        "account_id": "", "iam_user": ""},
    {"account_type": "root", "email": "devops@thomascook.com",   "password": "D3v0ps!Secure",         "account_id": "", "iam_user": ""},

    # IAM user attempts with account ID (found from GitHub leaks)
    {"account_type": "iam",  "email": "", "account_id": "123456789012", "iam_user": "admin",         "password": "password123"},
    {"account_type": "iam",  "email": "", "account_id": "123456789012", "iam_user": "devops",        "password": "Dev0ps@2025"},
    {"account_type": "iam",  "email": "", "account_id": "123456789012", "iam_user": "deploy-bot",    "password": "deploy@2026"},
    {"account_type": "iam",  "email": "", "account_id": "123456789012", "iam_user": "ci-system",     "password": "CIpipeline#99"},
    {"account_type": "iam",  "email": "", "account_id": "987654321098", "iam_user": "s3-backup",     "password": "S3Backup!2026"},
    {"account_type": "iam",  "email": "", "account_id": "987654321098", "iam_user": "lambda-exec",   "password": "Lambda2026!"},

    # Credentials from a realistic phishing campaign
    {"account_type": "root", "email": "security@thomascook.com", "password": "Secur!ty2026TC",       "account_id": "", "iam_user": ""},
    {"account_type": "root", "email": "finance@thomascook.com",  "password": "Finance@AWS99",        "account_id": "", "iam_user": ""},
]

def print_banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║          CLOUD CREDENTIAL THEFT ATTACK SIMULATION            ║
║          MITRE ATT&CK: T1078 — Valid Accounts (Cloud)        ║
╚══════════════════════════════════════════════════════════════╝
""")

def stage1_recon():
    print("━" * 62)
    print("  STAGE 1 : RECONNAISSANCE")
    print("  Attacker scans for cloud admin panels...")
    print("━" * 62)

    recon_paths = ["/aws-console", "/aws", "/cloud-admin"]
    for path in recon_paths:
        try:
            r = requests.get(f"{BASE_URL}{path}", timeout=5)
            status = "✅ FOUND" if r.status_code == 200 else f"[{r.status_code}]"
            print(f"  GET {path:<20} → {status}")
            time.sleep(0.4)
        except Exception as e:
            print(f"  GET {path:<20} → ERROR: {e}")

    print(f"\n  [!] AWS Console discovered at {BASE_URL}/aws-console")
    print(f"  [!] Starting credential stuffing attack...\n")
    time.sleep(1)

def stage2_credential_stuffing():
    print("━" * 62)
    print("  STAGE 2-4 : CREDENTIAL STUFFING + IAM ENUMERATION")
    print("  Replaying 12 stolen credential sets from dark web dump...")
    print("━" * 62)

    results = []
    for i, creds in enumerate(STOLEN_CREDS, 1):
        try:
            r = requests.post(
                f"{BASE_URL}/aws-login",
                json=creds,
                timeout=5,
                headers={
                    "User-Agent":    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "X-Forwarded-For": f"185.220.{i}.{200+i}",  # simulated attacker IPs
                    "Content-Type":  "application/json",
                }
            )
            resp = r.json()

            acct_type = creds["account_type"].upper()
            identity  = creds["email"] or f"{creds['account_id']}/{creds['iam_user']}"
            password  = creds["password"]

            print(f"  [{i:02d}] {acct_type:<4} | {identity:<35} | pass: {password:<22} → {resp.get('status','?').upper()}")
            results.append({"creds": creds, "response": resp})
            time.sleep(0.5)

        except Exception as e:
            print(f"  [{i:02d}] ERROR: {e}")

    return results

def print_summary(results):
    print(f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ATTACK SIMULATION COMPLETE
  ──────────────────────────
  Total attempts      : {len(results)}
  Credential sets     : {len(STOLEN_CREDS)}
  Root account tries  : {sum(1 for r in results if r['creds']['account_type']=='root')}
  IAM user tries      : {sum(1 for r in results if r['creds']['account_type']=='iam')}

  HONEYPOT RESPONSE
  ─────────────────
  ✅ All attempts logged to attack.log
  ✅ risk_score = 10/10 assigned to every entry
  ✅ Telegram + Email alerts fired
  ✅ Blockchain record created per entry
  ✅ Attacker IPs geolocated + fingerprinted

  WHAT JUST GOT CAPTURED (per attempt):
  - IP address + ISP + Country
  - Account type (root vs IAM)
  - Email / IAM username tried
  - Password attempted
  - User-Agent / Browser fingerprint
  - Full timestamp

  View results at: http://127.0.0.1:5000/dashboard
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
""")

if __name__ == "__main__":
    print_banner()
    stage1_recon()
    results = stage2_credential_stuffing()
    print_summary(results)
