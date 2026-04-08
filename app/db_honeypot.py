import socket
import threading
import struct
import json
import time
import os

# ── Fake MongoDB responses ────────────────────────────────
# Real MongoDB speaks BSON over TCP port 27017
# We fake just enough to fool scanners and basic mongo clients

FAKE_DATABASES = ["thomascook_prod", "thomascook_customers", "thomascook_payments", "admin", "local"]

FAKE_COLLECTIONS = {
    "thomascook_prod": ["users", "bookings", "config", "sessions", "logs"],
    "thomascook_customers": ["profiles", "passports", "payment_methods", "travel_history"],
    "thomascook_payments": ["transactions", "refunds", "cards", "invoices"],
    "admin": ["system.users", "system.roles"],
}

# ── IMPORTANT: All data below is entirely SYNTHETIC / FAKE ───────────────────
# These are honeypot decoy records designed to deceive and engage attackers.
# Card numbers use the Luhn-valid test ranges (no real accounts); hashed
# passwords are MD5 of well-known test strings; credentials are fabricated.
# None of this data belongs to any real person or organisation.
FAKE_DOCUMENTS = {
    "users": [
        {"_id": "1", "username": "admin", "password": "e10adc3949ba59abbe56e057f20f883e", "role": "superadmin", "email": "admin@thomascook.com"},
        {"_id": "2", "username": "ops_manager", "password": "5f4dcc3b5aa765d61d8327deb882cf99", "role": "admin", "email": "ops@thomascook.com"},
        {"_id": "3", "username": "finance", "password": "d8578edf8458ce06fbc5bb76a58c5ca4", "role": "manager", "email": "finance@thomascook.com"},
    ],
    "cards": [
        # Synthetic Luhn-valid test card numbers — NOT real payment data
        {"_id": "1", "customer_id": "CUS10021", "card_number": "4532015112830366", "expiry": "12/27", "cvv": "123", "type": "VISA"},
        {"_id": "2", "customer_id": "CUS10022", "card_number": "5425233430109903", "expiry": "09/26", "cvv": "456", "type": "Mastercard"},
    ],
    "config": [
        {"_id": "1", "key": "db_password", "value": "Tc@Admin#2026!Secure"},
        {"_id": "2", "key": "aws_secret", "value": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
        {"_id": "3", "key": "stripe_secret", "value": "sk_live_EXAMPLESECRET456789"},
    ],
}



def build_fake_mongo_response(request_data: bytes, client_ip: str) -> tuple:
    """
    Parse incoming MongoDB wire protocol and return fake response.
    Returns (response_bytes, detected_action)
    """
    try:
        # MongoDB wire protocol header is 16 bytes
        if len(request_data) < 16:
            return b"", "unknown"

        # Parse header
        msg_length  = struct.unpack_from("<i", request_data, 0)[0]
        request_id  = struct.unpack_from("<i", request_data, 4)[0]
        response_to = struct.unpack_from("<i", request_data, 8)[0]
        op_code     = struct.unpack_from("<i", request_data, 12)[0]

        # Try to extract readable text from request
        try:
            readable = request_data[16:].decode("utf-8", errors="ignore")
        except:
            readable = ""

        # Detect what attacker is doing
        action = "MongoDB Probe"
        if "listDatabases" in readable:
            action = "MongoDB List Databases"
        elif "listCollections" in readable:
            action = "MongoDB List Collections"
        elif "find" in readable or "query" in readable:
            action = "MongoDB Data Dump Attempt"
        elif "insert" in readable:
            action = "MongoDB Insert Attempt"
        elif "drop" in readable:
            action = "MongoDB Drop Attempt"
        elif "createUser" in readable or "addUser" in readable:
            action = "MongoDB Create User Attempt"
        elif "isMaster" in readable or "ismaster" in readable:
            action = "MongoDB Handshake"
        elif "serverStatus" in readable:
            action = "MongoDB Server Recon"

        # Build fake isMaster response (makes client think it connected successfully)
        fake_response = build_ismaster_response(request_id)
        return fake_response, action, readable[:200]

    except Exception as e:
        return b"", "parse_error", ""


def build_ismaster_response(request_id: int) -> bytes:
    """Build a fake MongoDB isMaster response."""
    # Fake BSON document response
    doc = {
        "ismaster": True,
        "maxBsonObjectSize": 16777216,
        "maxMessageSizeBytes": 48000000,
        "maxWriteBatchSize": 100000,
        "localTime": {"$date": int(time.time() * 1000)},
        "minWireVersion": 0,
        "maxWireVersion": 17,
        "readOnly": False,
        "ok": 1.0,
        "version": "6.0.4",
        "gitVersion": "44ff6d4c01674e4e5b76f20d5a1ef8cba7c3a8e4",
    }

    # Simple fake BSON encoding (just enough to not crash client)
    doc_str = json.dumps(doc).encode()

    # MongoDB OP_REPLY header
    response_to = request_id
    op_reply    = 1  # OP_REPLY
    flags       = 0
    cursor_id   = 0
    start_from  = 0
    num_returned= 1

    header = struct.pack("<iiii", 0, 1, response_to, op_reply)
    body   = struct.pack("<iqii", flags, cursor_id, start_from, num_returned)
    msg    = header + body + doc_str

    # Fix message length in header
    length = len(msg) + 4
    msg    = struct.pack("<i", length) + msg[4:]

    return msg


def handle_db_client(client_socket, client_ip, logger):
    """Handle a single fake MongoDB connection."""
    print(f"[DB Honeypot] Connection from {client_ip}")

    try:
        client_socket.settimeout(30)
        interaction_count = 0

        while interaction_count < 20:
            try:
                data = client_socket.recv(4096)
                if not data:
                    break

                interaction_count += 1

                # Build response and detect action
                response, action, readable = build_fake_mongo_response(
                    data, client_ip
                )

                print(f"[DB Honeypot] {client_ip} — {action}")
                if readable:
                    print(f"[DB Honeypot] Raw: {readable[:100]}")

                # Log to main logger
                try:
                    from geoip import get_location
                    location = get_location(client_ip)
                except:
                    location = {}

                entry = {
                    "ip":               client_ip,
                    "username":         "mongodb_client",
                    "password":         "",
                    "payload":          f"{action}: {readable[:150]}",
                    "user_agent":       "MongoDB Client",
                    "browser":          "MongoDB",
                    "operating_system": "Unknown",
                    "referrer":         "Direct",
                    "origin":           "MongoDB",
                    "x_forwarded_for":  "None",
                    "accept_language":  "N/A",
                    "endpoint":         "/mongodb",
                    "attack_type":      action,
                    "risk_score":       9,
                    "risk_level":       "HIGH",
                    "honeypot_type":    "DATABASE",
                    "country":          location.get("country",  "Unknown"),
                    "city":             location.get("city",     "Unknown"),
                    "isp":              location.get("isp",      "Unknown"),
                    "lat":              location.get("lat",      0),
                    "lon":              location.get("lon",      0),
                }
                logger.log(entry)

                # Send Telegram + Email alert for first interaction only
                if interaction_count == 1:
                    try:
                        import sys, os
                        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
                        from alerts import send_alert
                        from email_alert import send_email_alert
                        send_alert(entry)
                        send_email_alert(entry)
                        print(f"[DB Honeypot] Alerts sent for {client_ip}")
                    except Exception as alert_err:
                        print(f"[DB Honeypot] Alert error: {alert_err}")

                # Send fake response
                if response:
                    client_socket.send(response)

            except socket.timeout:
                break
            except Exception as e:
                print(f"[DB Honeypot] Error reading from {client_ip}: {e}")
                break

    except Exception as e:
        print(f"[DB Honeypot] Connection error from {client_ip}: {e}")
    finally:
        try:
            client_socket.close()
        except:
            pass


def start_db_honeypot(logger, host="0.0.0.0", port=27017):
    """Start the fake MongoDB honeypot."""
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server_socket.bind((host, port))
        except PermissionError:
            # Port 27017 needs root — try 27117 instead
            port = 27117
            server_socket.bind((host, port))
            print(f"[DB Honeypot] Port 27017 needs root — using {port} instead")

        server_socket.listen(100)
        print(f"[DB Honeypot] 🗄️  Listening on port {port}...")

        while True:
            try:
                client_socket, addr = server_socket.accept()
                client_ip = addr[0]

                thread = threading.Thread(
                    target=handle_db_client,
                    args=(client_socket, client_ip, logger),
                    daemon=True
                )
                thread.start()

            except Exception as e:
                print(f"[DB Honeypot] Accept error: {e}")

    except Exception as e:
        print(f"[DB Honeypot] Failed to start on port {port}: {e}")
