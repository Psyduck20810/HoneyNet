import socket
import threading
import paramiko
import logging
import os
import sys
import time

# ── Suppress paramiko internal logs ──────────────────────
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

# ── Path to host key ──────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
HOST_KEY_PATH = os.path.join(BASE_DIR, "ssh_host_key")

# ── Fake SSH banner (looks like real Ubuntu server) ───────
SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"

# ── Load host key ─────────────────────────────────────────
try:
    HOST_KEY = paramiko.RSAKey(filename=HOST_KEY_PATH)
    print("[SSH Honeypot] Host key loaded successfully")
except Exception as e:
    print(f"[SSH Honeypot] ERROR loading host key: {e}")
    HOST_KEY = paramiko.RSAKey.generate(2048)


class SSHHoneypotInterface(paramiko.ServerInterface):
    """Fake SSH server that accepts everything and logs it all."""

    def __init__(self, client_ip, logger):
        self.client_ip      = client_ip
        self.logger         = logger
        self.username       = ""
        self.password       = ""
        self.event          = threading.Event()
        self.auth_attempts  = 0

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        """Log every login attempt."""
        self.auth_attempts += 1
        self.username = username
        self.password = password

        print(f"[SSH] Login attempt from {self.client_ip} — {username}:{password}")

        # Log to main logger
        try:
            from geoip import get_location
            location = get_location(self.client_ip)
        except:
            location = {}

        entry = {
            "ip":               self.client_ip,
            "username":         username,
            "password":         password,
            "payload":          f"SSH login attempt: {username}:{password}",
            "user_agent":       "SSH Client",
            "browser":          "SSH",
            "operating_system": "Unknown",
            "referrer":         "Direct",
            "origin":           "SSH",
            "x_forwarded_for":  "None",
            "accept_language":  "N/A",
            "endpoint":         "/ssh",
            "attack_type":      "SSH Brute Force",
            "risk_score":       8,
            "risk_level":       "HIGH",
            "honeypot_type":    "SSH",
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
            print(f"[SSH Honeypot] Alerts sent for {client_ip}")
        except Exception as e:
            print(f"[SSH Honeypot] Alert error: {e}")

        # Accept on 2nd attempt to make attacker think they succeeded
        if self.auth_attempts >= 2:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_FAILED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height,
                                   pixelwidth, pixelheight, modes):
        return True

    def get_banner(self):
        return ("Welcome to Thomas Cook Travel Server\r\n"
                "Authorized access only. All sessions are monitored.\r\n", "en-US")


def handle_ssh_client(client_socket, client_ip, logger):
    """Handle a single SSH connection."""
    transport = None
    try:
        transport = paramiko.Transport(client_socket)
        transport.local_version = SSH_BANNER
        transport.add_server_key(HOST_KEY)

        server = SSHHoneypotInterface(client_ip, logger)

        try:
            transport.start_server(server=server)
        except paramiko.SSHException:
            return

        # Wait for auth
        channel = transport.accept(30)
        if channel is None:
            return

        # Wait for shell
        server.event.wait(10)

        # Show fake shell prompt
        channel.send(b"\r\n")
        channel.send(b"Last login: Mon Mar 10 09:23:41 2026 from 10.0.0.1\r\n")
        channel.send(b"\r\n")
        channel.send(b"tc-prod-server:~$ ")

        # Log commands the attacker types
        command_buffer = b""
        channel.settimeout(60)

        while True:
            try:
                data = channel.recv(1024)
                if not data:
                    break

                # Echo back what they type
                channel.send(data)
                command_buffer += data

                # When they press Enter
                if b"\r" in data or b"\n" in data:
                    command = command_buffer.strip().decode("utf-8", errors="ignore")
                    command_buffer = b""

                    if command:
                        print(f"[SSH] Command from {client_ip}: {command}")

                        # Log the command
                        try:
                            from geoip import get_location
                            location = get_location(client_ip)
                        except:
                            location = {}

                        cmd_entry = {
                            "ip":               client_ip,
                            "username":         server.username,
                            "password":         server.password,
                            "payload":          f"SSH command: {command}",
                            "user_agent":       "SSH Client",
                            "browser":          "SSH",
                            "operating_system": "Unknown",
                            "referrer":         "Direct",
                            "origin":           "SSH",
                            "x_forwarded_for":  "None",
                            "accept_language":  "N/A",
                            "endpoint":         "/ssh/command",
                            "attack_type":      "SSH Command Execution",
                            "risk_score":       10,
                            "risk_level":       "HIGH",
                            "honeypot_type":    "SSH",
                            "country":          location.get("country",  "Unknown"),
                            "city":             location.get("city",     "Unknown"),
                            "isp":              location.get("isp",      "Unknown"),
                            "lat":              location.get("lat",      0),
                            "lon":              location.get("lon",      0),
                        }
                        logger.log(cmd_entry)

                        # Send fake responses
                        response = get_fake_response(command)
                        channel.send(response.encode())
                        channel.send(b"tc-prod-server:~$ ")

            except socket.timeout:
                break
            except Exception:
                break

    except Exception as e:
        print(f"[SSH Honeypot] Connection error from {client_ip}: {e}")
    finally:
        try:
            if transport:
                transport.close()
            client_socket.close()
        except:
            pass


def get_fake_response(command: str) -> str:
    """Return convincing fake responses to attacker commands."""
    command = command.lower().strip()

    responses = {
        "whoami":       "root\r\n",
        "id":           "uid=0(root) gid=0(root) groups=0(root)\r\n",
        "pwd":          "/root\r\n",
        "hostname":     "tc-prod-server-01\r\n",
        "uname -a":     "Linux tc-prod-server-01 5.15.0-1034-aws #38-Ubuntu SMP Mon Mar 20 15:41:27 UTC 2026 x86_64 GNU/Linux\r\n",
        "ls":           "backup  config  data  logs  scripts  www\r\n",
        "ls -la":       "total 48\r\ndrwx------ 8 root root 4096 Mar 10 02:00 .\r\ndrwxr-xr-x 20 root root 4096 Mar  1 12:00 ..\r\ndrwxr-xr-x 3 root root 4096 Mar 10 02:00 backup\r\ndrwxr-xr-x 2 root root 4096 Mar  9 18:30 config\r\ndrwxr-xr-x 4 root root 4096 Mar 10 01:00 data\r\ndrwxr-xr-x 2 root root 4096 Mar  8 10:00 logs\r\n-rw-r--r-- 1 root root  220 Mar  1 12:00 .bash_logout\r\n-rw-r--r-- 1 root root 3526 Mar  1 12:00 .bashrc\r\n",
        "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\ntc_admin:x:1000:1000:Thomas Cook Admin:/home/tc_admin:/bin/bash\n",
        "ifconfig":     "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255\n        inet6 fe80::1  prefixlen 64  scopeid 0x20<link>\n",
        "ip a":         "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n    inet 127.0.0.1/8 scope host lo\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n    inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0\n",
        "ps aux":       "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot         1  0.0  0.1  22544  1024 ?        Ss   Mar01   0:01 /sbin/init\nroot       423  0.0  0.2  72296  2048 ?        Ss   Mar01   0:00 /usr/sbin/sshd\nmysql      891  0.1  2.5 983040 25600 ?        Ssl  Mar01   1:23 /usr/sbin/mysqld\nroot      1234  0.0  0.8 123456  8192 ?        Ss   Mar01   0:12 python3 app.py\n",
        "netstat -an":  "Active Internet connections\nProto  Local Address     Foreign Address  State\ntcp    0.0.0.0:22        0.0.0.0:*        LISTEN\ntcp    0.0.0.0:80        0.0.0.0:*        LISTEN\ntcp    0.0.0.0:3306      0.0.0.0:*        LISTEN\ntcp    0.0.0.0:27017     0.0.0.0:*        LISTEN\n",
        "env":          "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nDB_PASS=Tc@Admin#2026!Secure\nAWS_KEY=AKIAIOSFODNN7EXAMPLE\nSECRET_KEY=tc_internal_2026_SECRETKEY_xyz789\nHOME=/root\nUSER=root\n",
        "history":      "    1  apt update\n    2  mysql -u root -p\n    3  cd /var/www/html\n    4  nano config/database.php\n    5  systemctl restart apache2\n    6  tar -czf backup/db_backup.tar.gz /var/lib/mysql\n",
        "exit":         "\r\nlogout\r\n",
        "clear":        "\033[2J\033[H",
    }

    # Check exact match
    if command in responses:
        return responses[command] + "\r\n"

    # Partial matches
    if command.startswith("cd "):
        return "\r\n"
    if command.startswith("cat "):
        return f"-bash: {command.split()[-1]}: Permission denied\r\n"
    if command.startswith("wget ") or command.startswith("curl "):
        return f"--2026-03-10 10:23:41-- Connecting... Connection refused\r\n"
    if command.startswith("sudo "):
        return f"[sudo] password for root: Sorry, try again.\r\n"
    if "python" in command or "perl" in command or "bash" in command:
        return f"-bash: restricted: cannot execute scripts\r\n"

    # Default
    return f"-bash: {command}: command not found\r\n"


def start_ssh_honeypot(logger, host="0.0.0.0", port=2222):
    """Start the SSH honeypot server."""
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        server_socket.listen(100)

        print(f"[SSH Honeypot] 🔌 Listening on port {port}...")

        while True:
            try:
                client_socket, addr = server_socket.accept()
                client_ip = addr[0]
                print(f"[SSH Honeypot] Connection from {client_ip}")

                thread = threading.Thread(
                    target=handle_ssh_client,
                    args=(client_socket, client_ip, logger),
                    daemon=True
                )
                thread.start()

            except Exception as e:
                print(f"[SSH Honeypot] Accept error: {e}")

    except Exception as e:
        print(f"[SSH Honeypot] Failed to start: {e}")
