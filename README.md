# 🛡️ Intelligent Honeypot as a Service

A production-grade cybersecurity honeypot with real-time attack detection, geolocation tracking, risk scoring, and live analytics dashboard.

---

## 🧠 Intelligence Features

| Feature | Description |
|---|---|
| Attack Detection | SQL Injection, XSS, Command Injection, Path Traversal, Brute Force, Recon |
| Geo-IP Tracking | Country, city, ISP via ip-api.com |
| Risk Scoring | Score 1–10, levels: LOW / MEDIUM / HIGH |
| Behavior Analysis | Brute force tracking, multi-endpoint recon detection |
| Real-time Alerts | Telegram bot notifications for HIGH risk attacks |
| Live Dashboard | Chart.js analytics with auto-refresh every 10 seconds |

---

## 📁 Project Structure

```
honeypot-project/
├── app/
│   ├── app.py           ← Flask server + route handlers
│   ├── intelligence.py  ← Attack detection engine (regex patterns)
│   ├── logger.py        ← File + MongoDB logging + analytics queries
│   ├── geoip.py         ← IP geolocation lookup
│   └── alerts.py        ← Telegram alert sender
├── templates/
│   ├── login.html       ← Fake admin login (honeypot trap)
│   └── dashboard.html   ← Attack analytics dashboard
├── logs/
│   └── attack.log       ← JSON log file (auto-created)
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── .env.example
```

---

## ⚡ Quick Start (Local)

### 1. Clone and install
```bash
git clone https://github.com/yourteam/honeypot-project
cd honeypot-project
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure environment
```bash
cp .env.example .env
# Edit .env with your MongoDB URI and Telegram tokens
```

### 3. Run
```bash
cd app
python app.py
```

Open browser:
- Honeypot: http://localhost:5000
- Dashboard: http://localhost:5000/dashboard

---

## 🐳 Docker (Recommended)

```bash
# Build and run
docker-compose up --build -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

---

## ☁️ AWS Deployment

### Step 1: Launch EC2
- Instance: t2.micro (Free tier)
- OS: Ubuntu 22.04
- Storage: 20GB
- Security group ports: 22, 80, 5000

### Step 2: SSH & setup
```bash
ssh -i "your-key.pem" ubuntu@YOUR_EC2_IP
sudo apt update && sudo apt install docker.io docker-compose -y
sudo systemctl start docker
sudo usermod -aG docker ubuntu
```

### Step 3: Deploy
```bash
git clone https://github.com/yourteam/honeypot-project
cd honeypot-project
cp .env.example .env
nano .env   # Fill in your values

docker-compose up --build -d
```

Your honeypot is live at: **http://YOUR_EC2_IP**
Dashboard at: **http://YOUR_EC2_IP/dashboard**

---

## 🤖 Telegram Alert Setup

1. Open Telegram → search `@BotFather`
2. Send `/newbot` → follow steps → copy token
3. Open `@userinfobot` → copy your Chat ID
4. Add both to your `.env` file

---

## 🧪 Test Attacks

### SQL Injection
```
Username: admin' OR 1=1 --
Password: anything
```

### XSS
```
Username: <script>alert('xss')</script>
Password: test
```

### Path Traversal
```
Username: ../../../../etc/passwd
Password: test
```

### Command Injection
```
Username: admin; ls -la
Password: test
```

### Brute Force
Submit login 5+ times in under 1 minute.

---

## 📊 Dashboard Panels

| Panel | Shows |
|---|---|
| Total Attacks | Live counter |
| High Risk | Critical threats count |
| SQL Injections | Most common attack |
| Countries | Unique origins |
| Timeline | Attacks per hour (24h) |
| Attack Types | Donut chart distribution |
| Top IPs | Most active attackers |
| Risk Levels | HIGH/MEDIUM/LOW breakdown |
| Live Feed | Most recent 20 attacks |
| Countries List | Geographic distribution |

---

## 🏗️ System Architecture

![IHaaS System Architecture](IHaaS%20System%20Architecture%20Diagram.jpg)

> *Fig. 1. IHaaS System Architecture Diagram*


