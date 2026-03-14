import os
import io
import csv
import json
import zipfile
import datetime

def generate_decoy_zip() -> bytes:
    """Generate a convincing fake ZIP file with multiple decoy files."""

    zip_buffer = io.BytesIO()

    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:

        # ── File 1: Employee CSV ─────────────────────────
        employees_csv = generate_employees_csv()
        zf.writestr("thomascook_employees_2026.csv", employees_csv)

        # ── File 2: Database config ──────────────────────
        db_config = generate_db_config()
        zf.writestr("config/database.php", db_config)

        # ── File 3: API keys file ────────────────────────
        api_keys = generate_api_keys()
        zf.writestr("config/api_keys.env", api_keys)

        # ── File 4: Customer data CSV ────────────────────
        customers_csv = generate_customers_csv()
        zf.writestr("exports/customers_march_2026.csv", customers_csv)

        # ── File 5: Financial data ───────────────────────
        financial = generate_financial_data()
        zf.writestr("exports/financial_summary_Q1_2026.csv", financial)

        # ── File 6: Fake SQL dump ────────────────────────
        sql_dump = generate_sql_dump()
        zf.writestr("backup/thomascook_db_partial.sql", sql_dump)

        # ── File 7: README to make it look legit ─────────
        readme = generate_readme()
        zf.writestr("README.txt", readme)

    zip_buffer.seek(0)
    return zip_buffer.read()


def generate_employees_csv() -> str:
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Employee ID", "Full Name", "Email", "Department",
        "Role", "Salary (INR)", "Phone", "Join Date",
        "Manager", "Access Level"
    ])

    employees = [
        ["TC001", "Rajesh Kumar",    "r.kumar@thomascook.com",    "IT Security",    "CISO",              "45,00,000", "+91-9876543210", "2018-03-15", "CEO",           "ADMIN"],
        ["TC002", "Priya Sharma",    "p.sharma@thomascook.com",   "Finance",         "CFO",               "42,00,000", "+91-9823456781", "2017-06-01", "CEO",           "ADMIN"],
        ["TC003", "Amit Patel",      "a.patel@thomascook.com",    "Operations",      "Head of Ops",       "28,00,000", "+91-9712345678", "2019-01-10", "COO",           "LEVEL3"],
        ["TC004", "Sneha Reddy",     "s.reddy@thomascook.com",    "IT",              "Database Admin",    "22,00,000", "+91-9634567890", "2020-05-20", "TC001",         "LEVEL3"],
        ["TC005", "Vikram Singh",    "v.singh@thomascook.com",    "Finance",         "Senior Accountant", "18,00,000", "+91-9556789012", "2019-08-15", "TC002",         "LEVEL2"],
        ["TC006", "Neha Gupta",      "n.gupta@thomascook.com",    "HR",              "HR Manager",        "16,00,000", "+91-9445678901", "2018-11-01", "COO",           "LEVEL2"],
        ["TC007", "Rohit Verma",     "r.verma@thomascook.com",    "IT",              "Network Engineer",  "14,00,000", "+91-9334567890", "2021-02-28", "TC001",         "LEVEL2"],
        ["TC008", "Kavya Nair",      "k.nair@thomascook.com",     "Sales",           "Sales Manager",     "20,00,000", "+91-9223456789", "2019-07-14", "COO",           "LEVEL2"],
        ["TC009", "Arjun Mehta",     "a.mehta@thomascook.com",    "IT",              "DevOps Engineer",   "15,00,000", "+91-9112345678", "2022-01-10", "TC001",         "LEVEL1"],
        ["TC010", "Divya Pillai",    "d.pillai@thomascook.com",   "Finance",         "Financial Analyst", "12,00,000", "+91-9001234567", "2021-09-15", "TC002",         "LEVEL1"],
        ["TC011", "Suresh Babu",     "s.babu@thomascook.com",     "IT",              "System Admin",      "13,00,000", "+91-8990123456", "2020-12-01", "TC001",         "LEVEL2"],
        ["TC012", "Anita Joshi",     "a.joshi@thomascook.com",    "Marketing",       "Marketing Head",    "19,00,000", "+91-8879012345", "2018-04-20", "COO",           "LEVEL2"],
    ]

    for emp in employees:
        writer.writerow(emp)

    return output.getvalue()


def generate_customers_csv() -> str:
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Customer ID", "Name", "Email", "Phone",
        "Passport No", "Country", "Total Bookings",
        "Total Spent (INR)", "Loyalty Points", "Last Travel"
    ])

    customers = [
        ["CUS10021", "Rahul Sharma",    "rahul.sharma@gmail.com",   "+91-9876543210", "K1234567", "India",     12, "8,45,000",  12500, "2026-02-15"],
        ["CUS10022", "Priya Patel",     "priya.p@hotmail.com",      "+91-9823456781", "L9876543", "India",      8, "5,72,500",   8200, "2026-01-20"],
        ["CUS10023", "James Wilson",    "j.wilson@gmail.com",       "+44-7911123456", "GB123456", "UK",         5, "12,45,000",  6500, "2025-12-10"],
        ["CUS10024", "Sarah Johnson",   "sarah.j@yahoo.com",        "+1-5551234567",  "US987654", "USA",        3, "9,80,000",   4200, "2026-01-05"],
        ["CUS10025", "Mohammed Al-Faris","m.alfaris@outlook.com",   "+971-501234567", "AE654321", "UAE",        9, "24,30,000", 18500, "2026-02-28"],
        ["CUS10026", "Sneha Reddy",     "sneha.r@gmail.com",        "+91-9634567890", "M5678901", "India",      6, "4,15,000",   5800, "2025-11-30"],
        ["CUS10027", "Vikram Singh",    "v.singh99@gmail.com",      "+91-9556789012", "N2345678", "India",     15, "18,75,000", 22000, "2026-03-01"],
        ["CUS10028", "Emily Chen",      "emily.chen@gmail.com",     "+65-91234567",   "SG123456", "Singapore",  4, "7,60,000",   4900, "2026-02-10"],
    ]

    for cust in customers:
        writer.writerow(cust)

    return output.getvalue()


def generate_financial_data() -> str:
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["Month", "Revenue (INR)", "Bookings", "Refunds", "Net Profit", "Top Destination"])

    data = [
        ["January 2026",  "1,24,50,000", 1823, "12,30,000", "98,45,000",  "Dubai"],
        ["February 2026", "98,75,000",   1456, "8,90,000",  "76,20,000",  "Singapore"],
        ["March 2026",    "1,45,80,000", 2134, "15,60,000", "1,12,30,000","Maldives"],
    ]

    for row in data:
        writer.writerow(row)

    writer.writerow([])
    writer.writerow(["TOTAL Q1 2026", "3,69,05,000", 5413, "36,80,000", "2,86,95,000", ""])
    writer.writerow([])
    writer.writerow(["CONFIDENTIAL — Thomas Cook Finance Dept — Do Not Share"])

    return output.getvalue()


def generate_db_config() -> str:
    return """<?php
// Thomas Cook — Production Database Configuration
// Generated: 2026-03-10 02:00 AM
// WARNING: Do not commit this file to version control

// Primary Database
define('DB_HOST',     '192.168.1.100');
define('DB_NAME',     'thomascook_prod');
define('DB_USER',     'tc_admin');
define('DB_PASS',     'Tc@Admin#2026!Secure');
define('DB_PORT',     '3306');
define('DB_CHARSET',  'utf8mb4');

// Replica Database (Read-only)
define('DB_REPLICA_HOST', '192.168.1.101');
define('DB_REPLICA_USER', 'tc_readonly');
define('DB_REPLICA_PASS', 'Readonly@2026#TC');

// AWS S3 Backup Storage
define('AWS_REGION',    'ap-south-1');
define('AWS_KEY',       'AKIAIOSFODNN7EXAMPLE');
define('AWS_SECRET',    'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');
define('AWS_BUCKET',    'thomascook-prod-backups');

// Razorpay Payment Gateway (LIVE)
define('RAZORPAY_KEY',    'rzp_live_EXAMPLEKEY123456');
define('RAZORPAY_SECRET', 'rzp_live_secret_EXAMPLE789');

// Stripe (International)
define('STRIPE_PK',  'pk_live_EXAMPLESTRIPEKEY123');
define('STRIPE_SK',  'sk_live_EXAMPLESECRET456789');

// SMTP Mail
define('SMTP_HOST',  'smtp.thomascook.com');
define('SMTP_USER',  'noreply@thomascook.com');
define('SMTP_PASS',  'Mail@2026#Secure!TC');
define('SMTP_PORT',  '587');
?>"""


def generate_api_keys() -> str:
    return """# Thomas Cook — API Keys Configuration
# Environment: PRODUCTION
# Last Updated: 2026-03-10
# CONFIDENTIAL — Internal Use Only

# Database
MONGO_URI=mongodb+srv://tc_admin:MongoSecure2026@cluster0.thomascook.mongodb.net/prod
REDIS_URL=redis://:Redis@2026Secure@192.168.1.102:6379/0

# AWS
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=ap-south-1
S3_BUCKET=thomascook-prod-backups

# Payment Gateways
RAZORPAY_KEY_ID=rzp_live_EXAMPLEKEY123456
RAZORPAY_KEY_SECRET=rzp_live_secret_EXAMPLE789
STRIPE_PUBLISHABLE_KEY=pk_live_EXAMPLESTRIPEKEY123
STRIPE_SECRET_KEY=sk_live_EXAMPLESECRET456789

# Communications
TWILIO_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
TWILIO_TOKEN=your_auth_token_here
SENDGRID_API_KEY=SG.EXAMPLEKEY.EXAMPLEKEY123456789

# Internal Services
INTERNAL_API_KEY=tc_internal_2026_SECRETKEY_xyz789
ADMIN_SECRET=admin_2026_ULTRASECRET_abc123
JWT_SECRET=jwt_thomascook_2026_SUPERSECRET

# Google Services
GOOGLE_MAPS_KEY=AIzaSyEXAMPLEKEY123456789
GOOGLE_ANALYTICS_ID=UA-XXXXXXXX-X

# Monitoring
SENTRY_DSN=https://EXAMPLEKEY@sentry.io/123456
"""


def generate_sql_dump() -> str:
    return """-- Thomas Cook Travel Database Backup
-- Server: 192.168.1.100
-- Database: thomascook_prod
-- Generated: 2026-03-10 02:00:01
-- WARNING: CONFIDENTIAL — Do not distribute

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";

-- Table structure for `users`
CREATE TABLE `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(100) NOT NULL,
  `email` varchar(255) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `role` enum('superadmin','admin','manager','staff') NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Dumping data for table `users`
INSERT INTO `users` (`id`, `username`, `email`, `password_hash`, `role`) VALUES
(1, 'admin',        'admin@thomascook.com',   'e10adc3949ba59abbe56e057f20f883e', 'superadmin'),
(2, 'ops_manager',  'ops@thomascook.com',     '5f4dcc3b5aa765d61d8327deb882cf99', 'admin'),
(3, 'finance_head', 'finance@thomascook.com', 'd8578edf8458ce06fbc5bb76a58c5ca4', 'manager'),
(4, 'hr_manager',   'hr@thomascook.com',      '25f9e794323b453885f5181f1b624d0b', 'manager'),
(5, 'sales_head',   'sales@thomascook.com',   '96e79218965eb72c92a549dd5a330112', 'staff');

-- Table structure for `bookings`
CREATE TABLE `bookings` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `booking_ref` varchar(20) NOT NULL,
  `customer_id` int(11) NOT NULL,
  `destination` varchar(100) NOT NULL,
  `amount` decimal(10,2) NOT NULL,
  `status` enum('confirmed','pending','cancelled') NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `bookings` (`booking_ref`, `customer_id`, `destination`, `amount`, `status`) VALUES
('TC-2026-8821', 1, 'Dubai',     85000.00, 'confirmed'),
('TC-2026-8820', 2, 'Singapore', 72500.00, 'confirmed'),
('TC-2026-8819', 3, 'Thailand',  45000.00, 'pending'),
('TC-2026-8818', 4, 'Maldives', 120000.00, 'confirmed'),
('TC-2026-8817', 5, 'Europe',   185000.00, 'pending');

COMMIT;
-- End of backup
"""


def generate_readme() -> str:
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    return f"""Thomas Cook Travel — System Backup
====================================
Generated: {now}
Server: tc-prod-server-01 (192.168.1.100)
Backup Type: Full System Backup

CONTENTS:
---------
thomascook_employees_2026.csv     — Staff directory with contact details
config/database.php               — Production database configuration
config/api_keys.env               — All API keys and secrets
exports/customers_march_2026.csv  — Customer database export
exports/financial_summary_Q1.csv  — Q1 2026 financial data
backup/thomascook_db_partial.sql  — Partial database dump

WARNING: This backup contains CONFIDENTIAL information.
Unauthorized access is strictly prohibited.
All access is logged and monitored.

Thomas Cook Travel Ltd
IT Security Team
security@thomascook.com
"""
