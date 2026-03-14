import os
import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

# ── Colour palette ───────────────────────────────────────
BG        = colors.HexColor("#0a0c10")
SURFACE   = colors.HexColor("#111318")
SURFACE2  = colors.HexColor("#0d1017")
ORANGE    = colors.HexColor("#ff6600")
RED       = colors.HexColor("#ff3b6e")
GREEN     = colors.HexColor("#00e599")
BLUE      = colors.HexColor("#2a5cff")
PURPLE    = colors.HexColor("#a78bfa")
TEXT      = colors.HexColor("#c8d0e0")
TEXT_DIM  = colors.HexColor("#4a5568")
BORDER    = colors.HexColor("#1e2229")
HEADER_BG = colors.HexColor("#1a2035")
WHITE     = colors.white


def generate_report(stats: dict, recent: list, output_path: str) -> str:
    """Generate a professional PDF security report."""

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=20*mm,
        rightMargin=20*mm,
        topMargin=20*mm,
        bottomMargin=20*mm,
    )

    styles = getSampleStyleSheet()
    story  = []

    # ── Custom styles ────────────────────────────────────
    title_style = ParagraphStyle("title",
        fontSize=26, textColor=WHITE, fontName="Helvetica-Bold",
        alignment=TA_CENTER, spaceAfter=4)

    subtitle_style = ParagraphStyle("subtitle",
        fontSize=11, textColor=TEXT_DIM, fontName="Helvetica",
        alignment=TA_CENTER, spaceAfter=2)

    badge_style = ParagraphStyle("badge",
        fontSize=9, textColor=ORANGE, fontName="Helvetica-Bold",
        alignment=TA_CENTER, spaceAfter=16)

    section_style = ParagraphStyle("section",
        fontSize=13, textColor=ORANGE, fontName="Helvetica-Bold",
        spaceBefore=18, spaceAfter=8)

    section2_style = ParagraphStyle("section2",
        fontSize=13, textColor=BLUE, fontName="Helvetica-Bold",
        spaceBefore=18, spaceAfter=8)

    body_style = ParagraphStyle("body",
        fontSize=10, textColor=TEXT, fontName="Helvetica",
        spaceAfter=6, leading=16)

    small_style = ParagraphStyle("small",
        fontSize=9, textColor=TEXT_DIM, fontName="Helvetica",
        spaceAfter=4)

    rec_style = ParagraphStyle("rec",
        fontSize=10, textColor=TEXT, fontName="Helvetica",
        spaceAfter=6, leading=16, leftIndent=12)

    def th(text, align=TA_LEFT):
        return Paragraph(text, ParagraphStyle("th", fontSize=9,
            textColor=TEXT_DIM, fontName="Helvetica-Bold", alignment=align))

    def td(text, color=TEXT, align=TA_LEFT, size=10):
        return Paragraph(str(text), ParagraphStyle("td", fontSize=size,
            textColor=color, fontName="Helvetica", alignment=align))

    def tdb(text, color=WHITE, align=TA_CENTER):
        return Paragraph(str(text), ParagraphStyle("tdb", fontSize=10,
            textColor=color, fontName="Helvetica-Bold", alignment=align))

    def table_style(has_header=True):
        s = [
            ("GRID",         (0,0), (-1,-1), 0.5, BORDER),
            ("TOPPADDING",   (0,0), (-1,-1), 8),
            ("BOTTOMPADDING",(0,0), (-1,-1), 8),
            ("LEFTPADDING",  (0,0), (-1,-1), 10),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [SURFACE, SURFACE2]),
        ]
        if has_header:
            s.append(("BACKGROUND", (0,0), (-1,0), HEADER_BG))
        return TableStyle(s)

    # ── Page background ──────────────────────────────────
    def dark_background(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(BG)
        canvas.rect(0, 0, A4[0], A4[1], fill=True, stroke=False)
        canvas.restoreState()

    # ════════════════════════════════════════════════════
    # HEADER
    # ════════════════════════════════════════════════════
    story.append(Paragraph("HONEYPOT AS A SERVICE — MULTI-TYPE INTELLIGENCE SYSTEM", badge_style))
    story.append(Paragraph("Security Threat Report", title_style))
    story.append(Paragraph("Thomas Cook Travel — Integrated Honeypot Platform", subtitle_style))

    now = datetime.datetime.utcnow()
    story.append(Paragraph(
        f"Generated: {now.strftime('%d %B %Y, %H:%M UTC')}   |   Classification: CONFIDENTIAL",
        ParagraphStyle("gen", fontSize=9, textColor=TEXT_DIM,
                       fontName="Helvetica", alignment=TA_CENTER, spaceAfter=20)
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=ORANGE, spaceAfter=20))

    # ════════════════════════════════════════════════════
    # SECTION 1 — EXECUTIVE SUMMARY
    # ════════════════════════════════════════════════════
    story.append(Paragraph("01. EXECUTIVE SUMMARY", section_style))

    total        = stats.get("total", 0)
    risk_levels  = stats.get("risk_levels", {})
    attack_types = stats.get("attack_types", {})
    top_countries= stats.get("top_countries", {})
    top_ips      = stats.get("top_ips", {})
    honeypot_types = stats.get("honeypot_types", {})

    high_count   = risk_levels.get("HIGH",   0)
    medium_count = risk_levels.get("MEDIUM", 0)
    low_count    = risk_levels.get("LOW",    0)

    top_attack  = max(attack_types,  key=attack_types.get)  if attack_types  else "N/A"
    top_country = max(top_countries, key=top_countries.get) if top_countries else "N/A"
    top_ip      = max(top_ips,       key=top_ips.get)       if top_ips       else "N/A"

    def stat_cell(label, value, color=WHITE):
        return [
            Paragraph(f'<font size="22"><b>{value}</b></font>',
                      ParagraphStyle("sv", textColor=color,
                                     fontName="Helvetica-Bold", alignment=TA_CENTER)),
            Paragraph(label,
                      ParagraphStyle("sl", fontSize=8, textColor=TEXT_DIM,
                                     fontName="Helvetica", alignment=TA_CENTER)),
        ]

    summary_data = [[
        stat_cell("TOTAL EVENTS",  total,        WHITE),
        stat_cell("HIGH RISK",     high_count,   RED),
        stat_cell("MEDIUM RISK",   medium_count, ORANGE),
        stat_cell("LOW RISK",      low_count,    GREEN),
    ]]
    summary_table = Table(summary_data, colWidths=[42*mm]*4)
    summary_table.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), SURFACE),
        ("GRID",         (0,0), (-1,-1), 0.5, BORDER),
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",   (0,0), (-1,-1), 10),
        ("BOTTOMPADDING",(0,0), (-1,-1), 10),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 14))

    # Key findings row
    findings_data = [[
        [th("TOP ATTACK TYPE", TA_CENTER),
         Paragraph(str(top_attack), ParagraphStyle("fv", fontSize=13,
             textColor=ORANGE, fontName="Helvetica-Bold", alignment=TA_CENTER))],
        [th("TOP COUNTRY", TA_CENTER),
         Paragraph(str(top_country), ParagraphStyle("fv", fontSize=13,
             textColor=RED, fontName="Helvetica-Bold", alignment=TA_CENTER))],
        [th("TOP ATTACKER IP", TA_CENTER),
         Paragraph(str(top_ip), ParagraphStyle("fv", fontSize=13,
             textColor=BLUE, fontName="Helvetica-Bold", alignment=TA_CENTER))],
    ]]
    findings_table = Table(findings_data, colWidths=[56*mm]*3)
    findings_table.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), SURFACE),
        ("GRID",         (0,0), (-1,-1), 0.5, BORDER),
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",   (0,0), (-1,-1), 10),
        ("BOTTOMPADDING",(0,0), (-1,-1), 10),
    ]))
    story.append(findings_table)

    # ════════════════════════════════════════════════════
    # SECTION 2 — HONEYPOT TYPE BREAKDOWN
    # ════════════════════════════════════════════════════
    story.append(Paragraph("02. HONEYPOT TYPE BREAKDOWN", section2_style))
    story.append(Paragraph(
        "This platform runs 4 integrated honeypot types simultaneously, "
        "each capturing a different class of attacker behaviour.",
        body_style
    ))

    web_count   = honeypot_types.get("WEB",      0)
    ssh_count   = honeypot_types.get("SSH",       0)
    db_count    = honeypot_types.get("DATABASE",  0)
    email_count = honeypot_types.get("EMAIL",     0)

    def pct(count):
        return f"{round((count/total)*100,1)}%" if total > 0 else "0%"

    htype_data = [
        [th("Honeypot Type"), th("Description"), th("Events", TA_CENTER), th("% Share", TA_CENTER), th("Status", TA_CENTER)],
        [td("🌐  Web Honeypot"),      td("Fake travel portal — catches SQL injection, XSS, brute force"),   tdb(web_count,   ORANGE), tdb(pct(web_count),   TEXT_DIM), tdb("ACTIVE", GREEN)],
        [td("🔌  SSH Honeypot"),      td("Fake SSH server on port 2222 — logs credentials + commands"),      tdb(ssh_count,   RED),    tdb(pct(ssh_count),   TEXT_DIM), tdb("ACTIVE", GREEN)],
        [td("🗄️  Database Honeypot"), td("Fake MongoDB on port 27017 — catches database scan attempts"),     tdb(db_count,    GREEN),  tdb(pct(db_count),    TEXT_DIM), tdb("ACTIVE", GREEN)],
        [td("📧  Email Honeypot"),    td("Fake SMTP on port 2525 — catches phishing and spam emails"),       tdb(email_count, PURPLE), tdb(pct(email_count), TEXT_DIM), tdb("ACTIVE", GREEN)],
    ]
    htype_table = Table(htype_data, colWidths=[38*mm, 72*mm, 18*mm, 18*mm, 18*mm])
    htype_table.setStyle(table_style())
    story.append(htype_table)

    # ════════════════════════════════════════════════════
    # SECTION 3 — ATTACK TYPE BREAKDOWN
    # ════════════════════════════════════════════════════
    story.append(Paragraph("03. ATTACK TYPE BREAKDOWN", section_style))

    risk_map = {
        "SQL Injection":           ("HIGH",     RED),
        "Command Injection":       ("CRITICAL", RED),
        "XSS":                     ("HIGH",     RED),
        "Path Traversal":          ("HIGH",     RED),
        "Brute Force":             ("MEDIUM",   ORANGE),
        "Reconnaissance":          ("MEDIUM",   ORANGE),
        "SSH Brute Force":         ("HIGH",     RED),
        "SSH Command Execution":   ("CRITICAL", RED),
        "MongoDB Probe":           ("HIGH",     RED),
        "MongoDB List Databases":  ("HIGH",     RED),
        "MongoDB Data Dump Attempt":("CRITICAL",RED),
        "Phishing Email":          ("HIGH",     RED),
        "Spam Email":              ("MEDIUM",   ORANGE),
        "Suspicious Email":        ("MEDIUM",   ORANGE),
        "Normal":                  ("LOW",      GREEN),
    }

    at_rows = [[th("Attack Type"), th("Honeypot"), th("Count", TA_CENTER), th("% Total", TA_CENTER), th("Risk", TA_CENTER)]]

    htype_for_attack = {
        "SQL Injection":"WEB", "Command Injection":"WEB", "XSS":"WEB",
        "Path Traversal":"WEB", "Brute Force":"WEB", "Reconnaissance":"WEB",
        "SSH Brute Force":"SSH", "SSH Command Execution":"SSH",
        "MongoDB Probe":"DB", "MongoDB List Databases":"DB",
        "MongoDB Data Dump Attempt":"DB",
        "Phishing Email":"EMAIL", "Spam Email":"EMAIL", "Suspicious Email":"EMAIL",
        "Normal":"WEB",
    }
    htype_colors = {"WEB":ORANGE, "SSH":RED, "DB":GREEN, "EMAIL":PURPLE}

    for atype, count in sorted(attack_types.items(), key=lambda x: x[1], reverse=True):
        p = round((count/total)*100,1) if total > 0 else 0
        risk_label, risk_color = risk_map.get(atype, ("MEDIUM", ORANGE))
        htype = htype_for_attack.get(atype, "WEB")
        hcol  = htype_colors.get(htype, ORANGE)
        at_rows.append([
            td(atype),
            Paragraph(htype, ParagraphStyle("ht", fontSize=9, textColor=hcol,
                fontName="Helvetica-Bold")),
            tdb(count),
            tdb(f"{p}%", TEXT_DIM),
            Paragraph(risk_label, ParagraphStyle("rl", fontSize=9,
                textColor=risk_color, fontName="Helvetica-Bold", alignment=TA_CENTER)),
        ])

    at_table = Table(at_rows, colWidths=[65*mm, 22*mm, 22*mm, 22*mm, 25*mm])
    at_table.setStyle(table_style())
    story.append(at_table)

    # ════════════════════════════════════════════════════
    # SECTION 4 — TOP ATTACKING COUNTRIES
    # ════════════════════════════════════════════════════
    story.append(Paragraph("04. TOP ATTACKING COUNTRIES", section_style))

    geo_rows = [[th("Country"), th("Attacks", TA_CENTER), th("% Share", TA_CENTER), th("Threat Level", TA_CENTER)]]
    for i, (country, count) in enumerate(list(top_countries.items())[:8]):
        p = round((count/total)*100,1) if total > 0 else 0
        threat = "CRITICAL" if p > 30 else "HIGH" if p > 15 else "MEDIUM" if p > 5 else "LOW"
        tcol   = RED if threat in ("CRITICAL","HIGH") else ORANGE if threat == "MEDIUM" else GREEN
        geo_rows.append([
            td(f"#{i+1}  {country}"),
            tdb(count),
            tdb(f"{p}%", TEXT_DIM),
            Paragraph(threat, ParagraphStyle("tl", fontSize=9, textColor=tcol,
                fontName="Helvetica-Bold", alignment=TA_CENTER)),
        ])

    geo_table = Table(geo_rows, colWidths=[80*mm, 30*mm, 30*mm, 30*mm])
    geo_table.setStyle(table_style())
    story.append(geo_table)

    # ════════════════════════════════════════════════════
    # SECTION 5 — SSH ATTACK DETAILS
    # ════════════════════════════════════════════════════
    story.append(Paragraph("05. SSH HONEYPOT — CREDENTIAL ATTEMPTS", section2_style))

    ssh_entries = [e for e in recent if e.get("honeypot_type") == "SSH"]
    if ssh_entries:
        ssh_rows = [[th("Timestamp"), th("IP Address"), th("Username"), th("Password"), th("Command")]]
        for e in ssh_entries[:8]:
            ts  = e.get("timestamp","")[:16].replace("T"," ")
            payload = e.get("payload","")
            username = e.get("username","?")
            password = e.get("password","?")
            cmd = payload.replace("SSH command: ","").replace("SSH login attempt: ","")[:30] if "command" in payload.lower() else "—"
            ssh_rows.append([
                td(ts, TEXT_DIM, size=8),
                td(e.get("ip","?"), BLUE, size=8),
                td(username, ORANGE, size=8),
                td(password, RED, size=8),
                td(cmd, TEXT_DIM, size=8),
            ])
        ssh_table = Table(ssh_rows, colWidths=[35*mm, 28*mm, 28*mm, 28*mm, 37*mm])
        ssh_table.setStyle(table_style())
        story.append(ssh_table)
    else:
        story.append(Paragraph("No SSH attacks recorded yet.", small_style))

    # ════════════════════════════════════════════════════
    # SECTION 6 — DATABASE ATTACK DETAILS
    # ════════════════════════════════════════════════════
    story.append(Paragraph("06. DATABASE HONEYPOT — SCAN ATTEMPTS", section2_style))

    db_entries = [e for e in recent if e.get("honeypot_type") == "DATABASE"]
    if db_entries:
        db_rows = [[th("Timestamp"), th("IP Address"), th("Action"), th("Country"), th("Risk")]]
        for e in db_entries[:8]:
            ts  = e.get("timestamp","")[:16].replace("T"," ")
            rc  = RED if e.get("risk_level") == "HIGH" else ORANGE
            db_rows.append([
                td(ts, TEXT_DIM, size=8),
                td(e.get("ip","?"), BLUE, size=8),
                td(e.get("attack_type","?"), TEXT, size=8),
                td(e.get("country","?"), TEXT_DIM, size=8),
                Paragraph(e.get("risk_level","?"), ParagraphStyle("rl",
                    fontSize=8, textColor=rc, fontName="Helvetica-Bold",
                    alignment=TA_CENTER)),
            ])
        db_table = Table(db_rows, colWidths=[35*mm, 28*mm, 48*mm, 30*mm, 20*mm])
        db_table.setStyle(table_style())
        story.append(db_table)
    else:
        story.append(Paragraph("No database attacks recorded yet.", small_style))

    # ════════════════════════════════════════════════════
    # SECTION 7 — EMAIL HONEYPOT DETAILS
    # ════════════════════════════════════════════════════
    story.append(Paragraph("07. EMAIL HONEYPOT — PHISHING & SPAM CAUGHT", section2_style))

    email_entries = [e for e in recent if e.get("honeypot_type") == "EMAIL"]
    if email_entries:
        em_rows = [[th("Timestamp"), th("From"), th("Subject"), th("Type"), th("Risk")]]
        for e in email_entries[:8]:
            ts      = e.get("timestamp","")[:16].replace("T"," ")
            subject = e.get("email_subject","?")[:30]
            sender  = e.get("email_from","?")[:25]
            rc      = RED if e.get("risk_level") == "HIGH" else ORANGE
            em_rows.append([
                td(ts, TEXT_DIM, size=8),
                td(sender, BLUE, size=8),
                td(subject, TEXT, size=8),
                td(e.get("attack_type","?"), PURPLE, size=8),
                Paragraph(e.get("risk_level","?"), ParagraphStyle("rl",
                    fontSize=8, textColor=rc, fontName="Helvetica-Bold",
                    alignment=TA_CENTER)),
            ])
        em_table = Table(em_rows, colWidths=[30*mm, 38*mm, 48*mm, 30*mm, 14*mm])
        em_table.setStyle(table_style())
        story.append(em_table)
    else:
        story.append(Paragraph("No email attacks recorded yet.", small_style))

    # ════════════════════════════════════════════════════
    # SECTION 8 — RECENT WEB ATTACK LOG
    # ════════════════════════════════════════════════════
    story.append(Paragraph("08. WEB HONEYPOT — RECENT ATTACK LOG", section_style))

    web_entries = [e for e in recent if e.get("honeypot_type","WEB") == "WEB"]
    rec_rows = [[th("Timestamp"), th("IP"), th("Attack Type"), th("Risk"), th("Country")]]
    risk_colors_map = {"HIGH": RED, "MEDIUM": ORANGE, "LOW": GREEN}

    for e in web_entries[:10]:
        ts = e.get("timestamp","")[:16].replace("T"," ")
        rc = risk_colors_map.get(e.get("risk_level","LOW"), TEXT_DIM)
        rec_rows.append([
            td(ts, TEXT_DIM, size=8),
            td(e.get("ip","?"), BLUE, size=8),
            td(e.get("attack_type","?"), TEXT, size=8),
            Paragraph(e.get("risk_level","?"), ParagraphStyle("rl",
                fontSize=8, textColor=rc, fontName="Helvetica-Bold",
                alignment=TA_CENTER)),
            td(e.get("country","?"), TEXT_DIM, size=8),
        ])

    rec_table = Table(rec_rows, colWidths=[35*mm, 28*mm, 45*mm, 20*mm, 38*mm])
    rec_table.setStyle(table_style())
    story.append(rec_table)

    # ════════════════════════════════════════════════════
    # SECTION 9 — DECOY FILE DOWNLOADS
    # ════════════════════════════════════════════════════
    story.append(Paragraph("09. DECOY FILE DOWNLOAD TRACKING", section_style))
    story.append(Paragraph(
        "When attackers access /backup.zip they receive a convincing fake ZIP containing "
        "decoy employee records, database configs, API keys and SQL dumps. "
        "Every download is logged as a HIGH risk data theft attempt.",
        body_style
    ))

    decoy_entries = [e for e in recent if "backup" in e.get("endpoint","").lower()
                     or "download" in e.get("endpoint","").lower()]
    if decoy_entries:
        decoy_rows = [[th("Timestamp"), th("IP"), th("File Requested"), th("Country"), th("Risk")]]
        for e in decoy_entries[:5]:
            ts = e.get("timestamp","")[:16].replace("T"," ")
            decoy_rows.append([
                td(ts, TEXT_DIM, size=8),
                td(e.get("ip","?"), RED, size=8),
                td(e.get("endpoint","?"), ORANGE, size=8),
                td(e.get("country","?"), TEXT_DIM, size=8),
                tdb("HIGH", RED),
            ])
        decoy_table = Table(decoy_rows, colWidths=[35*mm, 28*mm, 50*mm, 30*mm, 20*mm])
        decoy_table.setStyle(table_style())
        story.append(decoy_table)
    else:
        story.append(Paragraph(
            "No decoy file downloads recorded yet. "
            "Decoy files contain fake employee CSV, database config, API keys and SQL dump.",
            small_style
        ))

    # ════════════════════════════════════════════════════
    # SECTION 10 — SECURITY RECOMMENDATIONS
    # ════════════════════════════════════════════════════
    story.append(Paragraph("10. SECURITY RECOMMENDATIONS", section_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=10))

    recommendations = []

    if high_count > 0:
        recommendations.append(
            f"🔴  <b>Critical:</b> {high_count} HIGH risk events detected across all honeypot types. "
            f"Immediately review firewall rules and block top attacker IPs.")
    if ssh_count > 0:
        recommendations.append(
            f"🔌  <b>SSH Security:</b> {ssh_count} SSH brute force attempts detected. "
            f"Disable password authentication, use SSH keys only, and change default SSH port.")
    if db_count > 0:
        recommendations.append(
            f"🗄️  <b>Database Exposure:</b> {db_count} MongoDB probe attempts detected. "
            f"Never expose databases to public internet. Use firewall to restrict port 27017.")
    if email_count > 0:
        recommendations.append(
            f"📧  <b>Email Threats:</b> {email_count} phishing/spam emails caught. "
            f"Implement SPF, DKIM, DMARC records and train staff on phishing awareness.")
    if attack_types.get("SQL Injection", 0) > 0:
        recommendations.append(
            f"💉  <b>SQL Injection:</b> {attack_types['SQL Injection']} attempts detected. "
            f"Use parameterized queries and prepared statements exclusively.")
    if attack_types.get("Brute Force", 0) > 0:
        recommendations.append(
            f"🔑  <b>Brute Force:</b> {attack_types.get('Brute Force',0) + ssh_count} total attempts. "
            f"Implement account lockout, CAPTCHA, and Multi-Factor Authentication.")
    if attack_types.get("Reconnaissance", 0) > 0:
        recommendations.append(
            f"🔍  <b>Reconnaissance:</b> {attack_types['Reconnaissance']} scans detected. "
            f"Remove sensitive endpoints, implement rate limiting and IP reputation checks.")
    if top_ip != "N/A":
        recommendations.append(
            f"🌍  <b>IP Blocking:</b> Top attacker IP {top_ip} from {top_country}. "
            f"Block this IP range at firewall level immediately.")

    recommendations.append(
        "🛡️  <b>WAF:</b> Deploy a Web Application Firewall to filter malicious traffic "
        "before it reaches application servers.")
    recommendations.append(
        "📊  <b>Continuous Monitoring:</b> This honeypot system provides 24/7 real-time "
        "alerting via Telegram and Email. Review weekly PDF reports to track threat trends.")

    for rec in recommendations:
        story.append(Paragraph(f"•  {rec}", rec_style))
        story.append(Spacer(1, 4))

    # ════════════════════════════════════════════════════
    # FOOTER
    # ════════════════════════════════════════════════════
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=8))
    story.append(Paragraph(
        f"Honeypot as a Service · Thomas Cook Travel Security · "
        f"Web | SSH | Database | Email Honeypots · "
        f"Generated {now.strftime('%d %b %Y %H:%M')} UTC · CONFIDENTIAL",
        ParagraphStyle("footer", fontSize=8, textColor=TEXT_DIM,
                       fontName="Helvetica", alignment=TA_CENTER)
    ))

    doc.build(story, onFirstPage=dark_background, onLaterPages=dark_background)
    return output_path
