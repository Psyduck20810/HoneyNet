import re

# ─────────────────────────────────────────
# ATTACK PATTERN DEFINITIONS
# ─────────────────────────────────────────

SQL_PATTERNS = [
    r"('|\")\s*(or|and)\s+('|\")?\s*\d+\s*=\s*\d+",   # ' OR 1=1
    r"union\s+(all\s+)?select",                          # UNION SELECT
    r"drop\s+table",                                     # DROP TABLE
    r"insert\s+into",                                    # INSERT INTO
    r"delete\s+from",                                    # DELETE FROM
    r"--\s*$",                                           # SQL comment
    r";\s*select",                                       # ; SELECT chaining
    r"xp_cmdshell",                                      # MSSQL exec
    r"sleep\(\d+\)",                                     # Time-based blind
    r"benchmark\(\d+",                                   # MySQL benchmark
    r"waitfor\s+delay",                                  # MSSQL delay
    r"information_schema",                               # Schema enum
    r"'.*'.*=.*'",                                       # Tautology
    r"or\s+1\s*=\s*1",                                  # OR 1=1
]

XSS_PATTERNS = [
    r"<script[\s>]",                                     # <script>
    r"javascript\s*:",                                   # javascript:
    r"on\w+\s*=",                                        # onerror= onclick=
    r"<\s*iframe",                                       # <iframe
    r"<\s*img[^>]+src\s*=",                              # <img src=
    r"alert\s*\(",                                       # alert(
    r"document\.(cookie|location|write)",                # DOM attacks
    r"eval\s*\(",                                        # eval(
    r"<\s*svg[^>]*on\w+",                               # SVG event
    r"expression\s*\(",                                  # CSS expression
    r"vbscript\s*:",                                     # VBScript
]

PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",                                            # ../
    r"%2e%2e%2f",                                        # URL encoded ../
    r"%00",                                              # Null-byte evasion
    r"\.\.\\",                                           # ..\
    r"/etc/passwd",                                      # Linux sensitive
    r"c:\\windows",                                      # Windows path
    r"boot\.ini",                                        # Windows boot
]

COMMAND_INJECTION_PATTERNS = [
    r";\s*(ls|cat|pwd|whoami|id|uname)",                # ; ls
    r"\|\s*(ls|cat|pwd|whoami|id)",                     # | ls
    r"`.*`",                                             # Backtick execution
    r"\$\(.*\)",                                         # $(command)
    r"&&\s*(ls|cat|rm|curl|wget)",                       # && command
]

RISK_SCORES = {
    "SQL Injection":        9,
    "XSS Attack":           7,
    "Command Injection":    10,
    "Path Traversal":       8,
    "Brute Force":          6,
    "Reconnaissance":       4,
    "Normal":               1,
}

def _risk_level(score):
    if score >= 7:
        return "HIGH"
    elif score >= 4:
        return "MEDIUM"
    return "LOW"


# ─────────────────────────────────────────
# INTELLIGENCE ENGINE CLASS
# ─────────────────────────────────────────

class IntelligenceEngine:

    def analyze(self, payload, ip, endpoint, login_count=0, recon_count=0):
        """
        Analyze a request and return full threat intelligence.
        Returns a dict with attack_type, risk_score, risk_level, details.
        """
        payload_lower = payload.lower()
        attack_type = "Normal"
        matched_pattern = None

        # Priority order: most dangerous first
        if self._match(payload_lower, COMMAND_INJECTION_PATTERNS):
            attack_type = "Command Injection"
            matched_pattern = self._get_match(payload_lower, COMMAND_INJECTION_PATTERNS)

        elif self._match(payload_lower, SQL_PATTERNS):
            attack_type = "SQL Injection"
            matched_pattern = self._get_match(payload_lower, SQL_PATTERNS)

        elif self._match(payload_lower, PATH_TRAVERSAL_PATTERNS):
            attack_type = "Path Traversal"
            matched_pattern = self._get_match(payload_lower, PATH_TRAVERSAL_PATTERNS)

        elif self._match(payload_lower, XSS_PATTERNS):
            attack_type = "XSS Attack"
            matched_pattern = self._get_match(payload_lower, XSS_PATTERNS)

        elif login_count >= 5:
            attack_type = "Brute Force"
            matched_pattern = f"{login_count} attempts in 60s"

        elif recon_count >= 3:
            attack_type = "Reconnaissance"
            matched_pattern = f"{recon_count} endpoints probed"

        risk_score = RISK_SCORES.get(attack_type, 1)
        risk_level = _risk_level(risk_score)

        return {
            "attack_type": attack_type,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "matched_pattern": matched_pattern or "None",
        }

    def _match(self, payload, patterns):
        return any(re.search(p, payload, re.IGNORECASE) for p in patterns)

    def _get_match(self, payload, patterns):
        for p in patterns:
            m = re.search(p, payload, re.IGNORECASE)
            if m:
                return m.group(0)
        return None
