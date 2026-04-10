# ai_analyzer/threat_intel.py
"""
Threat Intelligence Matching Engine.

Matches incoming payloads against:
  - OWASP Top 10 payload signatures
  - MITRE ATT&CK technique mappings
  - Known attacker tool fingerprints (sqlmap, Nikto, Metasploit, etc.)

Reuses detection/mitre_mapper.py TTPs — no duplication.
"""

import re
from typing import NamedTuple


class IntelMatch(NamedTuple):
    matched_signature: str
    mitre_technique:   str
    pattern_type:      str
    owasp_category:    str


# ── OWASP Top 10 (2021) signatures ───────────────────────────────────────────
# Each entry: (regex_pattern, signature_name, mitre_id, pattern_type, owasp_category)
OWASP_SIGNATURES: list[tuple] = [
    # A03 — Injection
    (r"union\s+select|'\s+or\s+'1'='1|--\s*$|;\s*drop\s+table|xp_cmdshell|sleep\(\d+\)|benchmark\(",
     "SQLi — Union/Boolean/Time-based", "T1190", "sql_injection",
     "A03:2021 — Injection"),

    # A03 — Command Injection
    (r";\s*(?:ls|id|whoami|cat|wget|curl|bash|sh)\b|`[^`]+`|\$\([^)]+\)",
     "Command Injection", "T1059.004", "command_injection",
     "A03:2021 — Injection"),

    # A03 — XSS
    (r"<script[^>]*>|javascript\s*:|onerror\s*=|onload\s*=|alert\s*\(|document\.cookie",
     "XSS — Reflected/Stored", "T1059.007", "xss",
     "A03:2021 — Injection"),

    # A01 — Path Traversal (Broken Access Control)
    (r"\.\.\/|\.\.\\|%2e%2e%2f|%252e%252e|\/etc\/passwd|\/etc\/shadow|\/proc\/",
     "Path Traversal / LFI", "T1083", "path_traversal",
     "A01:2021 — Broken Access Control"),

    # A02 — Credential exposure
    (r"(?:password|passwd|secret|api_key|token)\s*=\s*\S+",
     "Credential Exposure", "T1552.001", "credential_exposure",
     "A02:2021 — Cryptographic Failures"),

    # A05 — Security Misconfiguration (env/config probing)
    (r"\.env$|/config(?:\.php|\.json|\.yml)?$|/wp-config\.php|/settings\.py",
     "Config File Probe", "T1552.001", "config_probe",
     "A05:2021 — Security Misconfiguration"),

    # A06 — Vulnerable component scanning
    (r"CVE-\d{4}-\d+|shellshock|heartbleed|log4shell|struts|dirtycow|pwnkit",
     "CVE Exploit Attempt", "T1190", "cve_exploit",
     "A06:2021 — Vulnerable Components"),

    # A07 — Authentication attacks
    (r"(?:admin|root|user|test)(?:\s*[:/]\s*)(?:admin|password|123|pass|root|test|\x27)",
     "Credential Brute Force", "T1110", "brute_force",
     "A07:2021 — Auth Failures"),

    # Malware delivery
    (r"wget\s+http|curl\s+-[sOo]|chmod\s+\+x|\.\/[a-z0-9_]+\.sh|crontab\s+-[el]",
     "Malware Dropper", "T1105", "malware_delivery",
     "A08:2021 — Software Integrity Failures"),

    # Reverse shell
    (r"bash\s+-i\s*>&?|/dev/tcp/|nc\s+-e\s*/bin|python[23]?\s+-c\s+['\"]import socket",
     "Reverse Shell", "T1059.004", "reverse_shell",
     "A03:2021 — Injection"),
]

# ── Known attacker tool fingerprints ──────────────────────────────────────────
TOOL_SIGNATURES: dict[str, str] = {
    "sqlmap":       "SQLMap — Automated SQL injection scanner",
    "nikto":        "Nikto — Web vulnerability scanner",
    "nmap":         "Nmap — Network scanner",
    "masscan":      "Masscan — Port scanner",
    "metasploit":   "Metasploit Framework",
    "acunetix":     "Acunetix — Web scanner",
    "burpsuite":    "Burp Suite — Web proxy",
    "hydra":        "THC Hydra — Brute force tool",
    "medusa":       "Medusa — Brute force tool",
    "dirbuster":    "DirBuster — Directory brute forcer",
    "gobuster":     "GoBuster — Directory/DNS bruter",
    "wfuzz":        "WFuzz — Web fuzzer",
    "python-requests": "Python requests — Custom script",
    "go-http-client":  "Go HTTP client — Custom tool",
    "zgrab":           "ZGrab — Banner grabber",
}

_NO_MATCH = IntelMatch(
    matched_signature="No known signature",
    mitre_technique="T1595",   # Active Scanning — default
    pattern_type="unknown",
    owasp_category="Unclassified",
)


def match_threat_intel(
    path: str,
    query: str,
    body: str,
    request: str = "",
    user_agent: str = "",
) -> dict:
    """
    Scan combined request data against OWASP/MITRE/tool signatures.
    Returns the highest-confidence match as a dict.
    """
    combined = " ".join([path, query, body, request]).lower()
    ua_lower  = user_agent.lower()

    # ── OWASP signature scan ──────────────────────────────────────────────────
    for pattern, signature, mitre, p_type, owasp in OWASP_SIGNATURES:
        if re.search(pattern, combined, re.IGNORECASE):
            result = IntelMatch(
                matched_signature=signature,
                mitre_technique=mitre,
                pattern_type=p_type,
                owasp_category=owasp,
            )
            # Also check for tool fingerprint in user-agent
            tool = _detect_tool(ua_lower)
            return {**result._asdict(), "tool_detected": tool}

    # ── Tool fingerprint scan (user-agent only) ───────────────────────────────
    tool = _detect_tool(ua_lower)
    if tool:
        return {
            **_NO_MATCH._asdict(),
            "matched_signature": f"Known tool: {tool}",
            "pattern_type":      "tool_fingerprint",
            "tool_detected":     tool,
        }

    return {**_NO_MATCH._asdict(), "tool_detected": None}


def _detect_tool(user_agent: str) -> str | None:
    """Return tool name if user-agent matches a known scanner."""
    for keyword, tool_name in TOOL_SIGNATURES.items():
        if keyword in user_agent:
            return tool_name
    return None