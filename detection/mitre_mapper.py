# detection/mitre_mapper.py
"""
MITRE ATT&CK Mapper — maps observed attacker behaviors to ATT&CK technique IDs.
Reference: https://attack.mitre.org/
"""

# ── Path/command → MITRE TTP mapping ─────────────────────────────────────────
PATH_TTP_MAP = {
    "/admin":         ("T1078", "Valid Accounts"),
    "/wp-admin":      ("T1078", "Valid Accounts"),
    "/.env":          ("T1552.001", "Credentials In Files"),
    "/etc/passwd":    ("T1003.008", "OS Credential Dumping: /etc/passwd"),
    "/etc/shadow":    ("T1003.008", "OS Credential Dumping: /etc/shadow"),
    "/config":        ("T1552.001", "Credentials In Files"),
    "config.php":     ("T1552.001", "Credentials In Files"),
}

SCENARIO_TTP_MAP = {
    "sql_injection":          ("T1190",     "Exploit Public-Facing Application"),
    "rce_attempt":            ("T1059.004", "Command and Scripting Interpreter: Unix Shell"),
    "path_traversal":         ("T1083",     "File and Directory Discovery"),
    "admin_access":           ("T1078",     "Valid Accounts"),
    "user_enumeration":       ("T1087.001", "Account Discovery: Local Account"),
    "db_credential_exposure": ("T1552.001", "Credentials In Files"),
    "env_exposure":           ("T1552.001", "Credentials In Files"),
    "generic_probe":          ("T1595",     "Active Scanning"),
}

# ── Query/body keyword → TTP ──────────────────────────────────────────────────
KEYWORD_TTP_MAP = {
    "whoami":  ("T1033",     "System Owner/User Discovery"),
    "uname":   ("T1082",     "System Information Discovery"),
    "sudo":    ("T1548.003", "Abuse Elevation Control: Sudo"),
    "passwd":  ("T1003.008", "OS Credential Dumping"),
    "netstat": ("T1049",     "System Network Connections Discovery"),
    "ps aux":  ("T1057",     "Process Discovery"),
    "wget":    ("T1105",     "Ingress Tool Transfer"),
    "curl":    ("T1105",     "Ingress Tool Transfer"),
    "bash -i": ("T1059.004", "Command and Scripting Interpreter: Unix Shell"),
    "/dev/tcp":("T1059.004", "Command and Scripting Interpreter: Unix Shell"),
    "nc -e":   ("T1059.004", "Command and Scripting Interpreter: Unix Shell"),
    "union select": ("T1190", "Exploit Public-Facing Application"),
    "1=1":          ("T1190", "Exploit Public-Facing Application"),
    "<script":      ("T1059.007", "XSS / JavaScript"),
}


def map_to_mitre(path: str, query: str, scenario: str, body: str) -> tuple | None:
    """
    Return the best-matching (technique_id, technique_name) for this event,
    or None if no match found.
    """
    combined = (path + " " + query + " " + body).lower()

    # Scenario is the highest-confidence signal
    if scenario in SCENARIO_TTP_MAP:
        return SCENARIO_TTP_MAP[scenario]

    # Path match
    for path_key, ttp in PATH_TTP_MAP.items():
        if path_key in combined:
            return ttp

    # Keyword match
    for keyword, ttp in KEYWORD_TTP_MAP.items():
        if keyword in combined:
            return ttp

    return None