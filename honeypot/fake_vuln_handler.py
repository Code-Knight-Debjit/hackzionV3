# honeypot/fake_vuln_handler.py
"""
Maps attacker HTTP requests to believable fake vulnerability responses.
Covers: SQLi, path traversal, RCE, credential stuffing, admin panels.
"""

from honeypot.ai_engine import get_fake_db_dump, FAKE_ENV_CONTENTS

# ── Fake admin panel HTML ─────────────────────────────────────────────────────
FAKE_ADMIN_HTML = """<!DOCTYPE html>
<html>
<head><title>Admin Panel — Internal</title></head>
<body style="font-family:monospace;background:#1a1a1a;color:#00ff00;padding:40px">
<h2>⚙️  CMS Admin Panel v2.3.1</h2>
<p>Logged in as: <strong>admin</strong></p>
<ul>
  <li><a href="/admin/users" style="color:#00ff00">Manage Users</a></li>
  <li><a href="/admin/db" style="color:#00ff00">Database Console</a></li>
  <li><a href="/admin/files" style="color:#00ff00">File Manager</a></li>
  <li><a href="/admin/logs" style="color:#00ff00">System Logs</a></li>
</ul>
<p style="color:#ff6b6b">⚠️ Internal network access only</p>
</body>
</html>"""

FAKE_ADMIN_USERS = {
    "users": [
        {"id": 1, "username": "admin",    "role": "superadmin", "email": "admin@corp.internal"},
        {"id": 2, "username": "db_admin", "role": "dba",        "email": "dba@corp.internal"},
        {"id": 3, "username": "devops",   "role": "ops",        "email": "devops@corp.internal"},
    ]
}

FAKE_CONFIG = {
    "database": {
        "host": "10.0.1.200",
        "port": 5432,
        "name": "customers_prod",
        "user": "db_admin",
        "pass": "Pr0d$ecret!2024",
    },
    "cache": {"host": "10.0.1.201", "port": 6379, "pass": "r3d1s_p4ss"},
    "debug": True,
    "secret_key": "sk-prod-8f3a2b1c9d4e7f6a",
}

# ── SQL Injection fake responses ──────────────────────────────────────────────
SQLI_FAKE_DUMP = {
    "error":  False,
    "query":  "SELECT * FROM users",   # Reflected back — classic SQLi fingerprint
    "rows":   3,
    "result": [
        {"id": 1, "username": "admin",    "password_hash": "5f4dcc3b5aa765d61d8327deb882cf99"},
        {"id": 2, "username": "john.doe", "password_hash": "e10adc3949ba59abbe56e057f20f883e"},
        {"id": 3, "username": "jane.doe", "password_hash": "25d55ad283aa400af464c76d713c07ad"},
    ],
}

# ── Path traversal fake responses ─────────────────────────────────────────────
TRAVERSAL_RESPONSES = {
    "/etc/passwd":  "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n",
    "/etc/shadow":  "root:$6$rounds=656000$fakehash:19000:0:99999:7:::\n",
    "/etc/hosts":   "127.0.0.1 localhost\n10.0.1.45 prod-db-01\n10.0.1.200 db-server\n",
    ".env":         FAKE_ENV_CONTENTS,
    "config.php":   "<?php\n$db_pass = 'Pr0d$ecret!2024';\n$secret = 'sk-prod-8f3a2b1c9d4e7f6a';\n?>",
}


def handle_path(path: str, method: str, query: str, body: bytes) -> dict:
    """
    Given an incoming request, return a fake response dict with:
      - status_code
      - content_type
      - body (str | dict)
      - scenario (label for detection engine)
    """
    p = path.lower().rstrip("/")
    q = query.lower()

    # ── Admin panel ──────────────────────────────────────────────
    if p in ("/admin", "/admin/login", "/wp-admin", "/administrator"):
        return {
            "status_code":   200,
            "content_type":  "text/html",
            "body":          FAKE_ADMIN_HTML,
            "scenario":      "admin_access",
        }

    if p == "/admin/users":
        return {
            "status_code":  200,
            "content_type": "application/json",
            "body":         FAKE_ADMIN_USERS,
            "scenario":     "user_enumeration",
        }

    if p in ("/admin/db", "/admin/database"):
        return {
            "status_code":  200,
            "content_type": "application/json",
            "body":         get_fake_db_dump(),
            "scenario":     "db_credential_exposure",
        }

    # ── Config / env exposure ────────────────────────────────────
    if p in ("/.env", "/config", "/config.php", "/settings.py", "/app/config"):
        return {
            "status_code":  200,
            "content_type": "text/plain",
            "body":         FAKE_ENV_CONTENTS,
            "scenario":     "env_exposure",
        }

    # ── Path traversal ───────────────────────────────────────────
    for file_key, content in TRAVERSAL_RESPONSES.items():
        if file_key in path:
            return {
                "status_code":  200,
                "content_type": "text/plain",
                "body":         content,
                "scenario":     "path_traversal",
            }

    # ── SQL injection probe ──────────────────────────────────────
    sqli_markers = ["'", "\"", " or ", " and ", "1=1", "union", "select", "drop"]
    if any(m in q for m in sqli_markers):
        return {
            "status_code":  200,
            "content_type": "application/json",
            "body":         SQLI_FAKE_DUMP,
            "scenario":     "sql_injection",
        }

    # ── RCE / shell upload probe ─────────────────────────────────
    rce_markers = ["cmd=", "exec=", "system=", "shell=", "passthru=", "eval="]
    if any(m in q for m in rce_markers) or b"bash" in body or b"sh -i" in body:
        return {
            "status_code":  200,
            "content_type": "text/plain",
            "body":         "uid=0(root) gid=0(root) groups=0(root)\n",
            "scenario":     "rce_attempt",
        }

    # ── Default honeypot landing ─────────────────────────────────
    return {
        "status_code":  200,
        "content_type": "application/json",
        "body": {
            "status":  "ok",
            "server":  "Apache/2.4.41 (Ubuntu)",
            "version": "2.3.1",
        },
        "scenario": "generic_probe",
    }