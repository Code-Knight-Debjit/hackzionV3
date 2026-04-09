# logs/logger.py
"""
Central event logger for HackzionV3.
Enforces strict schema. Writes to SQLite via database/db.py.
Can be imported by any service.
"""

import asyncio
import hashlib
import json
import logging
import time
import uuid

_stdout_logger = logging.getLogger("hackzion.events")
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
)

# ── Strict schema definition ──────────────────────────────────────────────────
SCHEMA_FIELDS = {
    "timestamp":         float,
    "ip":                str,
    "session_id":        str,
    "attack_type":       str,
    "attack_vector":     str,
    "mitre_technique":   str,
    "attack_phase":      str,
    "severity":          str,
    "confidence":        float,
    "risk_score":        int,
    "action_taken":      str,
    "status":            str,
    "honeypot":          bool,
    "commands_executed": list,
    "skill_level":       str,
}

# Valid enum values
VALID_SEVERITY    = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
VALID_PHASES      = {"recon", "weaponize", "deliver", "exploit", "install", "c2", "exfil", "unknown"}
VALID_SKILL       = {"script_kiddie", "intermediate", "advanced", "nation_state", "unknown"}
VALID_STATUS      = {"detected", "trapped", "blocked", "escalated", "ignored"}
VALID_ACTIONS     = {"ignore", "log", "sanitize", "redirect_honeypot", "block", "alert", "escalate"}
VALID_VECTORS     = {
    "web_app", "brute_force", "sql_injection", "xss", "rce",
    "path_traversal", "recon", "malware", "kernel_exploit",
    "credential_harvest", "generic_probe", "unknown"
}


def _derive_session_id(ip: str) -> str:
    """Deterministic session ID from IP + hour bucket."""
    bucket = str(int(time.time() // 3600))
    return hashlib.md5(f"{ip}:{bucket}".encode()).hexdigest()[:16]


def _infer_attack_vector(attack_type: str, scenario: str = "") -> str:
    mapping = {
        "SQL Injection":           "sql_injection",
        "Cross-Site Scripting":    "xss",
        "Remote Code Execution":   "rce",
        "Path Traversal":          "path_traversal",
        "Credential Harvesting":   "credential_harvest",
        "Privilege Escalation Probe": "recon",
        "Automated Scanner":       "recon",
        "Brute Force":             "brute_force",
        "Malware Deployment":      "malware",
        "Kernel Exploit":          "kernel_exploit",
        "Generic Reconnaissance":  "generic_probe",
    }
    return mapping.get(attack_type, scenario if scenario in VALID_VECTORS else "unknown")


def _infer_attack_phase(attack_type: str, scenario: str = "") -> str:
    phase_map = {
        "recon":                   "recon",
        "generic_probe":           "recon",
        "sql_injection":           "exploit",
        "rce_attempt":             "exploit",
        "path_traversal":          "exploit",
        "db_credential_exposure":  "exfil",
        "env_exposure":            "exfil",
        "admin_access":            "exploit",
        "malware":                 "install",
        "kernel_exploit":          "exploit",
        "brute_force":             "deliver",
    }
    return phase_map.get(scenario, phase_map.get(attack_type.lower().replace(" ", "_"), "unknown"))


def _infer_skill_level(attack_type: str, mitre_techniques: list, event_count: int) -> str:
    advanced_types = {"Remote Code Execution", "Kernel Exploit", "Malware Deployment"}
    mid_types = {"SQL Injection", "Path Traversal", "Credential Harvesting"}
    if attack_type in advanced_types or len(mitre_techniques) > 3:
        return "advanced"
    if event_count > 50:
        return "advanced"
    if attack_type in mid_types or event_count > 10:
        return "intermediate"
    return "script_kiddie"


def build_event(
    ip: str,
    attack_type: str,
    severity: str,
    risk_score: int,
    action_taken: str,
    mitre_ttps: list = None,
    scenario: str = "",
    confidence: float = 0.75,
    commands_executed: list = None,
    extra: dict = None,
) -> dict:
    """
    Build a fully validated log event dict matching the strict schema.
    All callers should use this factory instead of constructing dicts manually.
    """
    mitre_ttps         = mitre_ttps or []
    commands_executed  = commands_executed or []
    extra              = extra or {}

    mitre_technique = mitre_ttps[0][0] if mitre_ttps and isinstance(mitre_ttps[0], (list, tuple)) \
        else (mitre_ttps[0] if mitre_ttps else "T1595")

    event = {
        "timestamp":        time.time(),
        "ip":               str(ip),
        "session_id":       _derive_session_id(ip),
        "attack_type":      attack_type,
        "attack_vector":    _infer_attack_vector(attack_type, scenario),
        "mitre_technique":  mitre_technique,
        "attack_phase":     _infer_attack_phase(attack_type, scenario),
        "severity":         severity if severity in VALID_SEVERITY else "LOW",
        "confidence":       round(float(confidence), 3),
        "risk_score":       int(risk_score),
        "action_taken":     action_taken if action_taken in VALID_ACTIONS else "log",
        "status":           "trapped" if scenario not in ("", "generic_probe") else "detected",
        "honeypot":         True,
        "commands_executed": commands_executed,
        "skill_level":      _infer_skill_level(attack_type, mitre_ttps, extra.get("event_count", 1)),
    }
    return event


# ── DB import is deferred to avoid circular imports at module load ────────────
_db_available = False
try:
    from database.db import insert_event as _db_insert_event
    _db_available = True
except ImportError:
    pass


async def log_event_async(data: dict):
    """Async version — use inside FastAPI/asyncio contexts."""
    _stdout_logger.info(json.dumps(data))
    if _db_available:
        try:
            await _db_insert_event(data)
        except Exception as e:
            _stdout_logger.error(f"DB write failed: {e}")


def log_event(data: dict):
    """
    Sync wrapper — safe to call from anywhere.
    Schedules async DB write without blocking caller.
    """
    _stdout_logger.info(json.dumps(data))
    if _db_available:
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.ensure_future(_db_insert_event(data))
            else:
                loop.run_until_complete(_db_insert_event(data))
        except RuntimeError:
            asyncio.run(_db_insert_event(data))
        except Exception as e:
            _stdout_logger.error(f"DB write failed: {e}")