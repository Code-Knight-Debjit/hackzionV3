# detection/behavior_analyzer.py
"""
Behavior Analyzer — parses honeypot event logs, tracks per-IP command sequences,
detects attack patterns, and maintains a session behavior profile.
"""

import time
from collections import defaultdict
from threading import Lock
from detection.mitre_mapper import map_to_mitre
from detection.ml_model import classify_attack

# ── Session store ─────────────────────────────────────────────────────────────
# { ip: { "events": [...], "first_seen": ts, "last_seen": ts, "scenarios": [...] } }
_sessions: dict[str, dict] = defaultdict(lambda: {
    "events":     [],
    "first_seen": time.time(),
    "last_seen":  time.time(),
    "scenarios":  [],
    "mitre_ttps": [],
    "attack_type": None,
    "severity":   "LOW",
})
_lock = Lock()

# ── Severity thresholds ───────────────────────────────────────────────────────
CRITICAL_SCENARIOS = {"rce_attempt", "db_credential_exposure", "path_traversal"}
MEDIUM_SCENARIOS   = {"sql_injection", "admin_access", "user_enumeration", "env_exposure"}


def ingest_event(event: dict) -> dict:
    """
    Process a single honeypot event.
    Returns an enriched analysis result for the response engine.
    """
    ip       = event.get("ip", "unknown")
    path     = event.get("path", "/")
    query    = event.get("query", "")
    scenario = event.get("scenario", "generic_probe")
    body     = event.get("body", "")

    with _lock:
        session = _sessions[ip]
        session["last_seen"] = time.time()
        session["events"].append(event)
        session["scenarios"].append(scenario)

        # MITRE ATT&CK mapping
        ttp = map_to_mitre(path=path, query=query, scenario=scenario, body=body)
        if ttp and ttp not in session["mitre_ttps"]:
            session["mitre_ttps"].append(ttp)

        # ML classification
        attack_type = classify_attack(
            path=path,
            query=query,
            scenario=scenario,
            body=body,
            event_count=len(session["events"]),
        )
        session["attack_type"] = attack_type["attack_type"]

        # Severity escalation
        if scenario in CRITICAL_SCENARIOS:
            session["severity"] = "CRITICAL"
        elif scenario in MEDIUM_SCENARIOS and session["severity"] != "CRITICAL":
            session["severity"] = "MEDIUM"

        return {
            "ip":          ip,
            "scenario":    scenario,
            "attack_type": session["attack_type"],
            "severity":    session["severity"],
            "mitre_ttps":  session["mitre_ttps"],
            "event_count": len(session["events"]),
            "session_age": session["last_seen"] - session["first_seen"],
        }


def get_all_sessions() -> dict:
    with _lock:
        return dict(_sessions)


def get_session(ip: str) -> dict:
    with _lock:
        return dict(_sessions.get(ip, {}))