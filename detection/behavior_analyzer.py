# detection/behavior_analyzer.py
"""
Behavior Analyzer — tracks per-IP attack sessions with full history.

Session lifecycle:
  - First request from an IP → new session created
  - Requests within SESSION_TIMEOUT seconds → appended to same session
  - Gap > SESSION_TIMEOUT → current session archived, new session started
  - All completed sessions are stored in _completed_sessions (never dropped)
  - Active (ongoing) sessions live in _active_sessions
"""

import time
import uuid
from collections import defaultdict
from threading import Lock
from detection.mitre_mapper import map_to_mitre
from detection.ml_model import classify_attack

# ── Tuning ────────────────────────────────────────────────────────────────────
SESSION_TIMEOUT = 60  # seconds of inactivity before a session is considered closed

# ── Storage ───────────────────────────────────────────────────────────────────
# Active sessions: { ip → session_dict }
# One per IP at a time; replaced when timed out.
_active_sessions: dict[str, dict] = {}

# Completed sessions: flat list, all historical sessions, never overwritten.
_completed_sessions: list[dict] = []

_lock = Lock()

# ── Severity thresholds ───────────────────────────────────────────────────────
CRITICAL_SCENARIOS = {"rce_attempt", "db_credential_exposure", "path_traversal"}
MEDIUM_SCENARIOS   = {"sql_injection", "admin_access", "user_enumeration", "env_exposure"}


def _new_session(ip: str, now: float) -> dict:
    """Create a blank session dict for a given IP."""
    return {
        "session_id":  str(uuid.uuid4())[:16],
        "ip":          ip,
        "first_seen":  now,
        "last_seen":   now,
        "events":      [],
        "scenarios":   [],
        "mitre_ttps":  [],
        "attack_type": "Generic Reconnaissance",
        "severity":    "LOW",
        "status":      "active",   # becomes "completed" when archived
    }


def _archive_session(session: dict, now: float):
    """
    Mark a session as completed and move it to the permanent history list.
    Called when a session times out or explicitly closed.
    """
    session["status"]   = "completed"
    session["duration"] = round(now - session["first_seen"], 2)
    _completed_sessions.append(dict(session))   # snapshot copy


def _maybe_rotate_session(ip: str, now: float) -> dict:
    """
    If the IP has an active session that has timed out, archive it and
    return a fresh session. Otherwise return the existing active session.
    If no active session exists, create one.
    """
    if ip in _active_sessions:
        session = _active_sessions[ip]
        idle = now - session["last_seen"]
        if idle > SESSION_TIMEOUT:
            # Session timed out → archive it, start fresh
            _archive_session(session, now)
            _active_sessions[ip] = _new_session(ip, now)
    else:
        _active_sessions[ip] = _new_session(ip, now)

    return _active_sessions[ip]


def ingest_event(event: dict) -> dict:
    """
    Process a single honeypot event.
    Appends to the correct session (rotating if needed).
    Returns enriched analysis result for the response engine.
    """
    ip       = event.get("ip", "unknown")
    path     = event.get("path", "/")
    query    = event.get("query", "")
    scenario = event.get("scenario", "generic_probe")
    body     = event.get("body", "")
    now      = event.get("ts", time.time())

    with _lock:
        session = _maybe_rotate_session(ip, now)

        # Append event and update timestamps
        session["last_seen"] = now
        session["events"].append(event)
        session["scenarios"].append(scenario)

        # MITRE ATT&CK mapping — accumulate all unique TTPs
        ttp = map_to_mitre(path=path, query=query, scenario=scenario, body=body)
        if ttp and ttp not in session["mitre_ttps"]:
            session["mitre_ttps"].append(ttp)

        # ML classification — updates with every new event
        attack_type = classify_attack(
            path=path,
            query=query,
            scenario=scenario,
            body=body,
            event_count=len(session["events"]),
        )
        session["attack_type"] = attack_type["attack_type"]

        # Severity — only ever escalates, never de-escalates
        if scenario in CRITICAL_SCENARIOS:
            session["severity"] = "CRITICAL"
        elif scenario in MEDIUM_SCENARIOS and session["severity"] != "CRITICAL":
            session["severity"] = "MEDIUM"

        return {
            "ip":          ip,
            "session_id":  session["session_id"],
            "scenario":    scenario,
            "attack_type": session["attack_type"],
            "severity":    session["severity"],
            "mitre_ttps":  session["mitre_ttps"],
            "event_count": len(session["events"]),
            "session_age": round(now - session["first_seen"], 2),
        }


# ── Query functions ───────────────────────────────────────────────────────────

def get_all_sessions() -> dict:
    """
    Returns a dict with:
      - active:    currently ongoing sessions keyed by IP
      - completed: full list of all historical sessions (oldest first)
      - summary:   counts
    """
    with _lock:
        now = time.time()
        # Snapshot active sessions, annotating idle time
        active_snapshot = {}
        for ip, s in _active_sessions.items():
            snap = dict(s)
            snap["idle_seconds"] = round(now - s["last_seen"], 1)
            active_snapshot[ip] = snap

        return {
            "active":    active_snapshot,
            "completed": list(_completed_sessions),   # all history, never truncated
            "summary": {
                "active_count":    len(_active_sessions),
                "completed_count": len(_completed_sessions),
                "total_sessions":  len(_active_sessions) + len(_completed_sessions),
            },
        }


def get_session_by_id(session_id: str) -> dict | None:
    """Look up any session (active or completed) by its UUID."""
    with _lock:
        # Check active
        for s in _active_sessions.values():
            if s["session_id"] == session_id:
                return dict(s)
        # Check completed history
        for s in _completed_sessions:
            if s["session_id"] == session_id:
                return dict(s)
        return None


def get_sessions_by_ip(ip: str) -> list[dict]:
    """
    Return ALL sessions (active + completed) for a given IP, oldest first.
    This is the key function that was previously broken — it now returns
    the full history instead of just the current state.
    """
    with _lock:
        history = [dict(s) for s in _completed_sessions if s["ip"] == ip]
        if ip in _active_sessions:
            active = dict(_active_sessions[ip])
            active["idle_seconds"] = round(time.time() - active["last_seen"], 1)
            history.append(active)
        return history


def get_completed_sessions() -> list[dict]:
    """Return all completed (archived) sessions, oldest first."""
    with _lock:
        return list(_completed_sessions)


def get_active_sessions() -> dict:
    """Return only currently active sessions."""
    with _lock:
        return {ip: dict(s) for ip, s in _active_sessions.items()}


def flush_timed_out_sessions():
    """
    Explicitly archive any active sessions that have exceeded SESSION_TIMEOUT.
    Call this periodically (e.g. from a background task) to ensure sessions
    are closed even if no new events arrive for that IP.
    """
    now = time.time()
    with _lock:
        timed_out = [
            ip for ip, s in _active_sessions.items()
            if now - s["last_seen"] > SESSION_TIMEOUT
        ]
        for ip in timed_out:
            _archive_session(_active_sessions.pop(ip), now)