# gateway/risk_engine.py

import time
import urllib.parse
from threading import Lock

# ──────────────────────────────────────────────
# In-memory risk store
# Structure: { ip: { "score": int, "last_seen": float } }
# ──────────────────────────────────────────────
risk_store: dict[str, dict] = {}
_lock = Lock()

# ── Tuning constants ──────────────────────────
RATE_THRESHOLD_SECONDS = 2      # Requests faster than this → rate burst
RATE_SCORE_INCREMENT   = 2      # Score added per rate burst
PATH_SCORE_INCREMENT   = 5      # Score added per suspicious path hit
PAYLOAD_SCORE_INCREMENT= 3      # Score added per payload anomaly
DECAY_RATE             = 0.5    # Score decayed per second of idle time
MAX_QUERY_PARAM_LENGTH = 200    # Threshold for "long query param" anomaly

SUSPICIOUS_PATHS = {"/admin", "/.env", "/config", "/wp-admin", "/etc/passwd"}
ENCODED_PATTERNS = ["%3C", "%3E", "%27", "%22", "..%2F", "%00"]  # XSS, traversal, null

# ── Thresholds ────────────────────────────────
THRESHOLD_REAL      = 5
THRESHOLD_MONITOR   = 15


def _decay_score(entry: dict, now: float) -> int:
    """Apply time-based score decay to reward idle IPs."""
    idle_seconds = now - entry.get("last_seen", now)
    decayed = max(0, entry["score"] - int(idle_seconds * DECAY_RATE))
    return decayed


def score_request(metadata: dict) -> int:
    """
    Compute and persist a cumulative risk score for the requesting IP.
    Returns the updated score (int).
    """
    ip        = metadata["ip"]
    path      = metadata.get("path", "")
    query     = metadata.get("query", "")
    now       = metadata.get("timestamp", time.time())

    with _lock:
        # Initialise entry if first time seen
        if ip not in risk_store:
            risk_store[ip] = {"score": 0, "last_seen": now}

        entry = risk_store[ip]

        # ── 1. Apply decay for idle time ──────────
        entry["score"] = _decay_score(entry, now)

        # ── 2. Rate-based scoring ─────────────────
        time_since_last = now - entry["last_seen"]
        if time_since_last < RATE_THRESHOLD_SECONDS:
            entry["score"] += RATE_SCORE_INCREMENT

        # ── 3. Suspicious path scoring ────────────
        # Check exact matches and prefix matches
        path_lower = path.lower()
        for suspicious in SUSPICIOUS_PATHS:
            if path_lower == suspicious or path_lower.startswith(suspicious + "/"):
                entry["score"] += PATH_SCORE_INCREMENT
                break  # Only penalise once per request for path

        # ── 4. Payload anomaly scoring ────────────
        # Long query string
        if len(query) > MAX_QUERY_PARAM_LENGTH:
            entry["score"] += PAYLOAD_SCORE_INCREMENT

        # URL-encoded payloads (XSS, traversal, null bytes)
        query_upper = query.upper()
        for pattern in ENCODED_PATTERNS:
            if pattern in query_upper:
                entry["score"] += PAYLOAD_SCORE_INCREMENT
                break  # Penalise once per request for encoded patterns

        # ── 5. Update last_seen timestamp ─────────
        entry["last_seen"] = now

        return entry["score"]


def get_decision(score: int) -> str:
    """Map a numeric score to a routing decision label."""
    if score < THRESHOLD_REAL:
        return "real"
    elif score < THRESHOLD_MONITOR:
        return "monitor"
    else:
        return "honeypot"


def get_store_snapshot() -> dict:
    """Return a read-only snapshot of risk_store (for debugging/monitoring)."""
    with _lock:
        return {
            ip: {"score": data["score"], "last_seen": data["last_seen"]}
            for ip, data in risk_store.items()
        }
    
def force_escalate(ip: str, increment: int = 30):
    """
    Called by the response engine to permanently push an IP's score
    above the honeypot threshold, ensuring all future requests are trapped.
    """
    with _lock:
        now = __import__("time").time()
        if ip not in risk_store:
            risk_store[ip] = {"score": 0, "last_seen": now}
        risk_store[ip]["score"] += increment
        risk_store[ip]["last_seen"] = now