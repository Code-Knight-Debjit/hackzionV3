# ai_analyzer/profiler.py
"""
Threat Actor Profiling Engine — MongoDB backend.

Schema per attacker IP:
{
    "ip":               str,
    "first_seen":       float (unix timestamp),
    "last_seen":        float,
    "frequency":        int   (total events),
    "attack_types":     list[str],
    "tools_used":       list[str],
    "severity_history": list[str],
    "mitre_techniques": list[str],
    "owasp_categories": list[str],
    "peak_cvss":        float,
    "avg_cvss":         float,
    "pattern":          str  (manual | automated | tool-based | mixed),
    "threat_level":     str  (low | medium | high | critical),
}
"""

import time
import logging
from motor.motor_asyncio import AsyncIOMotorClient
import os

logger = logging.getLogger("ai_analyzer.profiler")

# ── MongoDB connection ────────────────────────────────────────────────────────
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://mongo:27017")
MONGO_DB  = os.environ.get("MONGO_DB",  "hackzion")

_client     = None
_db         = None
_profiles   = None   # profiles collection
_logs       = None   # attack_logs collection


def _get_collections():
    """Lazy initialise MongoDB motor client — safe to call multiple times."""
    global _client, _db, _profiles, _logs
    if _profiles is None:
        _client   = AsyncIOMotorClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        _db       = _client[MONGO_DB]
        _profiles = _db["attacker_profiles"]
        _logs     = _db["attack_logs"]
    return _profiles, _logs


def _compute_threat_level(frequency: int, peak_cvss: float, severity_history: list) -> str:
    """Derive an overall threat level from profile data."""
    critical_count = severity_history.count("Critical")
    high_count     = severity_history.count("High")

    if peak_cvss >= 9.0 or critical_count >= 2:
        return "critical"
    if peak_cvss >= 7.0 or high_count >= 3 or frequency >= 50:
        return "high"
    if peak_cvss >= 4.0 or frequency >= 10:
        return "medium"
    return "low"


def _compute_pattern(behaviors: list[str]) -> str:
    """Derive the dominant behavioral pattern from all recorded behaviors."""
    if not behaviors:
        return "unknown"
    counts = {b: behaviors.count(b) for b in set(behaviors)}
    dominant = max(counts, key=counts.get)
    if len(counts) > 1:
        return "mixed"
    return dominant


async def update_profile(ip: str, report: dict) -> dict:
    """
    Upsert threat actor profile in MongoDB.

    If the IP is new → create full profile.
    If it exists    → increment counters, append history lists, update derived fields.

    Returns the final profile dict (after update).
    """
    profiles, _ = _get_collections()

    now      = time.time()
    severity = report.get("severity", "Low")
    cvss     = report.get("cvss_score", 0.0)
    ttp      = report.get("mitre_technique", "")
    owasp    = report.get("owasp_category", "")
    tool     = report.get("tool_detected")
    behavior = report.get("behavior", "automated")
    a_type   = report.get("attack_type", "Unknown")

    try:
        existing = await profiles.find_one({"ip": ip})

        if existing:
            # ── Update existing profile ───────────────────────────────────────
            new_freq     = existing["frequency"] + 1
            sev_history  = existing.get("severity_history", []) + [severity]
            cvss_history = existing.get("cvss_history", []) + [cvss]
            a_types      = list(set(existing.get("attack_types", []) + [a_type]))
            tools        = list(set(filter(None, existing.get("tools_used", []) + ([tool] if tool else []))))
            mitres       = list(set(existing.get("mitre_techniques", []) + ([ttp] if ttp else [])))
            owasps       = list(set(existing.get("owasp_categories", []) + ([owasp] if owasp else [])))
            behaviors    = existing.get("behaviors", []) + [behavior]

            peak_cvss    = max(cvss_history)
            avg_cvss     = round(sum(cvss_history) / len(cvss_history), 2)
            pattern      = _compute_pattern(behaviors)
            threat_level = _compute_threat_level(new_freq, peak_cvss, sev_history)

            update_doc = {
                "$set": {
                    "last_seen":       now,
                    "frequency":       new_freq,
                    "attack_types":    a_types,
                    "tools_used":      tools,
                    "severity_history":sev_history[-100:],   # keep last 100
                    "cvss_history":    cvss_history[-100:],
                    "mitre_techniques":mitres,
                    "owasp_categories":owasps,
                    "behaviors":       behaviors[-100:],
                    "peak_cvss":       peak_cvss,
                    "avg_cvss":        avg_cvss,
                    "pattern":         pattern,
                    "threat_level":    threat_level,
                }
            }
            await profiles.update_one({"ip": ip}, update_doc)

        else:
            # ── Create new profile ────────────────────────────────────────────
            cvss_history = [cvss]
            sev_history  = [severity]
            behaviors    = [behavior]

            new_profile = {
                "ip":               ip,
                "first_seen":       now,
                "last_seen":        now,
                "frequency":        1,
                "attack_types":     [a_type],
                "tools_used":       [tool] if tool else [],
                "severity_history": sev_history,
                "cvss_history":     cvss_history,
                "mitre_techniques": [ttp] if ttp else [],
                "owasp_categories": [owasp] if owasp else [],
                "behaviors":        behaviors,
                "peak_cvss":        cvss,
                "avg_cvss":         cvss,
                "pattern":          behavior,
                "threat_level":     _compute_threat_level(1, cvss, sev_history),
            }
            await profiles.insert_one(new_profile)

        # Return current state
        result = await profiles.find_one({"ip": ip}, {"_id": 0})
        return result or {}

    except Exception as e:
        logger.error(f"MongoDB profile update failed for {ip}: {e}")
        return {"ip": ip, "error": str(e)}


async def get_profile(ip: str) -> dict | None:
    """Retrieve the full threat actor profile for an IP."""
    profiles, _ = _get_collections()
    try:
        result = await profiles.find_one({"ip": ip}, {"_id": 0})
        return result
    except Exception as e:
        logger.error(f"MongoDB profile lookup failed: {e}")
        return None


async def get_all_profiles(limit: int = 100) -> list[dict]:
    """Return all profiles sorted by threat level and frequency."""
    profiles, _ = _get_collections()
    try:
        cursor = profiles.find({}, {"_id": 0}).sort("frequency", -1).limit(limit)
        return await cursor.to_list(length=limit)
    except Exception as e:
        logger.error(f"MongoDB get_all_profiles failed: {e}")
        return []