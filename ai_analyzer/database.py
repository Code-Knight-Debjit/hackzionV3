# ai_analyzer/database.py
"""
MongoDB database layer for AI analyzer.
"""

import time
import logging
from motor.motor_asyncio import AsyncIOMotorClient
import os

logger = logging.getLogger("ai_analyzer.database")

MONGO_URI = os.environ.get("MONGO_URI", "mongodb://mongo:27017")
MONGO_DB  = os.environ.get("MONGO_DB",  "hackzion")

_client = None
_db     = None


def _get_db():
    global _client, _db
    if _db is None:
        _client = AsyncIOMotorClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        _db     = _client[MONGO_DB]
    return _db


async def insert_attack_log(report: dict) -> str | None:
    """Insert a full intelligence report into MongoDB attack_logs."""
    db = _get_db()
    try:
        doc = {**report, "stored_at": time.time()}
        doc.pop("_id", None)
        result = await db["attack_logs"].insert_one(doc)
        logger.debug(f"Inserted attack log _id={result.inserted_id} ip={report.get('ip')}")
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"insert_attack_log failed: {e}")
        return None


async def get_attack_logs(
    ip:       str | None = None,
    severity: str | None = None,
    limit:    int        = 50,
) -> list[dict]:
    """Query attack logs with optional IP/severity filters."""
    db = _get_db()
    try:
        query: dict = {}
        if ip:
            query["ip"] = ip
        if severity:
            query["severity"] = severity

        cursor = (
            db["attack_logs"]
            .find(query, {"_id": 0})
            .sort("timestamp", -1)
            .limit(limit)
        )
        return await cursor.to_list(length=limit)
    except Exception as e:
        logger.error(f"get_attack_logs failed: {e}")
        return []


async def get_all_attacks(
    ip:       str | None = None,
    severity: str | None = None,
    limit:    int        = 100,
) -> list[dict]:
    """
    Return ALL attacks ever recorded, newest first.
    Projects only the fields needed by GET /attacks —
    keeps the response lean and consistent regardless of
    how many fields the internal report contains.

    Called by: ai_analyzer/main.py GET /attacks
    Updated:   every time run_analysis_pipeline() completes (per attack)
    """
    db = _get_db()
    try:
        query: dict = {}
        if ip:
            query["ip"] = ip
        if severity:
            # Case-insensitive match
            import re
            query["severity"] = {"$regex": f"^{re.escape(severity)}$", "$options": "i"}

        # Project only what the /attacks consumer needs
        projection = {
            "_id":               0,
            "ip":                1,
            "timestamp":         1,
            "attack_type":       1,
            "severity":          1,
            "cvss_score":        1,
            "behavior":          1,
            "mitre_technique":   1,
            "owasp_category":    1,
            "matched_signature": 1,
            "mitigation":        1,
            "llm_used":          1,
            "confidence":        1,
            "pattern_type":      1,
        }

        cursor = (
            db["attack_logs"]
            .find(query, projection)
            .sort("timestamp", -1)
            .limit(limit)
        )
        results = await cursor.to_list(length=limit)

        # Normalise any None values so the API always returns clean JSON
        for r in results:
            r.setdefault("attack_type",       "Unknown")
            r.setdefault("severity",          "Low")
            r.setdefault("cvss_score",        0.0)
            r.setdefault("behavior",          "unknown")
            r.setdefault("mitre_technique",   "")
            r.setdefault("owasp_category",    "")
            r.setdefault("matched_signature", "")
            r.setdefault("mitigation",        "")
            r.setdefault("llm_used",          False)
            r.setdefault("confidence",        0.0)

        return results

    except Exception as e:
        logger.error(f"get_all_attacks failed: {e}")
        return []


async def get_stats() -> dict:
    """Aggregate statistics from attack_logs collection."""
    db = _get_db()
    try:
        total = await db["attack_logs"].count_documents({})

        sev_pipeline = [
            {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
            {"$sort":  {"count": -1}},
        ]
        sev_cursor    = db["attack_logs"].aggregate(sev_pipeline)
        sev_breakdown = {d["_id"]: d["count"] async for d in sev_cursor}

        type_pipeline = [
            {"$group": {"_id": "$attack_type", "count": {"$sum": 1}}},
            {"$sort":  {"count": -1}},
            {"$limit": 5},
        ]
        type_cursor = db["attack_logs"].aggregate(type_pipeline)
        top_types   = [(d["_id"], d["count"]) async for d in type_cursor]

        total_profiles = await db["attacker_profiles"].count_documents({})

        return {
            "total_attack_logs":  total,
            "total_profiles":     total_profiles,
            "severity_breakdown": sev_breakdown,
            "top_attack_types":   top_types,
        }
    except Exception as e:
        logger.error(f"get_stats failed: {e}")
        return {}