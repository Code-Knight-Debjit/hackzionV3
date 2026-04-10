# response/response_engine.py
"""
Response Engine — determines and executes the correct defensive action
based on detection engine output.

Severity → Action:
  LOW      → ignore (log only)
  MEDIUM   → sanitize + log + async AI analysis
  CRITICAL → redirect_to_honeypot + trigger_alert + async AI analysis
"""

import time
import logging
import httpx
import asyncio
import sys

logger = logging.getLogger("response.engine")

GATEWAY_URL     = "http://gateway:8000"
AI_ANALYZER_URL = "http://ai_analyzer:8004"

ALERT_STORE: list[dict] = []  # In-memory alert log

# ── DB Import ────────────────────────────────────────────────────────────────

sys.path.insert(0, "/app")
try:
    from database.db import insert_alert as _db_insert_alert
    _db_available = True
except ImportError:
    _db_available = False

# ── AI ANALYZER ASYNC CALL ───────────────────────────────────────────────────

async def _fire_ai_analysis(analysis: dict):
    """Fire-and-forget: send to AI analyzer without blocking response pipeline."""
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            await client.post(
                f"{AI_ANALYZER_URL}/analyze/async",
                json={
                    "ip":           analysis.get("ip", "unknown"),
                    "attack_type":  analysis.get("attack_type", ""),
                    "severity":     analysis.get("severity", "LOW"),
                    "scenario":     analysis.get("scenario", ""),
                    "score":        str(analysis.get("risk_score", 0)),
                    "path":         analysis.get("path", "/"),
                    "timestamp":    time.time(),
                },
            )
    except Exception as e:
        logger.debug(f"AI analyzer call failed (non-blocking): {e}")

# ── Actions ──────────────────────────────────────────────────────────────────

def ignore(analysis: dict) -> dict:
    logger.info(f"[LOW] Ignoring low-severity event from {analysis.get('ip')}")
    return {"action": "ignore", "ip": analysis.get("ip")}


def sanitize(analysis: dict) -> dict:
    logger.warning(
        f"[MEDIUM] Sanitizing/logging event | IP={analysis.get('ip')} "
        f"attack={analysis.get('attack_type')} ttps={analysis.get('mitre_ttps')}"
    )
    return {
        "action":      "sanitize_and_log",
        "ip":          analysis.get("ip"),
        "attack_type": analysis.get("attack_type"),
        "mitre_ttps":  analysis.get("mitre_ttps"),
        "logged_at":   time.time(),
    }


async def redirect_to_honeypot(analysis: dict) -> dict:
    ip = analysis.get("ip")
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            await client.post(
                f"{GATEWAY_URL}/risk/escalate",
                json={"ip": ip, "increment": 30},
            )
        logger.critical(f"[CRITICAL] Escalated IP {ip} → honeypot lock")
    except Exception as e:
        logger.error(f"Failed to escalate {ip}: {e}")

    return {
        "action": "redirect_to_honeypot",
        "ip":     ip,
        "ts":     time.time(),
    }


def trigger_alert(analysis: dict) -> dict:
    alert = {
        "id":          len(ALERT_STORE) + 1,
        "name":        analysis.get("attack_type", "Unknown Attack"),
        "severity":    "Critical",
        "timestamp":   time.strftime("%H:%M"),
        "ts":          time.time(),
        "ip":          analysis.get("ip"),
        "mitre_ttps":  analysis.get("mitre_ttps", []),
        "event_count": analysis.get("event_count", 0),
    }

    ALERT_STORE.append(alert)

    logger.critical(
        f"[ALERT] {alert['name']} from {alert['ip']} | TTPs: {alert['mitre_ttps']}"
    )

    # Persist to DB
    if _db_available:
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(_db_insert_alert(alert))
            else:
                loop.run_until_complete(_db_insert_alert(alert))
        except Exception:
            pass

    return alert


# ── Main dispatcher ───────────────────────────────────────────────────────────

async def dispatch(analysis: dict) -> dict:
    """
    Route to the correct response action based on severity.
    """

    severity = analysis.get("severity", "LOW")

    if severity == "LOW":
        return ignore(analysis)

    elif severity == "MEDIUM":
        # 🔥 NEW: async AI analysis
        asyncio.create_task(_fire_ai_analysis(analysis))
        return sanitize(analysis)

    else:  # CRITICAL
        # 🔥 NEW: async AI analysis
        asyncio.create_task(_fire_ai_analysis(analysis))

        honeypot_result = await redirect_to_honeypot(analysis)
        alert_result    = trigger_alert(analysis)

        return {
            "action":   "critical_response",
            "honeypot": honeypot_result,
            "alert":    alert_result,
        }


# ── API Helpers ───────────────────────────────────────────────────────────────

def get_alerts() -> list:
    return list(ALERT_STORE)


def get_defense_logs() -> list:
    return [
        {
            "time":   time.strftime("%H:%M", time.localtime(a.get("ts", time.time()))),
            "action": f"Blocked IP: {a.get('ip')}",
            "target": a.get('name', 'Unknown'),
        }
        for a in ALERT_STORE
    ]