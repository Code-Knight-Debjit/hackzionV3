# response/response_engine.py
"""
Response Engine — determines and executes the correct defensive action
based on detection engine output.

Severity → Action:
  LOW      → ignore (log only)
  MEDIUM   → sanitize + log
  CRITICAL → redirect_to_honeypot + trigger_alert + escalate risk score
"""

import time
import logging
import httpx

logger = logging.getLogger("response.engine")

GATEWAY_URL    = "http://gateway:8000"
ALERT_STORE: list[dict] = []    # In-memory alert log (exposed via API)


# ── Actions ───────────────────────────────────────────────────────────────────

def ignore(analysis: dict) -> dict:
    logger.info(f"[LOW] Ignoring low-severity event from {analysis.get('ip')}")
    return {"action": "ignore", "ip": analysis.get("ip")}


def sanitize(analysis: dict) -> dict:
    """Log the event and mark IP for enhanced monitoring."""
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
    """
    Forcefully escalate the IP's risk score in the gateway so all
    subsequent requests are permanently routed to the honeypot.
    """
    ip = analysis.get("ip")
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            await client.post(
                f"{GATEWAY_URL}/risk/escalate",
                json={"ip": ip, "increment": 30},   # Push score far above honeypot threshold
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
    """Push alert to in-memory store (consumed by monitorapp via /api/alerts)."""
    alert = {
        "id":          len(ALERT_STORE) + 1,
        "name":        analysis.get("attack_type", "Unknown Attack"),
        "severity":    "Critical",
        "timestamp":   time.strftime("%H:%M"),
        "ip":          analysis.get("ip"),
        "mitre_ttps":  analysis.get("mitre_ttps", []),
        "event_count": analysis.get("event_count", 0),
    }
    ALERT_STORE.append(alert)
    logger.critical(
        f"[ALERT] {alert['name']} from {alert['ip']} | "
        f"TTPs: {alert['mitre_ttps']}"
    )
    return alert


# ── Main dispatcher ───────────────────────────────────────────────────────────

async def dispatch(analysis: dict) -> dict:
    """
    Route to the correct response action based on severity.
    Returns the action result dict.
    """
    severity = analysis.get("severity", "LOW")

    if severity == "LOW":
        return ignore(analysis)

    elif severity == "MEDIUM":
        return sanitize(analysis)

    else:  # CRITICAL
        honeypot_result = await redirect_to_honeypot(analysis)
        alert_result    = trigger_alert(analysis)
        return {
            "action":   "critical_response",
            "honeypot": honeypot_result,
            "alert":    alert_result,
        }


def get_alerts() -> list:
    return list(ALERT_STORE)


def get_defense_logs() -> list:
    """Return defense action history formatted for monitorapp DefenseScreen."""
    return [
        {
            "time":   time.strftime("%H:%M", time.localtime(a.get("ts", time.time()))),
            "action": f"Blocked IP: {a.get('ip')}",
            "target": a.get('name', 'Unknown'),
        }
        for a in ALERT_STORE
    ]