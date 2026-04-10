# ai_analyzer/api_client.py
"""
External Alert API Client.
Sends CRITICAL attack reports to a configurable external webhook/SIEM.
Uses API key authentication. Fire-and-forget with retry.
"""

import logging
import os
import time
import httpx

logger = logging.getLogger("ai_analyzer.api_client")

# ── Config from environment ───────────────────────────────────────────────────
ALERT_API_URL     = os.environ.get("ALERT_API_URL", "")          # e.g. https://siem.corp/api/alert
ALERT_API_KEY     = os.environ.get("ALERT_API_KEY", "")
ALERT_API_TIMEOUT = float(os.environ.get("ALERT_API_TIMEOUT", "5"))
MAX_RETRIES       = 2


def _build_alert_payload(report: dict) -> dict:
    """Build the standardised alert payload for external API."""
    profile = report.get("attacker_profile", {})
    return {
        "source":         "HackzionV3",
        "timestamp":      report.get("timestamp", time.time()),
        "ip":             report.get("ip"),
        "attack_type":    report.get("attack_type"),
        "severity":       report.get("severity"),
        "cvss_score":     report.get("cvss_score"),
        "mitigation":     report.get("mitigation"),
        "mitre_technique":report.get("mitre_technique"),
        "owasp_category": report.get("owasp_category"),
        "matched_signature": report.get("matched_signature"),
        "profile": {
            "frequency":    profile.get("frequency", 1),
            "threat_level": profile.get("threat_level", "unknown"),
            "peak_cvss":    profile.get("peak_cvss", 0),
            "attack_types": profile.get("attack_types", []),
            "tools_used":   profile.get("tools_used", []),
            "pattern":      profile.get("pattern", "unknown"),
        },
    }


async def send_critical_alert(report: dict) -> bool:
    """
    Send a CRITICAL alert to the configured external API.
    Returns True on success, False on failure.
    If no ALERT_API_URL is configured, logs locally and returns True.
    """
    payload = _build_alert_payload(report)
    ip      = report.get("ip", "unknown")

    # If no external endpoint configured — log locally only
    if not ALERT_API_URL:
        logger.critical(
            f"[CRITICAL ALERT — no external endpoint configured] "
            f"IP={ip} type={report.get('attack_type')} "
            f"cvss={report.get('cvss_score')} "
            f"mitigation={report.get('mitigation')}"
        )
        return True

    headers = {
        "Content-Type":  "application/json",
        "Authorization": f"Bearer {ALERT_API_KEY}",
        "X-Source":      "HackzionV3",
    }

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            async with httpx.AsyncClient(timeout=ALERT_API_TIMEOUT) as client:
                response = await client.post(
                    ALERT_API_URL,
                    json=payload,
                    headers=headers,
                )
                if response.status_code < 300:
                    logger.info(
                        f"Critical alert sent → {ALERT_API_URL} "
                        f"[{response.status_code}] IP={ip}"
                    )
                    return True
                else:
                    logger.warning(
                        f"Alert API returned {response.status_code} "
                        f"(attempt {attempt}/{MAX_RETRIES})"
                    )
        except Exception as e:
            logger.error(f"Alert send error (attempt {attempt}/{MAX_RETRIES}): {e}")

    logger.error(f"Failed to send critical alert for {ip} after {MAX_RETRIES} attempts")
    return False