# honeypot/ai_handler.py
"""
AI Handler — HTTP request handler for honeypot.
"""

import json
import time
import logging
import httpx
from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response

from honeypot.fake_vuln_handler import handle_path
from honeypot.ai_engine import get_fake_response

logger = logging.getLogger("honeypot.events")

try:
    import sys
    sys.path.insert(0, "/app")
    from logs.logger import log_event, build_event
    _logging_available = True
except ImportError:
    _logging_available = False

DETECTION_URL    = "http://detection:8001"
RESPONSE_URL     = "http://response:8002"
AI_ANALYZER_URL  = "http://ai_analyzer:8004"   # ← NEW


def _emit_event(event: dict):
    logger.info(json.dumps(event))


async def handle_honeypot_request(request: Request, path: str) -> Response:
    ip    = request.headers.get("X-Forwarded-For", request.client.host if request.client else "unknown")
    ip    = ip.split(",")[0].strip()
    score = request.headers.get("X-Risk-Score", "0")
    body  = await request.body()
    query = str(request.url.query)

    result = handle_path(
        path=f"/{path}",
        method=request.method,
        query=query,
        body=body,
    )

    event = {
        "ts":         time.time(),
        "ip":         ip,
        "method":     request.method,
        "path":       f"/{path}",
        "query":      query,
        "body":       body.decode("utf-8", errors="replace")[:512],
        "score":      score,
        "scenario":   result["scenario"],
        "user_agent": request.headers.get("user-agent", ""),
    }

    analysis = {}
    async with httpx.AsyncClient(timeout=3.0) as client:
        # ── Step 1: Detection engine (existing pipeline) ──────────────────────
        try:
            detection_resp = await client.post(f"{DETECTION_URL}/analyze", json=event)
            analysis = detection_resp.json()
        except Exception as e:
            logger.error(f"Detection error: {e}")

        # ── Step 2: Response engine (existing pipeline) ───────────────────────
        try:
            await client.post(f"{RESPONSE_URL}/respond", json=analysis)
        except Exception as e:
            logger.error(f"Response engine error: {e}")

        # ── Step 3: AI Analyzer — fire-and-forget (NEW) ───────────────────────
        # Sends full event to LLM pipeline → MongoDB persisted → /api/attacks live
        try:
            ai_payload = {
                "ip":         ip,
                "path":       f"/{path}",
                "method":     request.method,
                "query":      query,
                "body":       body.decode("utf-8", errors="replace")[:512],
                "user_agent": request.headers.get("user-agent", ""),
                "timestamp":  event["ts"],
                "score":      score,
                "scenario":   result["scenario"],
                # Pass detection enrichment so LLM has context
                "attack_type":analysis.get("attack_type", ""),
                "severity":   analysis.get("severity", ""),
            }
            # /analyze/async returns immediately — LLM runs in background
            await client.post(
                f"{AI_ANALYZER_URL}/analyze/async",
                json=ai_payload,
                timeout=2.0,
            )
        except Exception as e:
            # Never block the honeypot response if AI analyzer is down
            logger.warning(f"AI analyzer unreachable (non-critical): {e}")

    _emit_event(event)

    # ── Existing SQLite logging (unchanged) ───────────────────────────────────
    if _logging_available:
        try:
            structured = build_event(
                ip=ip,
                attack_type=analysis.get("attack_type", "Generic Reconnaissance"),
                severity=analysis.get("severity", "LOW"),
                risk_score=int(score) if str(score).isdigit() else 0,
                action_taken=analysis.get("action", "log"),
                mitre_ttps=analysis.get("mitre_ttps", []),
                scenario=analysis.get("scenario", result["scenario"]),
                confidence=analysis.get("confidence", 0.75),
                commands_executed=analysis.get("commands_executed", []),
            )
            log_event(structured)
        except Exception as e:
            logger.error(f"log_event failed: {e}")

    # ── Return fake response (unchanged) ─────────────────────────────────────
    content_type = result["content_type"]
    body_data    = result["body"]
    status       = result["status_code"]

    if content_type == "text/html":
        return HTMLResponse(content=body_data, status_code=status)
    elif content_type == "application/json":
        return JSONResponse(content=body_data, status_code=status)
    else:
        return PlainTextResponse(content=str(body_data), status_code=status)