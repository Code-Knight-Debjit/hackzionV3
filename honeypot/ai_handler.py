# honeypot/ai_handler.py
"""
AI Handler — HTTP request handler for honeypot.
Orchestrates fake response generation and emits structured event logs.
"""

import json
import time
import asyncio
import logging
import httpx
from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response

from honeypot.fake_vuln_handler import handle_path
from honeypot.ai_engine import get_fake_response

# Structured JSON logger — detection engine reads this stream
logger = logging.getLogger("honeypot.events")

try:
    import sys
    sys.path.insert(0, "/app")
    from logs.logger import log_event, build_event
    _logging_available = True
except ImportError:
    _logging_available = False


def _emit_event(event: dict):
    logger.info(json.dumps(event))



DETECTION_URL = "http://detection:8001"

async def handle_honeypot_request(request: Request, path: str) -> Response:
    ip     = request.headers.get("X-Forwarded-For", request.client.host if request.client else "unknown")
    ip     = ip.split(",")[0].strip()
    score  = request.headers.get("X-Risk-Score", "0")
    body   = await request.body()
    query  = str(request.url.query)

    result = handle_path(
        path=f"/{path}",
        method=request.method,
        query=query,
        body=body,
    )

    event = {
        "ts":        time.time(),
        "ip":        ip,
        "method":    request.method,
        "path":      f"/{path}",
        "query":     query,
        "body":      body.decode("utf-8", errors="replace")[:512],
        "score":     score,
        "scenario":  result["scenario"],
        "user_agent": request.headers.get("user-agent", ""),
    }
    # ✅ FIX: POST to detection engine (fire-and-forget, don't block response)
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            detection_resp = await client.post(f"{DETECTION_URL}/analyze", json=event)
            analysis = detection_resp.json()

            # ✅ FIX: Forward detection result to response engine
            await client.post("http://response:8002/respond", json=analysis)
    except Exception as e:
        logger.error(f"Pipeline error: {e}")  # Don't crash honeypot if pipeline fails

    # Still emit structured log for visibility
    _emit_event(event)

    # Persist structured log event to DB
    if _logging_available:
        try:
            structured = build_event(
                ip=ip,
                attack_type="Generic Reconnaissance",   # refined by detection engine
                severity="MEDIUM",
                risk_score=int(score) if score.isdigit() else 0,
                action_taken="redirect_honeypot",
                scenario=result["scenario"],
            )
            log_event(structured)
        except Exception:
            pass

    # Build and return fake response as before
    content_type = result["content_type"]
    body_data    = result["body"]
    status       = result["status_code"]

    if content_type == "text/html":
        return HTMLResponse(content=body_data, status_code=status)
    elif content_type == "application/json":
        return JSONResponse(content=body_data, status_code=status)
    else:
        return PlainTextResponse(content=str(body_data), status_code=status)