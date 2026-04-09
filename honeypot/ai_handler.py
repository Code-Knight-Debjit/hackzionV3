# honeypot/ai_handler.py
"""
AI Handler — HTTP request handler for honeypot.
Orchestrates fake response generation and emits structured event logs.
"""

import json
import time
import logging
from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response

from honeypot.fake_vuln_handler import handle_path
from honeypot.ai_engine import get_fake_response

# Structured JSON logger — detection engine reads this stream
logger = logging.getLogger("honeypot.events")


def _emit_event(event: dict):
    """Emit a structured JSON event for the detection engine."""
    logger.info(json.dumps(event))


async def handle_honeypot_request(request: Request, path: str) -> Response:
    """
    Main handler called by honeypot/main.py for all routes.
    1. Generates fake response via fake_vuln_handler
    2. Emits structured log event
    3. Returns convincing fake HTTP response
    """
    ip     = request.headers.get("X-Forwarded-For", request.client.host if request.client else "unknown")
    ip     = ip.split(",")[0].strip()
    score  = request.headers.get("X-Risk-Score", "0")
    body   = await request.body()
    query  = str(request.url.query)

    # Determine fake response
    result = handle_path(
        path=f"/{path}",
        method=request.method,
        query=query,
        body=body,
    )

    # Emit structured event for detection engine
    _emit_event({
        "ts":        time.time(),
        "ip":        ip,
        "method":    request.method,
        "path":      f"/{path}",
        "query":     query,
        "body":      body.decode("utf-8", errors="replace")[:512],
        "score":     score,
        "scenario":  result["scenario"],
        "user_agent": request.headers.get("user-agent", ""),
    })

    # Build response
    content_type = result["content_type"]
    body_data    = result["body"]
    status       = result["status_code"]

    if content_type == "text/html":
        return HTMLResponse(content=body_data, status_code=status)
    elif content_type == "application/json":
        return JSONResponse(content=body_data, status_code=status)
    else:
        return PlainTextResponse(content=str(body_data), status_code=status)