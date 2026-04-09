# honeypot/main.py

import logging
import sys
from fastapi import FastAPI, Request
from honeypot.ai_handler import handle_honeypot_request

# ── Structured JSON logging (stdout → Docker → detection can tail) ─────────
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="%(message)s",   # Raw JSON lines — no extra prefix
)

app = FastAPI(title="HackzionV3 Honeypot", version="2.0.0")


@app.get("/health")
async def health():
    return {"status": "ok", "service": "honeypot"}


@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
)
async def catch_all(request: Request, path: str = ""):
    return await handle_honeypot_request(request, path)