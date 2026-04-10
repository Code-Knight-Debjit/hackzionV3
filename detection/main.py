# detection/main.py

import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from detection.behavior_analyzer import (
    ingest_event,
    get_all_sessions,
    get_sessions_by_ip,
    get_session_by_id,
    get_completed_sessions,
    get_active_sessions,
    flush_timed_out_sessions,
)


async def _periodic_flush():
    """Background task — archives timed-out sessions every 30 seconds."""
    while True:
        await asyncio.sleep(30)
        flush_timed_out_sessions()


@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(_periodic_flush())
    yield
    task.cancel()


app = FastAPI(
    title="HackzionV3 Detection Engine",
    version="2.0.0",
    lifespan=lifespan,
)


class HoneypotEvent(BaseModel):
    ts:         float = 0.0
    ip:         str
    method:     str   = "GET"
    path:       str   = "/"
    query:      str   = ""
    body:       str   = ""
    score:      str   = "0"
    scenario:   str   = "generic_probe"
    user_agent: str   = ""


@app.get("/health")
async def health():
    return {"status": "ok", "service": "detection"}


# ── Core ingestion ────────────────────────────────────────────────────────────

@app.post("/analyze")
async def analyze(event: HoneypotEvent):
    """Receive a honeypot event, analyze it, return enriched result."""
    import time
    data = event.dict()
    if not data.get("ts"):
        data["ts"] = time.time()
    return ingest_event(data)


# ── Session query endpoints ───────────────────────────────────────────────────

@app.get("/sessions")
async def sessions():
    """
    Return full session state:
      - active:    sessions currently in progress
      - completed: ALL historical sessions from start of container lifetime
      - summary:   counts
    """
    return get_all_sessions()


@app.get("/sessions/completed")
async def completed_sessions():
    """Return only completed (archived) sessions — full history."""
    data = get_completed_sessions()
    return {"count": len(data), "sessions": data}


@app.get("/sessions/active")
async def active_sessions():
    """Return only currently active sessions."""
    data = get_active_sessions()
    return {"count": len(data), "sessions": data}


@app.get("/sessions/id/{session_id}")
async def session_by_id(session_id: str):
    """Look up any session by its UUID (active or completed)."""
    s = get_session_by_id(session_id)
    if not s:
        raise HTTPException(404, f"Session {session_id} not found")
    return s


@app.get("/sessions/ip/{ip}")
async def sessions_by_ip(ip: str):
    """
    Return ALL sessions for a specific IP address — complete history.
    Includes both completed and the current active session if one exists.
    """
    data = get_sessions_by_ip(ip)
    if not data:
        raise HTTPException(404, f"No sessions found for IP {ip}")
    return {
        "ip":      ip,
        "count":   len(data),
        "sessions": data,
    }