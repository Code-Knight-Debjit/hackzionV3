# api/main.py
"""
HackzionV3 API Service — public-facing API layer.
Reads from SQLite. Proxies block actions to gateway.
"""

import time
import httpx
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import sys, os
sys.path.insert(0, "/app")

logger = logging.getLogger("honeypot.events")

from database.db import (
    init_db,
    get_live_attacks,
    get_events_by_session,
    get_alerts,
    block_ip,
    get_blocked_ips,
)

GATEWAY_URL = "http://gateway:8000"


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(title="HackzionV3 API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── 1. GET /api/attacks/live ──────────────────────────────────────────────────
@app.get("/api/attacks/live")
async def attacks_live(limit: int = 50):
    """
    Returns the most recent attack events from the DB.
    Used by monitorapp AttacksScreen.
    """
    events = await get_live_attacks(limit=limit)
    return {
        "count":   len(events),
        "attacks": events,
    }


# ── 2. GET /api/attacks/{session_id} ─────────────────────────────────────────
@app.get("/api/attacks/{session_id}")
async def attack_by_session(session_id: str):
    """
    Returns all events for a specific attacker session.
    session_id is derived from IP + hour bucket (see logs/logger.py).
    """
    events = await get_events_by_session(session_id)
    if not events:
        raise HTTPException(status_code=404, detail=f"No events found for session {session_id}")
    return {
        "session_id": session_id,
        "count":      len(events),
        "events":     events,
    }


# ── 3. GET /api/alerts ────────────────────────────────────────────────────────
@app.get("/api/alerts")
async def alerts_endpoint(limit: int = 100):
    """
    Returns critical alerts. Used by monitorapp AlertsScreen.
    """
    data = await get_alerts(limit=limit)
    return {
        "count":  len(data),
        "alerts": data,
    }


# ── 4. POST /api/action/block ─────────────────────────────────────────────────
class BlockRequest(BaseModel):
    ip:     str
    reason: str = "manual_block"


@app.post("/api/action/block")
async def action_block(req: BlockRequest):
    """
    Block an IP:
    1. Persist to blocked_ips table in DB
    2. Escalate risk score in gateway (force honeypot routing permanently)
    """
    # DB block
    await block_ip(req.ip, req.reason)

    # Escalate in gateway
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            await client.post(
                f"{GATEWAY_URL}/risk/escalate",
                json={"ip": req.ip, "increment": 100},
            )
    except Exception as e:
        pass  # DB block succeeded; gateway escalation is best-effort

    return {
        "status":    "blocked",
        "ip":        req.ip,
        "reason":    req.reason,
        "blocked_at": time.time(),
    }


@app.get("/api/blocked")
async def blocked_ips():
    """List all blocked IPs."""
    return await get_blocked_ips()


@app.get("/api/stats")
async def stats():
    """Summary stats for monitorapp dashboard."""
    attacks = await get_live_attacks(limit=1000)
    alerts  = await get_alerts(limit=1000)
    blocked = await get_blocked_ips()

    severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    attack_type_counts: dict = {}
    for ev in attacks:
        sev = ev.get("severity", "LOW")
        if sev in severity_counts:
            severity_counts[sev] += 1
        at = ev.get("attack_type", "Unknown")
        attack_type_counts[at] = attack_type_counts.get(at, 0) + 1

    return {
        "total_events":     len(attacks),
        "total_alerts":     len(alerts),
        "total_blocked":    len(blocked),
        "severity_breakdown": severity_counts,
        "top_attack_types": sorted(
            attack_type_counts.items(), key=lambda x: x[1], reverse=True
        )[:5],
    }

@app.get("/api/attacks")
async def attacks():
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            attack_resp = await client.get("http://detection:8001/sessions")
            return attack_resp.json()
    except Exception as e:
        logger.error(f"Pipeline error: {e}")

@app.get("/api/defence")
async def defence():
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            defence_resp = await client.get("http://response:8002/alerts")
            return defence_resp.json()
    except Exception as e:
        logger.error(f"Pipeline error: {e}")


@app.get("/health")
async def health():
    return {"status": "ok", "service": "api"}