# detection/main.py

from fastapi import FastAPI
from pydantic import BaseModel
from detection.behavior_analyzer import ingest_event, get_all_sessions, get_session

app = FastAPI(title="HackzionV3 Detection Engine", version="1.0.0")


class HoneypotEvent(BaseModel):
    ts:        float
    ip:        str
    method:    str
    path:      str
    query:     str = ""
    body:      str = ""
    score:     str = "0"
    scenario:  str = "generic_probe"
    user_agent: str = ""


@app.get("/health")
async def health():
    return {"status": "ok", "service": "detection"}


@app.post("/analyze")
async def analyze(event: HoneypotEvent):
    """
    Receive a honeypot event, analyze it, return enriched result.
    Called by honeypot service after every trapped request.
    """
    result = ingest_event(event.dict())
    return result


@app.get("/sessions")
async def sessions():
    """Return all tracked attacker sessions."""
    return get_all_sessions()


@app.get("/sessions/{ip}")
async def session_detail(ip: str):
    """Return session detail for a specific IP."""
    return get_session(ip)