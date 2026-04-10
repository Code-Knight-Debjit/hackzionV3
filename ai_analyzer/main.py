# ai_analyzer/main.py
"""
HackzionV3 AI Analyzer — FastAPI Service.

POST /analyze        → Full AI pipeline (LLM + CVSS + Intel + Profiling)
POST /analyze/async  → Fire-and-forget variant (returns immediately)
GET  /attacks        → ALL attacks ever recorded, newest first ← NEW
GET  /profiles       → All threat actor profiles
GET  /profiles/{ip}  → Single profile
GET  /logs           → Recent attack logs (alias for /attacks with filters)
GET  /stats          → Aggregate statistics
GET  /health         → Health check
"""

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from ai_analyzer.analyzer  import run_analysis_pipeline
from ai_analyzer.profiler  import get_profile, get_all_profiles
from ai_analyzer.database  import get_attack_logs, get_stats, get_all_attacks

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("ai_analyzer.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("AI Analyzer starting")
    yield
    logger.info("AI Analyzer shutting down")


app = FastAPI(
    title="HackzionV3 AI Attack Analyzer",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Input schema ──────────────────────────────────────────────────────────────
class AttackLog(BaseModel):
    ip:          str
    path:        str   = "/"
    method:      str   = "GET"
    query:       str   = ""
    body:        str   = ""
    request:     str   = ""
    user_agent:  str   = ""
    headers:     dict  = Field(default_factory=dict)
    timestamp:   float = Field(default_factory=time.time)
    scenario:    str   = ""
    attack_type: str   = ""
    severity:    str   = ""
    score:       str   = "0"


# ── Health ────────────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "ok", "service": "ai_analyzer"}


# ── Analysis endpoints ────────────────────────────────────────────────────────
@app.post("/analyze")
async def analyze(log: AttackLog):
    """Full synchronous pipeline — waits for LLM + DB write before responding."""
    log_dict = log.dict()
    if not log_dict["user_agent"]:
        log_dict["user_agent"] = log_dict.get("headers", {}).get("user-agent", "")
    try:
        report = await run_analysis_pipeline(log_dict)
        return {"status": "analyzed", "report": report}
    except Exception as e:
        logger.error(f"Pipeline error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/analyze/async")
async def analyze_async(log: AttackLog, background_tasks: BackgroundTasks):
    """
    Fire-and-forget — returns 202 immediately.
    LLM + MongoDB write runs in background.
    Called by honeypot on every trapped request.
    """
    log_dict = log.dict()
    if not log_dict["user_agent"]:
        log_dict["user_agent"] = log_dict.get("headers", {}).get("user-agent", "")
    background_tasks.add_task(run_analysis_pipeline, log_dict)
    return {"status": "queued", "ip": log.ip}


# ── NEW: /attacks — complete attack history ───────────────────────────────────
@app.get("/attacks")
async def attacks(
    limit:    int         = Query(default=100, ge=1,  le=1000),
    severity: str | None  = Query(default=None, description="Filter: Low | Medium | High | Critical"),
    ip:       str | None  = Query(default=None, description="Filter by attacker IP"),
):
    """
    Returns ALL attacks recorded since the system started.

    Every time an attack hits the honeypot:
      1. honeypot/ai_handler.py calls /analyze/async
      2. LLM classifies it + CVSS scored + threat intel matched
      3. Full report written to MongoDB attack_logs
      4. This endpoint reads that collection live

    Response shape per attack:
    {
      "ip":                str,
      "timestamp":         float,
      "attack_type":       str,
      "severity":          str,   ← CVSS-authoritative (Low/Medium/High/Critical)
      "cvss_score":        float,
      "behavior":          str,   ← manual | automated | tool-based
      "mitre_technique":   str,
      "owasp_category":    str,
      "matched_signature": str,
      "mitigation":        str,
      "llm_used":          bool,
      "confidence":        float,
    }
    """
    data = await get_all_attacks(ip=ip, severity=severity, limit=limit)
    return {
        "count":   len(data),
        "attacks": data,
    }


# ── Profiles ──────────────────────────────────────────────────────────────────
@app.get("/profiles")
async def profiles(limit: int = 100):
    data = await get_all_profiles(limit=limit)
    return {"count": len(data), "profiles": data}


@app.get("/profiles/{ip}")
async def profile_by_ip(ip: str):
    data = await get_profile(ip)
    if not data:
        raise HTTPException(404, f"No profile for {ip}")
    return data


# ── Logs (alias with filters) ─────────────────────────────────────────────────
@app.get("/logs")
async def logs(
    ip:       str | None = None,
    severity: str | None = None,
    limit:    int        = 50,
):
    data = await get_attack_logs(ip=ip, severity=severity, limit=limit)
    return {"count": len(data), "logs": data}


# ── Stats ─────────────────────────────────────────────────────────────────────
@app.get("/stats")
async def stats():
    return await get_stats()