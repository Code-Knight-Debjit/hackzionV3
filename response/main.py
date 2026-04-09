# response/main.py

from fastapi import FastAPI
from pydantic import BaseModel
from response.response_engine import dispatch, get_alerts, get_defense_logs

app = FastAPI(title="HackzionV3 Response Engine", version="1.0.0")


class AnalysisResult(BaseModel):
    ip:          str
    scenario:    str = "generic_probe"
    attack_type: str = "Unknown"
    severity:    str = "LOW"
    mitre_ttps:  list = []
    event_count: int = 0
    session_age: float = 0.0


@app.get("/health")
async def health():
    return {"status": "ok", "service": "response"}


@app.post("/respond")
async def respond(analysis: AnalysisResult):
    """Receive a detection result and execute the appropriate response."""
    result = await dispatch(analysis.dict())
    return result


@app.get("/alerts")
async def alerts():
    """Live alerts — consumed by monitorapp AlertsScreen."""
    return get_alerts()


@app.get("/defense-logs")
async def defense_logs():
    """Defense action log — consumed by monitorapp DefenseScreen."""
    return get_defense_logs()