# honeypot/main.py

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import time

app = FastAPI(title="HackzionV3 Honeypot", version="1.0.0")


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def honeypot_catch_all(request: Request, path: str = ""):
    """
    Honeypot handler — receives high-risk traffic.
    Responds slowly and with convincing-but-fake data.
    In production this would log attacker behaviour in detail.
    """
    time.sleep(0.5)  # Artificial delay to waste attacker time

    return JSONResponse({
        "backend":   "HONEYPOT",
        "path":      f"/{path}",
        "method":    request.method,
        "client_ip": request.headers.get("X-Real-IP", "unknown"),
        "score":     request.headers.get("X-Risk-Score", "unknown"),
        "message":   "Welcome. Your actions are being recorded.",
    }, status_code=200)