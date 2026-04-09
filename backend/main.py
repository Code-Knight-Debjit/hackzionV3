# backend/main.py

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="HackzionV3 Real Backend", version="1.0.0")


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def catch_all(request: Request, path: str = ""):
    """
    Catch-all handler — echoes request details back.
    Real backend: serves legitimate traffic.
    """
    return JSONResponse({
        "backend":   "REAL",
        "path":      f"/{path}",
        "method":    request.method,
        "client_ip": request.headers.get("X-Real-IP", "unknown"),
        "decision":  request.headers.get("X-Route-Decision", "unknown"),
        "score":     request.headers.get("X-Risk-Score", "unknown"),
        "headers":   dict(request.headers),
    })