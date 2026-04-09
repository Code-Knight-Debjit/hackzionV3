# gateway/router.py

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response
from gateway.risk_engine import get_store_snapshot, force_escalate, score_request, get_decision

routing_router = APIRouter()


# Internal Docker service URLs
BACKEND_URL   = "http://backend:9000"
HONEYPOT_URL  = "http://honeypot:9001"
DETECTION_URL = "http://detection:8001"
RESPONSE_URL  = "http://response:8002"

# Shared async HTTP client (connection pooling)
_client = httpx.AsyncClient(timeout=10.0)


@routing_router.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
)
async def proxy_request(request: Request, path: str = ""):
    """
    Main catch-all route.
    1. Read decision from middleware (attached to request.state)
    2. Forward full request to the correct backend
    3. Stream response back to client
    """
    decision = getattr(request.state, "risk_decision", "real")
    score    = getattr(request.state, "risk_score", 0)
    ip       = getattr(request.state, "client_ip", "unknown")

    # Skip internal health/debug routes
    if path in ("health", "risk/store"):
        return  # handled by their own endpoints

    # Select destination
    if decision == "honeypot":
        target = HONEYPOT_URL
    else:
        # Both "real" and "monitor" go to real backend.
        # "monitor" is distinguishable via X-Route-Decision header downstream.
        target = BACKEND_URL

    # Build the forwarded URL
    url = f"{target}/{path}"
    if request.url.query:
        url += f"?{request.url.query}"

    # Forward original headers, add routing metadata
    forward_headers = {
        key: value
        for key, value in request.headers.items()
        if key.lower() not in ("host", "content-length")
    }
    forward_headers["X-Route-Decision"] = decision
    forward_headers["X-Risk-Score"]     = str(score)
    forward_headers["X-Client-IP"]      = ip

    # Read body (for POST/PUT/PATCH)
    body = await request.body()

    # Proxy the request
    backend_response = await _client.request(
        method=request.method,
        url=url,
        headers=forward_headers,
        content=body,
    )

    # Stream response back — preserve status, headers, body
    excluded = {"transfer-encoding", "content-encoding"}
    response_headers = {
        k: v for k, v in backend_response.headers.items()
        if k.lower() not in excluded
    }
    response_headers["X-Route-Decision"] = decision
    response_headers["X-Risk-Score"]     = str(score)

    return Response(
        content=backend_response.content,
        status_code=backend_response.status_code,
        headers=response_headers,
        media_type=backend_response.headers.get("content-type", "application/json"),
    )


@routing_router.get("/risk/store")
async def risk_store_view():
    """Debug: view all IP scores in the in-memory store."""
    return get_store_snapshot()



@routing_router.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
)
async def proxy_request(request: Request, path: str = ""):
    # Skip internal routes
    if path in ("health", "risk/store", "risk/escalate") or path.startswith("api/"):
        return  # handled by dedicated endpoints below

    decision = getattr(request.state, "risk_decision", "real")
    score    = getattr(request.state, "risk_score", 0)
    ip       = getattr(request.state, "client_ip", "unknown")

    target = HONEYPOT_URL if decision == "honeypot" else BACKEND_URL

    url = f"{target}/{path}"
    if request.url.query:
        url += f"?{request.url.query}"

    forward_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in ("host", "content-length")
    }
    forward_headers["X-Route-Decision"] = decision
    forward_headers["X-Risk-Score"]     = str(score)
    forward_headers["X-Client-IP"]      = ip

    body = await request.body()

    backend_response = await _client.request(
        method=request.method,
        url=url,
        headers=forward_headers,
        content=body,
    )

    # ── If routed to honeypot → fire-and-forget to detection + response ───────
    if decision == "honeypot":
        event_payload = {
            "ts":        __import__("time").time(),
            "ip":        ip,
            "method":    request.method,
            "path":      f"/{path}",
            "query":     str(request.url.query),
            "body":      body.decode("utf-8", errors="replace")[:512],
            "score":     str(score),
            "scenario":  "gateway_routed",
            "user_agent": request.headers.get("user-agent", ""),
        }
        try:
            det_resp = await _client.post(f"{DETECTION_URL}/analyze", json=event_payload)
            analysis = det_resp.json()
            await _client.post(f"{RESPONSE_URL}/respond", json=analysis)
        except Exception:
            pass   # Never let detection failure break the honeypot response

    excluded = {"transfer-encoding", "content-encoding"}
    response_headers = {
        k: v for k, v in backend_response.headers.items()
        if k.lower() not in excluded
    }
    response_headers["X-Route-Decision"] = decision
    response_headers["X-Risk-Score"]     = str(score)

    return Response(
        content=backend_response.content,
        status_code=backend_response.status_code,
        headers=response_headers,
        media_type=backend_response.headers.get("content-type", "application/json"),
    )


@routing_router.get("/risk/store")
async def risk_store_view():
    return get_store_snapshot()


@routing_router.post("/risk/escalate")
async def risk_escalate(payload: dict):
    """Called by response engine to permanently lock an IP to honeypot."""
    ip        = payload.get("ip")
    increment = payload.get("increment", 30)
    if ip:
        force_escalate(ip, increment)
    return {"status": "escalated", "ip": ip}


# ── Live API endpoints for monitorapp ─────────────────────────────────────────

@routing_router.get("/api/alerts")
async def api_alerts():
    try:
        r = await _client.get(f"{RESPONSE_URL}/alerts")
        return r.json()
    except Exception:
        return []


@routing_router.get("/api/defense-logs")
async def api_defense_logs():
    try:
        r = await _client.get(f"{RESPONSE_URL}/defense-logs")
        return r.json()
    except Exception:
        return []


@routing_router.get("/api/attacks")
async def api_attacks():
    try:
        r = await _client.get(f"{DETECTION_URL}/sessions")
        sessions = r.json()
        logs = []
        for ip, session in sessions.items():
            for event in session.get("events", [])[-5:]:
                logs.append({
                    "time":     __import__("time").strftime(
                        "%H:%M", __import__("time").localtime(event.get("ts", 0))
                    ),
                    "attack":   session.get("attack_type", "Unknown"),
                    "severity": session.get("severity", "Low").title(),
                })
        return logs
    except Exception:
        return []