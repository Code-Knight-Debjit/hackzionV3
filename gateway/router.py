# gateway/router.py

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response
from gateway.risk_engine import get_store_snapshot

routing_router = APIRouter()

# Internal Docker service URLs
BACKEND_URL  = "http://backend:9000"
HONEYPOT_URL = "http://honeypot:9001"

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