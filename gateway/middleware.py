# gateway/middleware.py

import time
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from gateway.risk_engine import score_request, get_decision


class RiskMiddleware(BaseHTTPMiddleware):
    """
    Scores every inbound request and attaches decision + score to request.state.
    The router then forwards to the correct backend.
    """

    async def dispatch(self, request: Request, call_next):
        # Respect X-Forwarded-For set by Nginx
        forwarded_for = request.headers.get("X-Forwarded-For", "")
        ip = forwarded_for.split(",")[0].strip() if forwarded_for else (
            request.client.host if request.client else "unknown"
        )

        metadata = {
            "ip":        ip,
            "path":      request.headers.get("X-Original-URI", request.url.path),
            "method":    request.headers.get("X-Original-Method", request.method),
            "query":     str(request.url.query),
            "timestamp": time.time(),
        }

        score    = score_request(metadata)
        decision = get_decision(score)

        request.state.risk_score    = score
        request.state.risk_decision = decision
        request.state.client_ip     = ip

        response = await call_next(request)

        response.headers["X-Route-Decision"] = decision
        response.headers["X-Risk-Score"]     = str(score)
        return response