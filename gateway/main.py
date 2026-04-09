# gateway/main.py

from fastapi import FastAPI
from gateway.middleware import RiskMiddleware
from gateway.router import routing_router

app = FastAPI(title="HackzionV3 Gateway", version="1.0.0")

app.add_middleware(RiskMiddleware)
app.include_router(routing_router)

@app.get("/health")
async def health():
    return {"status": "ok", "service": "gateway"}