# api/Dockerfile
FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    fastapi==0.111.0 \
    uvicorn[standard]==0.29.0 \
    httpx==0.27.0 \
    aiosqlite==0.20.0 \
    pydantic==2.7.1

COPY api/     ./api/
COPY database/ ./database/
COPY logs/    ./logs/

EXPOSE 8003

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8003"]