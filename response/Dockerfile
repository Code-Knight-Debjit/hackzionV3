# response/Dockerfile
FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir fastapi==0.111.0 uvicorn[standard]==0.29.0 httpx==0.27.0 pydantic==2.7.1

COPY response/ ./response/

EXPOSE 8002

CMD ["uvicorn", "response.main:app", "--host", "0.0.0.0", "--port", "8002"]