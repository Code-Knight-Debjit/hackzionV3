# detection/Dockerfile
FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir fastapi==0.111.0 uvicorn[standard]==0.29.0 pydantic==2.7.1

COPY detection/ ./detection/

EXPOSE 8001

CMD ["uvicorn", "detection.main:app", "--host", "0.0.0.0", "--port", "8001"]