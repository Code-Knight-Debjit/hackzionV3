# backend/Dockerfile
FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir fastapi==0.111.0 uvicorn[standard]==0.29.0

COPY main.py .

EXPOSE 9000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "9000"]