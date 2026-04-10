# ai_analyzer/Dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY ai_analyzer/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ai_analyzer/ ./ai_analyzer/

EXPOSE 8004

CMD ["uvicorn", "ai_analyzer.main:app", "--host", "0.0.0.0", "--port", "8004", "--workers", "2"]