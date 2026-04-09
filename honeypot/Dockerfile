# honeypot/Dockerfile  (MODIFIED — add shared modules)
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy honeypot service
COPY honeypot/ ./honeypot/

# ✅ FIX: copy shared modules that honeypot imports
COPY logs/     ./logs/
COPY database/ ./database/

CMD ["uvicorn", "honeypot.main:app", "--host", "0.0.0.0", "--port", "9001"]