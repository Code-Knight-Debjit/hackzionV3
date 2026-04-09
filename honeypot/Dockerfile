# honeypot/Dockerfile
FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir fastapi==0.111.0 uvicorn[standard]==0.29.0

# Copy honeypot as a package
COPY honeypot/ ./honeypot/

EXPOSE 9001

CMD ["uvicorn", "honeypot.main:app", "--host", "0.0.0.0", "--port", "9001"]