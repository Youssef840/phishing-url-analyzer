FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY phishguard ./phishguard
COPY run.py .

RUN useradd --create-home appuser
USER appuser

# WEB_CONCURRENCY = gunicorn worker processes (read by gunicorn itself). The rate limiter
# keeps counters per worker, so use 1 worker when RATE_LIMIT_PER_MINUTE must be exact.
ENV PORT=8000 \
    WEB_CONCURRENCY=2
EXPOSE 8000
HEALTHCHECK CMD python -c "import os, urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"PORT\"]}/health')" || exit 1
CMD gunicorn --threads 8 --timeout 60 --bind "0.0.0.0:${PORT}" "phishguard:create_app()"
