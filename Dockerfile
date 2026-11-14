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

EXPOSE 8000
HEALTHCHECK CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1
CMD ["gunicorn", "--workers", "2", "--threads", "4", "--timeout", "60", "--bind", "0.0.0.0:8000", "phishguard:create_app()"]
