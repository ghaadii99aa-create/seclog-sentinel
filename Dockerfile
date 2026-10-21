FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SECLOG_DB=/data/seclog.db \
    SECLOG_TRUST_PROXY=1 \
    PORT=8000

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run as an unprivileged user; /data holds the SQLite file (mount a volume there to keep results).
RUN useradd --create-home app && mkdir -p /data && chown app /data
USER app
VOLUME ["/data"]

EXPOSE 8000

# Marks the container unhealthy if the app stops answering. Uses only the standard library.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import os,urllib.request as u; u.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('PORT','8000'), timeout=4)"

CMD ["sh", "-c", "exec gunicorn --bind 0.0.0.0:${PORT} --workers ${WEB_CONCURRENCY:-2} --threads 4 --access-logfile - wsgi:app"]
