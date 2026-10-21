FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SECLOG_DB=/data/seclog.db \
    SECLOG_TRUST_PROXY=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run as an unprivileged user; /data holds the SQLite file.
RUN useradd --create-home app && mkdir -p /data && chown app /data
USER app

EXPOSE 8000
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-8000} --workers 2 --threads 4 --access-logfile - wsgi:app"]
