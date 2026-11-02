# Deployment

## What is deployed today

The live demo runs on **Render** (free web service, Python runtime) from the `main` branch:
<https://seclog-sentinel.onrender.com>. It is not deployed to AWS, Azure or Google Cloud.

## Render settings

The repository contains a blueprint, `render.yaml`. Creating a **Blueprint** service from the repo
applies it.

| Setting | Value | Why |
|---|---|---|
| Runtime | Python 3 (version from `.python-version`, 3.13) | No container needed |
| Build command | `pip install -r requirements.txt` | Installs Flask and gunicorn |
| Start command | `gunicorn wsgi:app --bind 0.0.0.0:$PORT --workers 1 --threads 4 --access-logfile -` | One worker keeps the in-memory rate limiter accurate; threads handle concurrency |
| Health check path | `/healthz` | Render restarts the service if it stops answering |
| `SECLOG_TRUST_PROXY` | `1` | Read the real client address and HTTPS from Render's proxy headers |
| `SECLOG_EPHEMERAL` | `1` | Free instances lose local files when idle; the UI then says results are short-lived |
| `SECLOG_DB` | `/tmp/seclog.db` | The only writable location on the free tier |
| `SECLOG_REPO_URL` | the GitHub URL | Adds the source link to the footer |
| `SECLOG_LOG_LEVEL` | `INFO` (optional) | `DEBUG`, `INFO`, `WARNING`, `ERROR` |

No secret values are needed. The app has no API keys, passwords or tokens.

Free-tier behaviour to expect: the service sleeps after about 15 minutes without traffic and the
next request takes around a minute; saved analyses disappear on restart.

## Configuration reference

All configuration is environment variables. See `.env.example`.

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | 8000 in Docker, set by the host elsewhere | Port gunicorn listens on |
| `WEB_CONCURRENCY` | 2 in Docker | Number of gunicorn worker processes (Docker image only) |
| `SECLOG_DB` | `data/seclog.db` (`/data/seclog.db` in Docker) | SQLite file for results |
| `SECLOG_TRUST_PROXY` | unset | `1` behind one reverse proxy |
| `SECLOG_EPHEMERAL` | unset | `1` on hosts that erase local files |
| `SECLOG_REPO_URL` | unset | Footer source link |
| `SECLOG_LOG_LEVEL` | `INFO` | Log verbosity |

## Docker

```bash
docker build -t seclog-sentinel .
docker run -p 8000:8000 -v seclog-data:/data seclog-sentinel
curl http://127.0.0.1:8000/healthz
```

The image runs as a non-root user, defines a `HEALTHCHECK`, and keeps results in the `/data` volume.
GitHub Actions builds this image and smoke-tests the running container on every push and pull
request (see the `docker` job in `.github/workflows/ci.yml`).

## Running on another platform

The app is a standard WSGI application (`wsgi:app`), so any host that can run a container or a
Python process works. These are descriptions of how it would map, **not** deployments that exist:

- **AWS**: build the Docker image, push it to ECR, run it on App Runner or ECS Fargate behind an
  Application Load Balancer. Set the health check path to `/healthz`, set `SECLOG_TRUST_PROXY=1`, and
  mount an EFS volume (or move storage to RDS) if results must survive restarts.
- **Azure**: Azure Container Apps or App Service for Containers with the same image and settings; an
  Azure Files mount for `/data`.
- **Google Cloud**: Cloud Run with the same image. Cloud Run's filesystem is ephemeral, so set
  `SECLOG_EPHEMERAL=1` or switch storage to Cloud SQL.
- **Any Linux VM**: `pip install -r requirements.txt`, then run gunicorn under systemd behind nginx or Caddy.

## Scaling limits

Results live in a single SQLite file and the rate limiter is in process memory. That is right for a
demo and a single instance. Running several instances needs shared storage (PostgreSQL) and a shared
rate limiter (Redis, or limits at the load balancer).


## Dependencies

`requirements.txt` now includes `reportlab` for PDF reports. It is pure Python wheels on Render, so the
build command does not change. If it is missing, the PDF button is hidden and the other exports still work.
