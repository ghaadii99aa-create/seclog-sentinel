"""Flask application: upload a log, get an analysis you can share by link."""

from __future__ import annotations

import ipaddress
import os
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

from flask import Flask, Response, abort, g, jsonify, make_response, redirect, render_template, request, url_for
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from .. import __version__
from ..analyzer import analyze
from ..models import Analysis, Thresholds
from ..parser import parse_log
from ..report import render_html, render_json
from .storage import RETENTION_DAYS, Store

MAX_UPLOAD_BYTES = 5 * 1024 * 1024
SAMPLE_LOG = Path(__file__).resolve().parents[2] / "sample_data" / "auth.log"
SAMPLE_YEAR = 2026
COOKIE_NAME = "sid"
COOKIE_MAX_AGE = 30 * 86400


class SettingsError(ValueError):
    """A detection setting submitted by the user is not valid."""


class LogError(ValueError):
    """The uploaded file cannot be analysed."""


class RateLimiter:
    """Sliding-window limiter kept in memory (per worker process)."""

    def __init__(self, limit: int, window_seconds: int) -> None:
        self.limit = limit
        self.window = window_seconds
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            if len(self._hits) > 5000:  # keep memory bounded
                for stale in [k for k, v in self._hits.items() if not v]:
                    del self._hits[stale]
            return True


# --------------------------------------------------------------------------- settings


def _int_field(values, name: str, label: str, default: int, low: int, high: int) -> int:
    raw = (values.get(name) or "").strip()
    if not raw:
        return default
    try:
        number = int(raw)
    except ValueError:
        raise SettingsError(f"{label} must be a whole number.") from None
    if not low <= number <= high:
        raise SettingsError(f"{label} must be between {low} and {high}.")
    return number


def _list_field(values, name: str, label: str, max_items: int = 20) -> List[str]:
    raw = (values.get(name) or "").replace(",", " ").split()
    if len(raw) > max_items:
        raise SettingsError(f"{label}: enter at most {max_items} entries.")
    return raw


def read_settings(values) -> Tuple[Thresholds, int, Dict[str, Any]]:
    """Validate form or query settings and build the Thresholds object."""
    year = _int_field(values, "year", "Year", datetime.now().year, 1970, 2100)
    bf_failures = _int_field(values, "brute_force_threshold", "Brute-force threshold", 5, 2, 1000)
    bf_window = _int_field(values, "brute_force_window", "Brute-force window", 5, 1, 1440)
    spray_users = _int_field(values, "spray_users", "Spraying threshold", 5, 2, 1000)
    spray_window = _int_field(values, "spray_window", "Spraying window", 10, 1, 1440)

    privileged = [name[:64] for name in _list_field(values, "privileged", "Privileged accounts")]
    networks = _list_field(values, "internal_networks", "Internal networks")
    for cidr in networks:
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            raise SettingsError(f"'{cidr[:40]}' is not a valid network. Use CIDR notation, for example 100.64.0.0/10.") from None

    thresholds = Thresholds(
        brute_force_failures=bf_failures,
        brute_force_window=timedelta(minutes=bf_window),
        spray_users=spray_users,
        spray_window=timedelta(minutes=spray_window),
        privileged_users=Thresholds.privileged_users | frozenset(privileged),
        internal_networks=Thresholds.internal_networks + tuple(networks),
    )
    settings = {
        "year": year,
        "brute_force_failures": bf_failures,
        "brute_force_window_minutes": bf_window,
        "spray_users": spray_users,
        "spray_window_minutes": spray_window,
        "privileged_users": sorted(thresholds.privileged_users),
        "internal_networks": list(thresholds.internal_networks),
    }
    return thresholds, year, settings


# --------------------------------------------------------------------------- analysis


def run_analysis(raw: bytes, values, year_override: Optional[int] = None) -> Dict[str, Any]:
    thresholds, year, settings = read_settings(values)
    if year_override is not None:
        year = settings["year"] = year_override
    text = raw.decode("utf-8", errors="replace")
    parsed = parse_log(text.splitlines(), year=year)
    if not parsed.events:
        raise LogError(
            "No SSH login events were found in this file. Upload an sshd log such as "
            "/var/log/auth.log (Debian, Ubuntu) or /var/log/secure (RHEL, CentOS)."
        )
    analysis = analyze(parsed.events, thresholds, ignored_lines=parsed.ignored_lines)
    data = analysis.to_dict()
    data["settings"] = settings
    return data


def clean_filename(name: Optional[str]) -> str:
    base = Path(name or "").name
    cleaned = "".join(ch if ch.isprintable() else "?" for ch in base)[:80].strip()
    return cleaned or "uploaded log"


_ATTACK_RULES = {"brute_force", "password_spraying", "success_after_failures"}


def build_verdict(data: Dict[str, Any]) -> Dict[str, str]:
    summary = data["summary"]
    counts = summary["findings_by_severity"]
    total = sum(counts.values())
    if counts["critical"]:
        headline = "This log shows signs of a break-in."
    elif counts["high"]:
        headline = "This log shows active attacks on your server."
    elif total:
        headline = "This log shows suspicious activity."
    else:
        headline = "No attacks found in this log."

    parts = [f"{counts[name]} {name}" for name in ("critical", "high", "medium", "low") if counts[name]]
    found = f"{total} finding{'s' if total != 1 else ''} ({', '.join(parts)})" if total else "No findings"
    start = datetime.fromisoformat(summary["start"])
    end = datetime.fromisoformat(summary["end"])
    period = (
        f"{start:%d %b %Y, %H:%M} to {end:%H:%M}"
        if start.date() == end.date()
        else f"{start:%d %b %Y, %H:%M} to {end:%d %b %Y, %H:%M}"
    )
    detail = (
        f"{found} in {summary['total_events']} login events "
        f"({summary['failed']} failed), {period}."
    )
    return {"headline": headline, "detail": detail}


def build_blocklist(data: Dict[str, Any]) -> List[str]:
    networks = [ipaddress.ip_network(n, strict=False) for n in data.get("settings", {}).get("internal_networks", [])]
    seen: List[str] = []
    for finding in data["findings"]:
        if finding["rule"] not in _ATTACK_RULES or finding["ip"] in seen:
            continue
        address = ipaddress.ip_address(finding["ip"])
        if any(address in network for network in networks):
            continue
        seen.append(finding["ip"])
    return seen


def build_chart(hourly: List[Dict[str, int]]) -> Dict[str, Any]:
    """Geometry for the hourly SVG chart (CSP forbids inline styles, so we use attributes)."""
    plot_height, baseline, slot = 130, 150, 30
    peak = max((h["failed"] + h["accepted"] for h in hourly), default=0) or 1
    bars = []
    for h in hourly:
        failed_h = round(h["failed"] / peak * plot_height, 1)
        accepted_h = round(h["accepted"] / peak * plot_height, 1)
        bars.append(
            {
                "x": h["hour"] * slot + 5,
                "failed_h": failed_h,
                "failed_y": round(baseline - failed_h, 1),
                "accepted_h": accepted_h,
                "accepted_y": round(baseline - failed_h - accepted_h, 1),
                "label": f"{h['hour']:02d}",
                "show_label": h["hour"] % 3 == 0,
                "tip": f"{h['hour']:02d}:00 - {h['failed']} failed, {h['accepted']} accepted",
            }
        )
    return {"bars": bars, "peak": peak, "baseline": baseline}


# --------------------------------------------------------------------------- app factory


def create_app(
    db_path: Optional[str] = None,
    max_upload_bytes: int = MAX_UPLOAD_BYTES,
    rate_limit: Tuple[int, int] = (30, 600),
) -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = max_upload_bytes
    app.config["JSON_SORT_KEYS"] = False

    if os.environ.get("SECLOG_TRUST_PROXY") == "1":
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)  # type: ignore[assignment]

    store = Store(db_path or os.environ.get("SECLOG_DB", "data/seclog.db"))
    limiter = RateLimiter(*rate_limit)
    repo_url = os.environ.get("SECLOG_REPO_URL", "")
    # Free hosting tiers wipe local files when the server idles, so saved results are short-lived.
    ephemeral = os.environ.get("SECLOG_EPHEMERAL") == "1"

    @app.template_filter("dt")
    def format_datetime(value: Any) -> str:
        moment = value if isinstance(value, datetime) else datetime.fromisoformat(value)
        return moment.strftime("%d %b %Y, %H:%M")

    @app.template_filter("when")
    def format_epoch(value: float) -> str:
        return datetime.fromtimestamp(value).strftime("%d %b %Y, %H:%M")

    @app.context_processor
    def inject_globals() -> Dict[str, Any]:
        return {
            "version": __version__,
            "repo_url": repo_url,
            "retention_days": RETENTION_DAYS,
            "ephemeral": ephemeral,
        }

    # ----- request plumbing

    @app.before_request
    def identify_visitor() -> None:
        sid = request.cookies.get(COOKIE_NAME, "")
        if not (16 <= len(sid) <= 64):
            sid = secrets.token_urlsafe(16)
            g.new_sid = sid
        g.sid = sid

    @app.before_request
    def reject_cross_site_posts() -> None:
        if request.method == "POST" and not request.path.startswith("/api/"):
            origin = request.headers.get("Origin")
            if origin and origin != request.host_url.rstrip("/"):
                abort(403)

    @app.after_request
    def secure_response(response: Response) -> Response:
        if getattr(g, "new_sid", None):
            response.set_cookie(
                COOKIE_NAME, g.new_sid, max_age=COOKIE_MAX_AGE,
                httponly=True, samesite="Lax", secure=request.is_secure,
            )
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self' data:; "
            "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["X-Frame-Options"] = "DENY"
        if request.is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        if not request.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    def wants_json() -> bool:
        return request.path.startswith("/api/")

    @app.errorhandler(HTTPException)
    def handle_http_error(error: HTTPException):
        messages = {
            400: "The request could not be understood.",
            403: "This request was blocked because it came from another site.",
            404: (
                "We could not find that page. This demo server resets when it is idle, so saved "
                "analyses can disappear, or the link may be mistyped."
                if ephemeral
                else f"We could not find that page. Analyses are deleted after {RETENTION_DAYS} "
                "days, or the link may be mistyped."
            ),
            405: "That action is not allowed here.",
            413: f"That file is larger than {max_upload_bytes // (1024 * 1024) or 1} MB. "
                 "Upload a smaller log, or split it by day.",
            429: "You have run several analyses in a short time. Wait a few minutes and try again.",
        }
        code = error.code or 500
        message = messages.get(code, error.description or "Something went wrong.")
        if wants_json():
            return jsonify(error=message), code
        return render_template("error.html", status=code, message=message), code

    # ----- helpers

    def check_rate_limit() -> None:
        if not limiter.allow(request.remote_addr or "unknown"):
            abort(429)

    def store_result(raw: bytes, filename: str, year_override: Optional[int] = None) -> str:
        data = run_analysis(raw, request.form, year_override)
        return store.save(g.sid, filename, data)

    def render_index(error: Optional[str] = None, status: int = 200):
        return render_template("index.html", error=error, form=request.form), status

    # ----- pages

    @app.get("/")
    def index():
        return render_index()

    @app.post("/analyze")
    def analyze_upload():
        check_rate_limit()
        upload = request.files.get("file")
        if upload is None or not upload.filename:
            return render_index("Choose a log file to analyze.", 400)
        try:
            analysis_id = store_result(upload.read(), clean_filename(upload.filename))
        except (SettingsError, LogError) as exc:
            return render_index(str(exc), 400)
        return redirect(url_for("view_analysis", analysis_id=analysis_id), code=303)

    @app.post("/analyze/sample")
    def analyze_sample():
        check_rate_limit()
        if not SAMPLE_LOG.exists():
            abort(404)
        analysis_id = store_result(SAMPLE_LOG.read_bytes(), "sample auth.log", SAMPLE_YEAR)
        return redirect(url_for("view_analysis", analysis_id=analysis_id), code=303)

    @app.get("/a/<analysis_id>")
    def view_analysis(analysis_id: str):
        row = store.get(analysis_id) or abort(404)
        data = row["data"]
        expires = datetime.fromtimestamp(row["created_at"]) + timedelta(days=RETENTION_DAYS)
        return render_template(
            "analysis.html",
            row=row,
            data=data,
            verdict=build_verdict(data),
            blocklist=build_blocklist(data),
            chart=build_chart(data["hourly"]),
            is_owner=row["owner"] == g.sid,
            expires=expires,
        )

    @app.get("/a/<analysis_id>/report.html")
    def download_html(analysis_id: str):
        row = store.get(analysis_id) or abort(404)
        html = render_html(Analysis.from_dict(row["data"]), source_name=row["filename"])
        response = make_response(html)
        response.headers["Content-Type"] = "text/html; charset=utf-8"
        response.headers["Content-Disposition"] = f'attachment; filename="seclog-report-{analysis_id}.html"'
        return response

    @app.get("/a/<analysis_id>/report.json")
    def download_json(analysis_id: str):
        row = store.get(analysis_id) or abort(404)
        response = make_response(render_json(Analysis.from_dict(row["data"])))
        response.headers["Content-Type"] = "application/json"
        response.headers["Content-Disposition"] = f'attachment; filename="seclog-report-{analysis_id}.json"'
        return response

    @app.post("/a/<analysis_id>/delete")
    def delete_analysis(analysis_id: str):
        if not store.delete(analysis_id, g.sid):
            abort(404)
        return redirect(url_for("history"), code=303)

    @app.get("/history")
    def history():
        items = []
        for row in store.list_for_owner(g.sid):
            summary = row["data"]["summary"]
            counts = summary["findings_by_severity"]
            worst = next((s for s in ("critical", "high", "medium", "low") if counts[s]), None)
            items.append({"row": row, "total": sum(counts.values()), "worst": worst})
        return render_template("history.html", items=items)

    # ----- API

    @app.post("/api/analyze")
    def api_analyze():
        check_rate_limit()
        upload = request.files.get("file")
        if upload is None:
            return jsonify(error="Send the log as multipart form data in a field named 'file'."), 400
        try:
            analysis_id = store_result(upload.read(), clean_filename(upload.filename))
        except (SettingsError, LogError) as exc:
            return jsonify(error=str(exc)), 400
        row = store.get(analysis_id)
        body = {
            "id": analysis_id,
            "url": url_for("view_analysis", analysis_id=analysis_id, _external=True),
            "api_url": url_for("api_get", analysis_id=analysis_id, _external=True),
            **row["data"],
        }
        return jsonify(body), 201

    @app.get("/api/analyses/<analysis_id>")
    def api_get(analysis_id: str):
        row = store.get(analysis_id) or abort(404)
        return jsonify({"id": analysis_id, "filename": row["filename"], **row["data"]})

    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok", version=__version__)

    return app
