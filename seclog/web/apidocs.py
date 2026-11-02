"""Content of the /docs page. Kept as data so a test can check it against the real routes."""

from __future__ import annotations

from typing import Any, Dict, List

SETTINGS_FIELDS: List[Dict[str, str]] = [
    {"name": "year", "default": "current year", "values": "1970 to 2100. Only used for classic syslog timestamps."},
    {"name": "brute_force_threshold", "default": "5", "values": "2 to 1000 failed logins, one address against one account"},
    {"name": "brute_force_window", "default": "5", "values": "1 to 1440 minutes"},
    {"name": "spray_users", "default": "5", "values": "2 to 1000 different accounts from one address"},
    {"name": "spray_window", "default": "10", "values": "1 to 1440 minutes"},
    {"name": "compromise_failures", "default": "3", "values": "1 to 1000 failures before a success that looks like a takeover"},
    {"name": "compromise_window", "default": "10", "values": "1 to 1440 minutes"},
    {"name": "privileged", "default": "root, admin, administrator, sysadmin", "values": "Extra account names, space or comma separated, at most 20"},
    {"name": "internal_networks", "default": "RFC 1918, loopback, link-local", "values": "Extra CIDR ranges, space or comma separated, at most 20"},
]

API_SECTIONS: List[Dict[str, Any]] = [
    {
        "method": "POST",
        "path": "/api/analyze",
        "title": "Analyze a log",
        "summary": "Send a plain-text sshd log as multipart form data. The log is analyzed in memory and not stored; the result is.",
        "fields": [{"name": "file", "default": "required", "values": "Plain-text log up to 5 MB. Empty, binary and gzip files are rejected."}] + SETTINGS_FIELDS,
        "example": "curl -F file=@sample_data/auth.log -F year=2026 {base}/api/analyze",
        "responses": [
            ("201", "Analysis finished. Body has id, url, api_url, summary, top_sources, hourly, event_types, timeline, suspicious_hourly, findings, events and settings."),
            ("400", "No file, empty, binary or gzip file, no SSH events found, or an invalid setting."),
            ("413", "File larger than 5 MB."),
            ("429", "Rate limit reached (30 analyses per address per 10 minutes). Retry-After says when to try again."),
            ("500", "Unexpected error. Details are only in the server log."),
        ],
        "testable_path": "/api/analyze",
    },
    {
        "method": "GET",
        "path": "/api/analyses/{id}",
        "title": "Fetch a stored result",
        "summary": "Same body as the analysis response plus the file name. Results expire after 7 days, or when the host restarts on the free tier.",
        "fields": [],
        "example": "curl {base}/api/analyses/<id>",
        "responses": [("200", "Found."), ("404", "Unknown id, expired or deleted.")],
        "testable_path": "/api/analyses/<analysis_id>",
    },
    {
        "method": "GET",
        "path": "/healthz",
        "title": "Health check",
        "summary": "Used by Render and by the Docker HEALTHCHECK.",
        "fields": [],
        "example": "curl {base}/healthz",
        "responses": [("200", '{"status": "ok", "version": "..."}')],
        "testable_path": "/healthz",
    },
    {
        "method": "GET",
        "path": "/a/{id}/report.pdf",
        "title": "Downloads",
        "summary": "Reports for one analysis: report.pdf (branded report with charts), report.html, report.json, report.csv (findings) and events.csv (suspicious events).",
        "fields": [],
        "example": "curl -OJ {base}/a/<id>/report.pdf",
        "responses": [("200", "File download."), ("404", "Unknown id."), ("503", "PDF generation is not installed on this server.")],
        "testable_path": "/a/<analysis_id>/report.pdf",
    },
]

ERROR_EXAMPLES = [
    ("400", '{"error": "The file is empty. Choose a log file that contains SSH login lines."}'),
    ("404", '{"error": "We could not find that page. ..."}'),
    ("429", '{"error": "You have run several analyses in a short time. Wait a few minutes and try again."}'),
]
