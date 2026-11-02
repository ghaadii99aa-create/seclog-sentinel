# REST API

Everything the web page does is available over HTTP. Base URL for local use is
`http://127.0.0.1:5000`; the public demo is `https://seclog-sentinel.onrender.com`.

All API errors are JSON with one key: `{"error": "<message>"}`. Messages never contain stack
traces, file paths or other internals.

The API has no authentication and sends **no CORS headers**, so browsers on other sites cannot
call it from JavaScript. Use it from scripts, CI jobs and `curl`. Every request is rate limited
(30 analyses per client address per 10 minutes by default).

## `POST /api/analyze`

Analyze an SSH log. Send `multipart/form-data`.

| Field | Required | Default | Allowed values |
|---|---|---|---|
| `file` | yes | | A plain-text sshd log, up to 5 MB. Empty, binary and gzip files are rejected. |
| `year` | no | current year | 1970 to 2100. Only used for classic syslog timestamps, which have no year. |
| `brute_force_threshold` | no | 5 | 2 to 1000 failed logins from one address against one account |
| `brute_force_window` | no | 5 | 1 to 1440 minutes |
| `spray_users` | no | 5 | 2 to 1000 distinct accounts from one address |
| `spray_window` | no | 10 | 1 to 1440 minutes |
| `compromise_failures` | no | 3 | 1 to 1000 failures before a success that looks like a takeover |
| `compromise_window` | no | 10 | 1 to 1440 minutes |
| `privileged` | no | root, admin, administrator, sysadmin | Extra privileged account names, space or comma separated, at most 20 |
| `internal_networks` | no | RFC 1918, loopback, link-local | Extra CIDR ranges, space or comma separated, at most 20 |

```bash
curl -F file=@sample_data/auth.log -F year=2026 \
     https://seclog-sentinel.onrender.com/api/analyze
```

**`201 Created`**

```jsonc
{
  "id": "W8AwvZnWoick",                       // share and fetch handle, unguessable
  "url": "https://…/a/W8AwvZnWoick",          // the dashboard page
  "api_url": "https://…/api/analyses/W8AwvZnWoick",
  "summary": {
    "total_events": 119, "failed": 76, "accepted": 43,
    "unique_ips": 17, "unique_users": 24,
    "start": "2026-10-20T02:41:11", "end": "2026-10-20T22:14:52",   // local wall-clock time from the log
    "ignored_lines": 41,                       // lines that were not SSH logins
    "suspicious_events": 61,                   // events that support a finding
    "findings_by_severity": {"critical": 1, "high": 3, "medium": 1, "low": 0}
  },
  "top_sources": [{"ip": "203.0.113.45", "failures": 38, "distinct_users": 1}],   // up to 10
  "hourly": [{"hour": 2, "failed": 38, "accepted": 0}],                              // always 24 entries
  "findings": [{
    "rule": "brute_force",                     // brute_force | password_spraying | success_after_failures | privileged_external_login
    "title": "Brute-force attempt against 'root'",
    "severity": "high",                        // critical | high | medium | low
    "assessment": "Suspicious indicator",      // or "Likely compromise, investigate now". Never "confirmed".
    "ip": "203.0.113.45",
    "users": ["root"],
    "count": 38,
    "first_seen": "2026-10-20T02:41:11", "last_seen": "2026-10-20T02:43:39",
    "mitre": {"id": "T1110.001", "name": "Password Guessing"},
    "description": "38 failed logins for 'root' from 203.0.113.45 within 148s …",
    "reason": "Flagged because 38 failed logins … The threshold is 5.",
    "recommendation": "Block or rate-limit the source IP …"
  }],
  "events": [{                                 // only events that support a finding, at most 1000
    "time": "2026-10-20T02:41:11", "type": "failed login", "user": "root", "ip": "203.0.113.45",
    "method": "password", "severity": "high", "rules": ["brute_force"],
    "reason": "Brute-force attempt against 'root'", "recommendation": "…"
  }],
  "settings": {"year": 2026, "brute_force_failures": 5, "brute_force_window_minutes": 5, "…": "…"}
}
```

| Status | When |
|---|---|
| `201` | Analysis finished and stored |
| `400` | No `file` field, empty file, binary or gzip file, no SSH events found, or an invalid setting. The message says which and how to fix it |
| `413` | File larger than 5 MB |
| `429` | Rate limit reached |
| `500` | Unexpected server error (details are in the server log only) |

## `GET /api/analyses/{id}`

Fetch a stored result. The body is the same as above plus `"filename"`, without `url`/`api_url`.

```bash
curl https://seclog-sentinel.onrender.com/api/analyses/W8AwvZnWoick
```

| Status | When |
|---|---|
| `200` | Found |
| `404` | Unknown id, or the result has expired (7 days) or the host restarted (free tier) |

## `GET /healthz`

Liveness check used by Render and by the Docker `HEALTHCHECK`. Returns `200` with
`{"status": "ok", "version": "1.2.0"}`.

## Downloads (not JSON endpoints)

For an analysis `id`: `GET /a/{id}/report.html`, `/a/{id}/report.json`, `/a/{id}/report.csv`
(one row per finding) and `/a/{id}/events.csv` (one row per suspicious event). CSV cells that
start with `=`, `+`, `-` or `@` get a leading apostrophe so a hostile username cannot run as a
spreadsheet formula.

## Other status codes

`405` for a wrong method, and `404` for an unknown path, are also returned as `{"error": …}`
under `/api/`.


## PDF report and the `/docs` page

`GET /a/<id>/report.pdf` returns a branded PDF (cover page, summary, severity distribution, charts,
findings with evidence, why it matters and defensive actions, analysis date). It returns `503` with a JSON
error if ReportLab is not installed. The same reference is rendered at `/docs`, and a test checks that
every route listed there exists. New fields in the analysis JSON: `event_types`, `timeline`,
`suspicious_hourly`, and `impact` on each finding.
