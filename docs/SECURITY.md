# Security review

This is a practical review of the code in this repository, done by reading it and by writing a test
for each claim. It is **not** a penetration test or an independent audit, and the app is a portfolio
project, not a production service. Where a claim has a test, the test file is named.

## What the app accepts and what it does with it

An uploaded log is attacker-controlled text. The app reads it into memory, parses it with regular
expressions, and keeps only the findings. It never executes, includes, or follows anything from it.

## Controls and how each is checked

| Area | Control | Checked by |
|---|---|---|
| File type | No trust in the extension or the browser's content type. Empty files, gzip (magic bytes) and binary files (NUL bytes) are rejected with a clear message. Content that contains no SSH events is rejected | `ContentValidationTests`, `UploadValidationTests` |
| File size | 5 MB cap on the file, plus a request-size cap above it. Over the limit gives `413` | `test_file_just_under_the_limit_is_accepted`, `test_file_just_over_the_limit_is_rejected`, `test_oversized_upload_is_rejected` |
| Hostile line content | Lines over 4096 characters are ignored; usernames are cut to 64 characters; control characters (including terminal escapes) are replaced. 4000 randomly corrupted lines never crash the parser or produce an invalid event | `ParserEdgeCaseTests`, `ParserRobustnessTests` |
| File names and paths | The file name is never used to open, create or name a file. It is reduced to its base name, stripped of control characters, trimmed to 80 characters, escaped when displayed, and stored only as text | `test_filename_cannot_reach_the_filesystem`, `test_filename_is_escaped_and_trimmed` |
| Static files | Flask's static handler serves only `seclog/web/static`; path traversal attempts return 404 | `test_static_files_cannot_escape_the_static_folder` |
| XSS | Jinja autoescaping on every template, no `\|safe`, no `render_template_string`. Usernames, file names and search text are escaped. A strict Content Security Policy (`script-src 'self'`, `style-src 'self'`, no `unsafe-inline`) is a second layer. The charts use SVG attributes because inline styles are blocked | `SecurityTests`, `test_security_headers_and_no_inline_script`, `test_search_term_is_escaped` |
| CSV injection | Cells starting with `=`, `+`, `-`, `@`, tab or CR get a leading apostrophe | `test_spreadsheet_formulas_in_usernames_are_neutralised`, `test_csv_safe` |
| Injection | The only database is SQLite, and every query uses bound parameters. Nothing builds a shell command or evaluates input | code review; `grep` for `eval`, `exec`, `subprocess`, `os.system`, `pickle`, `shell=True` finds nothing |
| Cross-site requests | Form posts with a foreign `Origin` header get `403`. The session cookie is `HttpOnly`, `SameSite=Lax`, and `Secure` over HTTPS. The API sends no CORS headers, so other sites cannot read its responses from a browser | `test_cross_site_post_is_blocked`, `test_visitor_cookie_is_httponly`, `test_no_cors_headers_are_sent` |
| Security headers | CSP, `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`, HSTS over HTTPS, `Cache-Control: no-store` on dynamic pages | `test_extra_security_headers`, `test_security_headers_and_no_inline_script` |
| Error handling | Every unexpected exception returns a generic message and is logged server-side; no stack traces or paths reach the visitor. API errors are JSON | `test_unexpected_error_hides_internals`, `test_unexpected_api_error_is_json` |
| Debug mode | Not enabled anywhere; the app is started through gunicorn | `test_debug_mode_is_off` |
| Logging | Server log lines hold an id, byte count, event count, finding count and timing only. No file names, usernames or addresses | `test_log_lines_do_not_contain_uploaded_content` |
| Abuse | Per-address rate limit (30 analyses per 10 minutes), bounded setting values (for example thresholds 1 to 1000, at most 20 list entries), 7-day retention and a 1000-row cap on stored analyses | `test_rate_limit`, `test_api_rate_limit_is_json_429`, `StorageTests` |
| Secrets | The code needs none. A search of the repository found no keys, tokens or passwords. Configuration is environment variables only. `.env` is git-ignored | manual search |
| Containers | The Docker image runs as an unprivileged user and defines a health check | `Dockerfile`; built and smoke-tested by the `docker` CI job |

## What is stored, and for how long

The raw upload is processed in memory and discarded. This is tested: `test_raw_log_is_never_persisted`
writes a unique marker into a log and checks that it does not appear in the database file.

What **is** stored in SQLite, per analysis, for 7 days (or until the owner deletes it, or until a
free host restarts):

- the file name (cleaned),
- counts and the hourly histogram,
- each finding, including the account names and the source addresses involved,
- up to 1000 individual suspicious events (time, account, source address, method, why flagged),
- the detection settings used.

So usernames and IP addresses that appear in a finding are stored. They are shown to anyone with the
analysis link (the link contains a 72-bit random id and is not listed anywhere). Do not upload logs
you are not allowed to share. The demo is meant for synthetic or personal-server logs.

## Known limitations

- **No accounts.** A visitor is identified by a random cookie. Anyone with a result link can read it,
  but only the browser that created it can delete it.
- **In-memory rate limiting.** It resets on restart and is per process, so it does not protect a
  multi-instance deployment. A determined client could also rotate addresses.
- **No malware scanning** of uploads. Content is only ever parsed as text.
- **Timestamps.** ISO timestamps keep their wall-clock time and ignore the UTC offset. Mixed time zones
  in one file are not normalised.
- **Detection is rule based.** It can miss attacks that stay under the thresholds, spread across many
  addresses, or use methods that are not written as `Failed`/`Accepted` lines, and it can flag
  legitimate activity (a user who mistypes a password, an administrator working remotely). Findings
  are indicators, never confirmations.
- **Not independently tested.** The parser has a seeded random-mutation test, but there is no
  dedicated fuzzing, no external penetration test and no dependency scanning in CI yet.
- **Single-file database.** See the scaling notes in `DEPLOYMENT.md`.

## Reporting a problem

Open a GitHub issue. Do not paste real logs or credentials into it.
