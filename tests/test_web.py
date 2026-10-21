import io
import json
import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("SECLOG_LOG_LEVEL", "WARNING")  # keep test output quiet

try:
    from seclog.web import create_app
    from seclog.web.storage import RETENTION_DAYS, Store
except ModuleNotFoundError:  # Flask is an optional extra
    create_app = None

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "sample_data" / "auth.log"


def base_path(location):
    """Strip the ?done=1 marker so a result URL can be extended with /report.json etc."""
    return location.split("?")[0]


def attack_log(user="root", ip="203.0.113.9", count=6):
    return "".join(
        f"Oct 20 03:00:{i:02d} srv sshd[1]: Failed password for {user} from {ip} port 22 ssh2\n"
        for i in range(count)
    ).encode()


@unittest.skipIf(create_app is None, "Flask is not installed")
class WebTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "test.db")
        self.app = create_app(db_path=self.db)
        self.client = self.app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def upload(self, data, name="auth.log", client=None, **fields):
        return (client or self.client).post(
            "/analyze",
            data={"file": (io.BytesIO(data), name), **fields},
            content_type="multipart/form-data",
        )


class PageTests(WebTestCase):
    def test_landing_page(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Find out who has been guessing", response.data)

    def test_security_headers_and_no_inline_script(self):
        response = self.client.get("/")
        csp = response.headers["Content-Security-Policy"]
        self.assertIn("script-src 'self'", csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertNotIn(b"<script>", response.data)
        self.assertNotIn(b' style="', response.data)  # inline styles would violate the CSP

    def test_visitor_cookie_is_httponly(self):
        cookie = self.client.get("/").headers["Set-Cookie"]
        self.assertIn("sid=", cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)

    def test_open_graph_tags_for_link_previews(self):
        html = self.client.get("/", base_url="https://demo.example.com").get_data(as_text=True)
        self.assertIn('property="og:title"', html)
        self.assertIn('property="og:image" content="https://demo.example.com/static/og.png"', html)
        self.assertIn('name="twitter:card" content="summary_large_image"', html)
        image = self.client.get("/static/og.png")
        self.assertEqual(image.status_code, 200)
        self.assertEqual(image.mimetype, "image/png")
        self.assertEqual(image.data[:8], b"\x89PNG\r\n\x1a\n")
        image.close()

    def test_ephemeral_mode_does_not_promise_retention(self):
        normal = self.client.get("/").get_data(as_text=True)
        self.assertIn("for 7 days", normal)
        os.environ["SECLOG_EPHEMERAL"] = "1"
        try:
            demo = create_app(db_path=self.db).test_client()
            text = demo.get("/").get_data(as_text=True)
            self.assertNotIn("for 7 days", text)
            self.assertIn("resets when idle", text)
            self.assertIn("demo server resets", demo.get("/a/missing").get_data(as_text=True))
        finally:
            del os.environ["SECLOG_EPHEMERAL"]

    def test_healthz(self):
        self.assertEqual(self.client.get("/healthz").get_json()["status"], "ok")

    def test_unknown_analysis_is_404_page(self):
        response = self.client.get("/a/doesnotexist")
        self.assertEqual(response.status_code, 404)
        self.assertIn(b"could not find that page", response.data)


@unittest.skipUnless(SAMPLE.exists(), "sample log missing")
class AnalysisFlowTests(WebTestCase):
    def test_sample_analysis_end_to_end(self):
        response = self.client.post("/analyze/sample")
        self.assertEqual(response.status_code, 303)
        page = self.client.get(response.headers["Location"])
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"signs of a break-in", page.data)
        self.assertIn(b"Possible account compromise", page.data)
        self.assertIn(b"203.0.113.45", page.data)  # attacker shown in block list

    def test_upload_real_file(self):
        response = self.upload(SAMPLE.read_bytes(), year="2026")
        self.assertEqual(response.status_code, 303)

    def test_downloads(self):
        location = base_path(self.client.post("/analyze/sample").headers["Location"])
        html = self.client.get(location + "/report.html")
        self.assertEqual(html.status_code, 200)
        self.assertIn("attachment", html.headers["Content-Disposition"])
        self.assertTrue(html.data.startswith(b"<!doctype html>"))
        data = json.loads(self.client.get(location + "/report.json").data)
        self.assertEqual(data["summary"]["total_events"], 119)

    def test_internal_addresses_are_not_in_blocklist(self):
        page = self.client.get(self.client.post("/analyze/sample").headers["Location"]).get_data(as_text=True)
        block = page.split('id="blocklist"')[1].split("</textarea>")[0]
        self.assertNotIn("10.20.", block)


class UploadValidationTests(WebTestCase):
    def test_missing_file(self):
        response = self.client.post("/analyze", data={}, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Choose a log file", response.data)

    def test_file_without_ssh_events(self):
        response = self.upload(b"just some text\nanother line\n")
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"No SSH login events were found", response.data)

    def test_oversized_upload_is_rejected(self):
        app = create_app(db_path=self.db, max_upload_bytes=1024)
        response = app.test_client().post(
            "/analyze",
            data={"file": (io.BytesIO(b"x" * 5000), "big.log")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 413)
        self.assertIn(b"larger than", response.data)

    def test_file_just_under_the_limit_is_accepted(self):
        app = create_app(db_path=self.db, max_upload_bytes=2048)
        body = attack_log()[:600]
        self.assertLess(len(body), 2048)
        response = app.test_client().post(
            "/analyze", data={"file": (io.BytesIO(body), "ok.log"), "year": "2026"}, content_type="multipart/form-data"
        )
        self.assertEqual(response.status_code, 303)

    def test_file_just_over_the_limit_is_rejected(self):
        app = create_app(db_path=self.db, max_upload_bytes=1024)
        response = app.test_client().post(
            "/analyze", data={"file": (io.BytesIO(b"x" * 1025), "big.log")}, content_type="multipart/form-data"
        )
        self.assertEqual(response.status_code, 413)

    def test_invalid_settings_explain_the_fix(self):
        for field, value, expected in [
            ("brute_force_threshold", "abc", b"must be a whole number"),
            ("brute_force_threshold", "0", b"must be between"),
            ("internal_networks", "not-a-cidr", b"CIDR notation"),
        ]:
            with self.subTest(field=field, value=value):
                response = self.upload(attack_log(), **{field: value})
                self.assertEqual(response.status_code, 400)
                self.assertIn(expected, response.data)

    def test_custom_threshold_changes_result(self):
        # 6 failures trigger brute force at the default (5) but not at 10.
        strict = self.upload(attack_log(user="dr.sara"), brute_force_threshold="10", year="2026")
        page = self.client.get(strict.headers["Location"])
        self.assertIn(b"No attacks found", page.data)
        default = self.upload(attack_log(user="dr.sara"), year="2026")
        self.assertIn(b"Brute-force attempt", self.client.get(default.headers["Location"]).data)


class SecurityTests(WebTestCase):
    def test_log_content_is_html_escaped(self):
        payload = "<script>alert(1)</script>"
        response = self.upload(attack_log(user=payload), year="2026")
        page = self.client.get(response.headers["Location"]).get_data(as_text=True)
        self.assertNotIn(payload, page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)

    def test_filename_is_escaped_and_trimmed(self):
        response = self.upload(attack_log(), name="<img src=x onerror=alert(1)>.log", year="2026")
        page = self.client.get(response.headers["Location"]).get_data(as_text=True)
        self.assertNotIn("<img src=x", page)

    def test_cross_site_post_is_blocked(self):
        response = self.client.post("/analyze/sample", headers={"Origin": "https://evil.example"})
        self.assertEqual(response.status_code, 403)

    def test_same_origin_post_is_allowed(self):
        response = self.client.post("/analyze/sample", headers={"Origin": "http://localhost"})
        self.assertEqual(response.status_code, 303)

    def test_rate_limit(self):
        app = create_app(db_path=self.db, rate_limit=(2, 600))
        client = app.test_client()
        codes = [client.post("/analyze/sample").status_code for _ in range(3)]
        self.assertEqual(codes, [303, 303, 429])


class OwnershipTests(WebTestCase):
    def test_share_link_works_but_only_owner_can_delete(self):
        owner = self.app.test_client()
        stranger = self.app.test_client()
        location = base_path(self.upload(attack_log(), client=owner, year="2026").headers["Location"])

        self.assertEqual(stranger.get(location).status_code, 200)  # link sharing
        self.assertEqual(stranger.post(location + "/delete").status_code, 404)
        self.assertEqual(owner.post(location + "/delete").status_code, 303)
        self.assertEqual(owner.get(location).status_code, 404)

    def test_history_only_lists_own_analyses(self):
        owner = self.app.test_client()
        stranger = self.app.test_client()
        self.upload(attack_log(), name="mine.log", client=owner, year="2026")
        self.assertIn(b"mine.log", owner.get("/history").data)
        other = stranger.get("/history")
        self.assertNotIn(b"mine.log", other.data)
        self.assertIn(b"have not analyzed a log", other.data)


class ApiTests(WebTestCase):
    def test_api_round_trip(self):
        response = self.client.post(
            "/api/analyze",
            data={"file": (io.BytesIO(attack_log(user="dr.sara")), "a.log"), "year": "2026"},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 201)
        body = response.get_json()
        self.assertEqual(body["summary"]["failed"], 6)
        self.assertEqual(body["findings"][0]["rule"], "brute_force")
        fetched = self.client.get(f"/api/analyses/{body['id']}").get_json()
        self.assertEqual(fetched["findings"], body["findings"])

    def test_api_response_schema(self):
        response = self.client.post(
            "/api/analyze",
            data={"file": (io.BytesIO(attack_log(user="dr.sara")), "a.log"), "year": "2026"},
            content_type="multipart/form-data",
        )
        body = response.get_json()
        self.assertEqual(response.mimetype, "application/json")
        self.assertEqual(
            set(body), {"id", "url", "api_url", "summary", "top_sources", "hourly", "findings", "events", "settings"}
        )
        self.assertEqual(
            set(body["summary"]),
            {"total_events", "failed", "accepted", "unique_ips", "unique_users", "start", "end",
             "ignored_lines", "suspicious_events", "findings_by_severity"},
        )
        finding = body["findings"][0]
        self.assertEqual(
            set(finding),
            {"rule", "title", "severity", "ip", "users", "count", "first_seen", "last_seen", "mitre",
             "description", "recommendation", "reason", "assessment"},
        )
        self.assertEqual(len(body["hourly"]), 24)
        self.assertEqual(body["summary"]["suspicious_events"], 6)

    def test_api_settings_are_validated(self):
        response = self.client.post(
            "/api/analyze",
            data={"file": (io.BytesIO(attack_log()), "a.log"), "brute_force_threshold": "0"},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("must be between", response.get_json()["error"])

    def test_api_rejects_bad_files_with_json(self):
        for data, status in ((b"", 400), (b"\x00\x01\x02", 400), (b"nothing useful\n", 400)):
            with self.subTest(data=data):
                response = self.client.post(
                    "/api/analyze", data={"file": (io.BytesIO(data), "a.log")}, content_type="multipart/form-data"
                )
                self.assertEqual(response.status_code, status)
                self.assertEqual(response.mimetype, "application/json")
                self.assertEqual(list(response.get_json()), ["error"])

    def test_api_oversized_upload_is_json_413(self):
        app = create_app(db_path=self.db, max_upload_bytes=1024)
        response = app.test_client().post(
            "/api/analyze", data={"file": (io.BytesIO(b"x" * 5000), "big.log")}, content_type="multipart/form-data"
        )
        self.assertEqual(response.status_code, 413)
        self.assertIn("error", response.get_json())

    def test_api_wrong_method_and_unknown_route_are_json(self):
        for method, path, status in (("get", "/api/analyze", 405), ("post", "/api/analyses/x", 405), ("get", "/api/nothing", 404)):
            with self.subTest(path=path):
                response = getattr(self.client, method)(path)
                self.assertEqual(response.status_code, status)
                self.assertEqual(list(response.get_json()), ["error"])

    def test_api_rate_limit_is_json_429(self):
        client = create_app(db_path=self.db, rate_limit=(1, 600)).test_client()
        for expected in (201, 429):
            response = client.post(
                "/api/analyze", data={"file": (io.BytesIO(attack_log()), "a.log"), "year": "2026"},
                content_type="multipart/form-data",
            )
            self.assertEqual(response.status_code, expected)
        self.assertIn("error", response.get_json())

    def test_api_errors_are_json(self):
        missing = self.client.post("/api/analyze", data={}, content_type="multipart/form-data")
        self.assertEqual(missing.status_code, 400)
        self.assertIn("error", missing.get_json())
        self.assertEqual(self.client.get("/api/analyses/nope").status_code, 404)
        self.assertIn("error", self.client.get("/api/analyses/nope").get_json())


class ContentValidationTests(WebTestCase):
    def test_empty_file(self):
        for data in (b"", b"   \n\n"):
            with self.subTest(data=data):
                response = self.upload(data)
                self.assertEqual(response.status_code, 400)
                self.assertIn(b"The file is empty", response.data)

    def test_binary_file(self):
        response = self.upload(b"\x7fELF\x02\x01\x01\x00" + bytes(range(256)))
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"binary file", response.data)

    def test_gzip_file(self):
        import gzip

        response = self.upload(gzip.compress(attack_log()), name="auth.log.1.gz")
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"compressed", response.data)

    def test_malformed_lines_are_counted_not_fatal(self):
        data = b"garbage line\n" * 5 + attack_log(user="dr.sara")
        response = self.upload(data, year="2026")
        self.assertEqual(response.status_code, 303)
        body = self.client.get(response.headers["Location"]).get_data(as_text=True)
        self.assertIn("5 that were not SSH logins", body)

    def test_non_utf8_bytes_do_not_crash(self):
        response = self.upload(b"\xff\xfe bad bytes\n" + attack_log(), year="2026")
        self.assertEqual(response.status_code, 303)

    def test_filename_cannot_reach_the_filesystem(self):
        for name in ("../../../etc/passwd", "..\\..\\windows\\win.ini", "/etc/shadow", "a\x00b.log"):
            with self.subTest(name=name):
                response = self.upload(attack_log(), name=name, year="2026")
                self.assertEqual(response.status_code, 303)
                page = self.client.get(response.headers["Location"]).get_data(as_text=True)
                self.assertNotIn("../", page)
        # Nothing was written next to the database except the database itself.
        self.assertEqual(sorted(os.listdir(self.tmp.name)), ["test.db"])


@unittest.skipUnless(SAMPLE.exists(), "sample log missing")
class DashboardTests(WebTestCase):
    def setUp(self):
        super().setUp()
        self.location = base_path(self.client.post("/analyze/sample").headers["Location"])

    def page(self, query=""):
        response = self.client.get(self.location + query)
        self.assertEqual(response.status_code, 200)
        return response.get_data(as_text=True)

    def test_success_banner_only_right_after_analysis(self):
        self.assertNotIn("Analysis complete", self.page())
        self.assertIn("Analysis complete", self.page("?done=1"))

    def test_kpis_match_the_stored_result(self):
        html = self.page()
        data = self.client.get("/api/analyses/" + self.location.rsplit("/", 1)[1]).get_json()
        for label, value in (
            ("Events analyzed", data["summary"]["total_events"]),
            ("Failed logins", data["summary"]["failed"]),
            ("Suspicious events", data["summary"]["suspicious_events"]),
            ("Findings", len(data["findings"])),
        ):
            self.assertRegex(html, rf"<dt>{label}</dt><dd>{value}</dd>")

    def test_recent_activity_and_severity_chart_present(self):
        html = self.page()
        self.assertIn("Recent suspicious activity", html)
        self.assertIn("Findings by severity", html)
        self.assertIn("severity=critical", html)

    def test_filter_by_severity(self):
        html = self.page("?severity=critical")
        self.assertIn("Showing 1 of 5 findings", html)
        self.assertIn("Possible account compromise", html)
        self.assertNotIn("Password spraying from", html)

    def test_filter_by_rule(self):
        html = self.page("?rule=password_spraying")
        self.assertIn("Showing 1 of 5 findings and 14 of 61", html)

    def test_filter_by_search_term(self):
        html = self.page("?q=198.51.100.77")
        self.assertIn("Showing 1 of 5 findings", html)

    def test_filter_by_hour(self):
        html = self.page("?hour=4")
        self.assertIn("Password spraying from", html)
        self.assertNotIn("Possible account compromise", html)

    def test_filters_combine(self):
        html = self.page("?severity=high&rule=brute_force&q=root")
        self.assertIn("Showing 1 of 5 findings and 38 of 61", html)

    def test_no_match_shows_empty_state(self):
        html = self.page("?q=does-not-exist-anywhere")
        self.assertIn("No findings match these filters", html)
        self.assertIn("No suspicious events match these filters", html)

    def test_invalid_filter_values_are_ignored(self):
        for query in ("?severity=bogus", "?rule=%3Cscript%3E", "?hour=99", "?hour=abc", "?hour=-1"):
            with self.subTest(query=query):
                html = self.page(query)
                self.assertNotIn('role="status">Showing', html)  # no filter became active
                self.assertIn("Password spraying from", html)  # and every finding is still listed

    def test_search_text_is_length_limited(self):
        self.assertNotIn("x" * 65, self.page("?q=" + "x" * 500))

    def test_search_term_is_escaped(self):
        html = self.page("?q=%22%3E%3Cscript%3Ealert(1)%3C/script%3E")
        self.assertNotIn("<script>alert(1)", html)

    def test_table_is_capped(self):
        # 400 distinct failures from one address produce more rows than the page shows.
        data = b"".join(
            f"Oct 20 03:{i // 60:02d}:{i % 60:02d} srv sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2\n".encode()
            for i in range(300)
        )
        location = base_path(self.upload(data, year="2026").headers["Location"])
        html = self.client.get(location).get_data(as_text=True)
        self.assertEqual(html.count("<td class=\"addr\">root</td>"), 200)
        self.assertIn("Showing 200 of 300", html)


@unittest.skipUnless(SAMPLE.exists(), "sample log missing")
class CsvReportTests(WebTestCase):
    def setUp(self):
        super().setUp()
        self.location = base_path(self.client.post("/analyze/sample").headers["Location"])

    def read(self, suffix):
        import csv

        response = self.client.get(self.location + suffix)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.mimetype, "text/csv")
        self.assertIn("attachment", response.headers["Content-Disposition"])
        return list(csv.DictReader(io.StringIO(response.get_data(as_text=True))))

    def test_findings_csv_matches_the_analysis(self):
        rows = self.read("/report.csv")
        self.assertEqual(len(rows), 5)
        self.assertEqual(rows[0]["severity"], "critical")
        self.assertEqual(rows[0]["source_ip"], "192.0.2.88")
        self.assertEqual(rows[0]["mitre_id"], "T1078")
        by_ip = {r["source_ip"] + r["rule"]: r for r in rows}
        self.assertEqual(by_ip["203.0.113.45brute_force"]["events"], "38")
        self.assertTrue(all(r["why_flagged"].startswith("Flagged because") for r in rows))

    def test_events_csv_matches_the_analysis(self):
        rows = self.read("/events.csv")
        self.assertEqual(len(rows), 61)
        self.assertEqual({r["severity"] for r in rows}, {"critical", "high"})
        self.assertEqual(sum(r["type"] == "accepted login" for r in rows), 2)

    def test_csv_downloads_for_unknown_id_are_404(self):
        self.assertEqual(self.client.get("/a/nope/report.csv").status_code, 404)
        self.assertEqual(self.client.get("/a/nope/events.csv").status_code, 404)

    def test_json_report_matches_the_api(self):
        report = json.loads(self.client.get(self.location + "/report.json").data)
        api = self.client.get("/api/analyses/" + self.location.rsplit("/", 1)[1]).get_json()
        self.assertEqual(report["findings"], api["findings"])
        self.assertEqual(report["summary"], api["summary"])

    def test_spreadsheet_formulas_in_usernames_are_neutralised(self):
        import csv

        payload = "=HYPERLINK(\"http://evil.example\",\"x\")"
        body = attack_log(user=payload.replace(" ", ""))
        location = base_path(self.upload(body, year="2026").headers["Location"])
        for suffix in ("/report.csv", "/events.csv"):
            text = self.client.get(location + suffix).get_data(as_text=True)
            self.assertIn("'=HYPERLINK", text)  # the dangerous cell is present, but defused
            for row in csv.reader(io.StringIO(text)):
                for cell in row:
                    self.assertFalse(cell.startswith(("=", "+", "-", "@")), cell)


class HardeningTests(WebTestCase):
    def test_extra_security_headers(self):
        headers = self.client.get("/").headers
        self.assertIn("camera=()", headers["Permissions-Policy"])
        self.assertEqual(headers["Cross-Origin-Opener-Policy"], "same-origin")
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_no_cors_headers_are_sent(self):
        for path in ("/", "/healthz", "/api/analyses/nope"):
            response = self.client.get(path, headers={"Origin": "https://evil.example"})
            self.assertNotIn("Access-Control-Allow-Origin", response.headers)

    def test_unexpected_error_hides_internals(self):
        app = create_app(db_path=self.db)

        @app.get("/boom")
        def boom():
            raise RuntimeError("secret-internal-detail /srv/app/secret.py")

        with self.assertLogs("seclog", level="ERROR"):
            response = app.test_client().get("/boom")
        self.assertEqual(response.status_code, 500)
        self.assertNotIn(b"secret-internal-detail", response.data)
        self.assertNotIn(b"Traceback", response.data)

    def test_unexpected_api_error_is_json(self):
        app = create_app(db_path=self.db)

        @app.get("/api/boom")
        def boom():
            raise RuntimeError("secret-internal-detail")

        with self.assertLogs("seclog", level="ERROR"):
            response = app.test_client().get("/api/boom")
        self.assertEqual(response.status_code, 500)
        self.assertEqual(list(response.get_json()), ["error"])
        self.assertNotIn("secret-internal-detail", response.get_data(as_text=True))

    def test_debug_mode_is_off(self):
        self.assertFalse(self.app.debug)

    def test_log_lines_do_not_contain_uploaded_content(self):
        with self.assertLogs("seclog", level="INFO") as captured:
            self.upload(attack_log(user="SENSITIVE-USER"), name="SENSITIVE-NAME.log", year="2026")
        text = "\n".join(captured.output)
        self.assertIn("analysis id=", text)
        self.assertNotIn("SENSITIVE", text)

    def test_static_files_cannot_escape_the_static_folder(self):
        for path in ("/static/../app.py", "/static/%2e%2e/app.py", "/static/..%2f..%2fwsgi.py"):
            self.assertEqual(self.client.get(path).status_code, 404)


@unittest.skipIf(create_app is None, "Flask is not installed")
class StorageTests(unittest.TestCase):
    def test_prune_removes_expired_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "s.db")
            store = Store(path)
            old_id = store.save("owner", "old.log", {"x": 1})
            fresh_id = store.save("owner", "new.log", {"x": 2})
            expired = time.time() - (RETENTION_DAYS + 1) * 86400
            conn = sqlite3.connect(path)
            try:
                with conn:
                    conn.execute("UPDATE analyses SET created_at = ? WHERE id = ?", (expired, old_id))
            finally:
                conn.close()
            self.assertIsNotNone(store.get(old_id))  # still there until pruned
            self.assertEqual(store.prune(), 1)
            self.assertIsNone(store.get(old_id))
            self.assertIsNotNone(store.get(fresh_id))

    def test_raw_log_is_never_persisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "s.db")
            app = create_app(db_path=db)
            marker = "UNIQUE-MARKER-USER"
            app.test_client().post(
                "/analyze",
                data={"file": (io.BytesIO(attack_log(user="dr.sara") + b"Oct 20 03:05:00 srv cron[1]: " + marker.encode() + b"\n"), "a.log"),
                      "year": "2026"},
                content_type="multipart/form-data",
            )
            self.assertNotIn(marker.encode(), Path(db).read_bytes())


if __name__ == "__main__":
    unittest.main()
