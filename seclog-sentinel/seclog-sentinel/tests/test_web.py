import io
import json
import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

try:
    from seclog.web import create_app
    from seclog.web.storage import RETENTION_DAYS, Store
except ModuleNotFoundError:  # Flask is an optional extra
    create_app = None

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "sample_data" / "auth.log"


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
        location = self.client.post("/analyze/sample").headers["Location"]
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
        location = self.upload(attack_log(), client=owner, year="2026").headers["Location"]

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

    def test_api_errors_are_json(self):
        missing = self.client.post("/api/analyze", data={}, content_type="multipart/form-data")
        self.assertEqual(missing.status_code, 400)
        self.assertIn("error", missing.get_json())
        self.assertEqual(self.client.get("/api/analyses/nope").status_code, 404)
        self.assertIn("error", self.client.get("/api/analyses/nope").get_json())


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
