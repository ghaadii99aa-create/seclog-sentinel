import json
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from seclog.analyzer import analyze
from seclog.cli import main
from seclog.models import Event
from seclog.report import render_html, render_json

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "sample_data" / "auth.log"


class ReportTests(unittest.TestCase):
    def test_usernames_are_html_escaped(self):
        base = datetime(2026, 10, 20, 3, 0, 0)
        payload = "<script>alert(1)</script>"
        events = [
            Event(base + timedelta(seconds=i), "srv", payload, "203.0.113.9", False, "password", True)
            for i in range(6)
        ]
        html = render_html(analyze(events), source_name="<b>x</b>")
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertNotIn("<b>x</b>", html)

    def test_clean_log_message(self):
        html = render_html(analyze([]))
        self.assertIn("No suspicious activity detected", html)

    def test_json_is_valid(self):
        data = json.loads(render_json(analyze([])))
        self.assertEqual(data["summary"]["total_events"], 0)


@unittest.skipUnless(SAMPLE.exists(), "sample_data/auth.log not generated")
class CliTests(unittest.TestCase):
    def test_sample_log_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            html_path = Path(tmp) / "report.html"
            json_path = Path(tmp) / "report.json"
            code = main([str(SAMPLE), "--year", "2026", "--html", str(html_path),
                         "--json", str(json_path), "-q"])
            self.assertEqual(code, 0)
            self.assertTrue(html_path.read_text(encoding="utf-8").startswith("<!doctype html>"))
            data = json.loads(json_path.read_text(encoding="utf-8"))
            rules = {f["rule"] for f in data["findings"]}
            self.assertEqual(
                rules,
                {"brute_force", "password_spraying", "success_after_failures", "privileged_external_login"},
            )
            # The noisy-but-harmless activity must not produce extra findings.
            sources = {f["ip"] for f in data["findings"]}
            self.assertNotIn("192.0.2.150", sources)
            self.assertNotIn("10.20.1.13", sources)

    def test_fail_on_exit_code(self):
        self.assertEqual(main([str(SAMPLE), "--year", "2026", "-q", "--fail-on", "critical"]), 2)
        self.assertEqual(main([str(SAMPLE), "--year", "2026", "-q", "--fail-on", "high",
                               "--brute-force-threshold", "999", "--spray-users", "999"]), 2)

    def test_missing_file_returns_1(self):
        self.assertEqual(main(["does-not-exist.log", "-q"]), 1)

    def test_bad_internal_network_returns_1(self):
        self.assertEqual(main([str(SAMPLE), "-q", "--internal-network", "not-a-cidr"]), 1)


if __name__ == "__main__":
    unittest.main()
