import json
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from seclog.analyzer import analyze
from seclog.cli import main
from seclog.models import Event
from seclog.report import csv_safe, render_events_csv, render_findings_csv, render_html, render_json

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


class CsvAndCliTests(unittest.TestCase):
    def analysis(self):
        from seclog.parser import parse_log

        parsed = parse_log(SAMPLE.read_text().splitlines(), year=2026)
        return analyze(parsed.events)

    def test_csv_safe(self):
        for dangerous in ("=1+1", "+1", "-1", "@SUM(A1)", "\tx", "\rx"):
            self.assertEqual(csv_safe(dangerous), "'" + dangerous)
        for harmless in ("root", "203.0.113.4", "", "a=b"):
            self.assertEqual(csv_safe(harmless), harmless)
        self.assertEqual(csv_safe(None), "")
        self.assertEqual(csv_safe(7), "7")

    def test_findings_csv_has_header_and_one_row_per_finding(self):
        lines = render_findings_csv(self.analysis()).strip().split("\r\n")
        self.assertTrue(lines[0].startswith("severity,assessment,rule,title,source_ip"))
        self.assertEqual(len(lines) - 1, 5)

    def test_events_csv_row_count_matches_the_summary(self):
        analysis = self.analysis()
        lines = render_events_csv(analysis).strip().split("\r\n")
        self.assertEqual(len(lines) - 1, analysis.flagged_total)

    def test_empty_analysis_gives_header_only(self):
        empty = analyze([])
        self.assertEqual(len(render_findings_csv(empty).strip().split("\r\n")), 1)
        self.assertEqual(len(render_events_csv(empty).strip().split("\r\n")), 1)

    def test_json_round_trip_keeps_events_and_reasons(self):
        from seclog.models import Analysis

        original = self.analysis()
        again = Analysis.from_dict(json.loads(render_json(original)))
        self.assertEqual(again.flagged_total, original.flagged_total)
        self.assertEqual(again.flagged_events, original.flagged_events)
        self.assertEqual([f.reason for f in again.findings], [f.reason for f in original.findings])

    def test_old_saved_results_without_new_fields_still_load(self):
        from seclog.models import Analysis

        data = json.loads(render_json(self.analysis()))
        del data["events"]
        del data["summary"]["suspicious_events"]
        for finding in data["findings"]:
            del finding["reason"], finding["assessment"]
        loaded = Analysis.from_dict(data)
        self.assertEqual(loaded.flagged_events, [])
        self.assertEqual(loaded.findings[0].assessment, "Suspicious indicator")

    def test_html_report_states_it_shows_indicators_only(self):
        html = render_html(self.analysis())
        self.assertIn("cannot confirm", html)
        self.assertIn("Flagged because", html)

    def test_cli_writes_csv_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            findings, events = Path(tmp) / "f.csv", Path(tmp) / "e.csv"
            code = main([str(SAMPLE), "--year", "2026", "-q", "--csv", str(findings), "--events-csv", str(events)])
            self.assertEqual(code, 0)
            self.assertEqual(len(findings.read_text().strip().splitlines()), 6)
            self.assertEqual(len(events.read_text().strip().splitlines()), 62)

    def test_cli_compromise_threshold_is_configurable(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "r.json"
            main([str(SAMPLE), "--year", "2026", "-q", "--compromise-failures", "50", "--json", str(out)])
            rules = {f["rule"] for f in json.loads(out.read_text())["findings"]}
            self.assertNotIn("success_after_failures", rules)


class PdfAndAnalyticsTests(unittest.TestCase):
    def setUp(self):
        from seclog.parser import parse_log

        self.analysis = analyze(parse_log(SAMPLE.read_text(encoding="utf-8").splitlines(), year=2026).events)

    def test_cli_writes_pdf(self):
        try:
            import reportlab  # noqa: F401
        except ImportError:
            self.skipTest("reportlab not installed")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "r.pdf"
            self.assertEqual(main([str(SAMPLE), "--year", "2026", "--pdf", str(path), "-q"]), 0)
            self.assertTrue(path.read_bytes().startswith(b"%PDF-"))

    def test_analytics_add_up_to_the_summary(self):
        a = self.analysis.to_dict()
        s = a["summary"]
        self.assertEqual(sum(t["count"] for t in a["event_types"]), s["total_events"])
        self.assertEqual(sum(b["failed"] + b["accepted"] for b in a["timeline"]), s["total_events"])
        self.assertEqual(sum(b["suspicious"] for b in a["timeline"]), s["suspicious_events"])
        self.assertEqual(sum(a["suspicious_hourly"]), s["suspicious_events"])
        self.assertEqual(len(a["suspicious_hourly"]), 24)

    def test_every_finding_explains_impact(self):
        for finding in self.analysis.findings:
            self.assertTrue(finding.impact and finding.reason and finding.recommendation)

    def test_evidence_matches_finding_counts(self):
        from seclog.analyzer import events_for_finding

        a = self.analysis.to_dict()
        for finding in a["findings"]:
            self.assertEqual(len(events_for_finding(finding, a["events"])), finding["count"])
