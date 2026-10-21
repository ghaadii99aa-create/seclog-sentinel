"""The sample logs come with known expected results, so the detectors can be checked end to end."""

import json
import unittest
from pathlib import Path

from seclog.analyzer import analyze
from seclog.parser import parse_log

DATA = Path(__file__).resolve().parent.parent / "sample_data"
EXPECTED = json.loads((DATA / "expected_results.json").read_text())


def run(name, year=2026):
    parsed = parse_log((DATA / name).read_text().splitlines(), year=year)
    return analyze(parsed.events, ignored_lines=parsed.ignored_lines)


def key(finding):
    return (finding.rule, finding.severity, finding.ip)


class SampleExpectationTests(unittest.TestCase):
    def assert_matches(self, analysis, expected):
        self.assertEqual(analysis.total_events, expected["total_events"])
        self.assertEqual(analysis.failed, expected["failed"])
        self.assertEqual(analysis.flagged_total, expected["suspicious_events"])
        want = [(f["rule"], f["severity"], f["ip"]) for f in expected["findings"]]
        self.assertEqual(sorted(key(f) for f in analysis.findings), sorted(want))
        for exp in expected["findings"]:
            found = next(f for f in analysis.findings if (f.rule, f.ip) == (exp["rule"], exp["ip"]))
            self.assertEqual(found.count, exp["count"], exp)
            if "users" in exp:
                self.assertEqual(found.users, exp["users"])
            if "users_count" in exp:
                self.assertEqual(len(found.users), exp["users_count"])

    def test_auth_log(self):
        self.assert_matches(run("auth.log"), EXPECTED["auth.log"])

    def test_iso_timestamps_give_the_same_result(self):
        classic = run("auth.log")
        iso = run("auth_iso.log", year=1999)  # the year argument must be ignored for ISO lines
        self.assertEqual([key(f) for f in iso.findings], [key(f) for f in classic.findings])
        self.assertEqual(iso.flagged_total, classic.flagged_total)
        self.assertEqual(iso.start.year, 2026)

    def test_clean_log_has_no_findings(self):
        self.assert_matches(run("clean.log"), EXPECTED["clean.log"])

    def test_every_finding_explains_itself(self):
        for finding in run("auth.log").findings:
            self.assertIn("Flagged because", finding.reason)
            self.assertIn(finding.assessment, ("Suspicious indicator", "Likely compromise, investigate now"))

    def test_nothing_is_called_confirmed(self):
        for finding in run("auth.log").findings:
            text = " ".join([finding.title, finding.assessment, finding.reason]).lower()
            self.assertNotIn("confirmed", text)

    def test_flagged_events_support_findings(self):
        analysis = run("auth.log")
        severities = {e["severity"] for e in analysis.flagged_events}
        # Events that support several findings carry the worst one, so no event is left at "medium".
        self.assertEqual(severities, {"critical", "high"})
        self.assertTrue(all(e["rules"] for e in analysis.flagged_events))
        # The login that followed the failures is flagged as part of the takeover finding.
        takeover = [e for e in analysis.flagged_events if e["type"] == "accepted login" and e["user"] == "dr.fahad"]
        self.assertEqual(len(takeover), 1)
        self.assertEqual(takeover[0]["severity"], "critical")


if __name__ == "__main__":
    unittest.main()
