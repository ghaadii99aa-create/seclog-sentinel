import unittest
from datetime import datetime, timedelta

from seclog.analyzer import analyze
from seclog.detectors import (
    detect_brute_force,
    detect_password_spraying,
    detect_privileged_external_login,
    detect_success_after_failures,
)
from seclog.models import Event, Thresholds

BASE = datetime(2026, 10, 20, 3, 0, 0)
T = Thresholds()


def fail(seconds, user="root", ip="203.0.113.9"):
    return Event(BASE + timedelta(seconds=seconds), "srv", user, ip, False, "password")


def ok(seconds, user="dr.sara", ip="10.20.1.11", method="password"):
    return Event(BASE + timedelta(seconds=seconds), "srv", user, ip, True, method)


class BruteForceTests(unittest.TestCase):
    def test_flags_burst_against_one_account(self):
        events = [fail(i * 5) for i in range(6)]
        findings = detect_brute_force(events, T)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].count, 6)
        self.assertEqual(findings[0].mitre_id, "T1110.001")
        self.assertEqual(findings[0].severity, "high")  # root is privileged

    def test_below_threshold_is_ignored(self):
        self.assertEqual(detect_brute_force([fail(i * 5) for i in range(4)], T), [])

    def test_slow_attempts_outside_window_are_ignored(self):
        events = [fail(i * 120) for i in range(6)]  # one every 2 min -> max 3 in 5 min
        self.assertEqual(detect_brute_force(events, T), [])

    def test_non_privileged_medium_and_large_burst_high(self):
        medium = detect_brute_force([fail(i, user="dr.sara") for i in range(6)], T)
        large = detect_brute_force([fail(i, user="dr.sara") for i in range(25)], T)
        self.assertEqual(medium[0].severity, "medium")
        self.assertEqual(large[0].severity, "high")


class PasswordSprayingTests(unittest.TestCase):
    def test_flags_many_accounts_from_one_ip(self):
        users = [f"user{i}" for i in range(8)]
        events = [fail(i * 30, user=u) for i, u in enumerate(users)]
        findings = detect_password_spraying(events, T)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].mitre_id, "T1110.003")
        self.assertEqual(len(findings[0].users), 8)
        self.assertEqual(findings[0].severity, "medium")

    def test_few_accounts_not_flagged(self):
        events = [fail(i * 30, user=f"user{i}") for i in range(4)]
        self.assertEqual(detect_password_spraying(events, T), [])

    def test_followed_by_login_is_critical(self):
        events = [fail(i * 30, user=f"user{i}") for i in range(6)]
        events.append(ok(400, user="user2", ip="203.0.113.9"))
        events.sort(key=lambda e: e.timestamp)
        findings = detect_password_spraying(events, T)
        self.assertEqual(findings[0].severity, "critical")
        self.assertIn("user2", findings[0].description)

    def test_different_ips_are_not_combined(self):
        events = [fail(i, user=f"user{i}", ip=f"203.0.113.{i + 1}") for i in range(8)]
        self.assertEqual(detect_password_spraying(events, T), [])


class SuccessAfterFailuresTests(unittest.TestCase):
    def test_flags_login_after_failures(self):
        events = [fail(i * 5, user="dr.fahad", ip="192.0.2.88") for i in range(4)]
        events.append(ok(30, user="dr.fahad", ip="192.0.2.88"))
        findings = detect_success_after_failures(events, T)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "critical")
        self.assertEqual(findings[0].count, 5)

    def test_typo_then_success_is_fine(self):
        events = [fail(0, user="dr.sara", ip="10.20.1.11"), ok(10)]
        self.assertEqual(detect_success_after_failures(events, T), [])

    def test_failures_after_the_login_do_not_count(self):
        events = [ok(0, user="dr.sara", ip="203.0.113.9")]
        events += [fail(10 + i, user="dr.sara", ip="203.0.113.9") for i in range(5)]
        self.assertEqual(detect_success_after_failures(events, T), [])


class PrivilegedExternalLoginTests(unittest.TestCase):
    def test_external_privileged_login_flagged(self):
        findings = detect_privileged_external_login([ok(0, user="sysadmin", ip="198.51.100.23")], T)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "high")

    def test_internal_privileged_login_ok(self):
        self.assertEqual(detect_privileged_external_login([ok(0, user="sysadmin", ip="10.20.9.92")], T), [])

    def test_external_unprivileged_login_ok(self):
        self.assertEqual(detect_privileged_external_login([ok(0, user="dr.sara", ip="198.51.100.23")], T), [])


class AnalyzerTests(unittest.TestCase):
    def test_summary_numbers_and_ordering(self):
        events = [fail(i * 5, user="dr.fahad", ip="192.0.2.88") for i in range(6)]
        events.append(ok(40, user="dr.fahad", ip="192.0.2.88"))
        events.append(ok(50))
        analysis = analyze(events)
        self.assertEqual(analysis.total_events, 8)
        self.assertEqual(analysis.failed, 6)
        self.assertEqual(analysis.accepted, 2)
        self.assertEqual(analysis.unique_ips, 2)
        self.assertEqual(analysis.findings[0].severity, "critical")  # sorted most severe first
        self.assertEqual(analysis.top_sources[0]["ip"], "192.0.2.88")
        self.assertEqual(sum(h["failed"] for h in analysis.hourly), 6)

    def test_empty_input(self):
        analysis = analyze([])
        self.assertEqual(analysis.total_events, 0)
        self.assertEqual(analysis.findings, [])
        self.assertIsNone(analysis.start)


if __name__ == "__main__":
    unittest.main()
