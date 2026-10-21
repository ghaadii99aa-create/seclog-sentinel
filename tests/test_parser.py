import unittest
from datetime import datetime

from seclog.parser import parse_log


class ParserTests(unittest.TestCase):
    def test_failed_password(self):
        line = "Oct 20 02:41:10 srv sshd[1201]: Failed password for root from 203.0.113.45 port 40122 ssh2"
        result = parse_log([line], year=2026)
        self.assertEqual(len(result.events), 1)
        event = result.events[0]
        self.assertFalse(event.success)
        self.assertFalse(event.invalid_user)
        self.assertEqual(event.user, "root")
        self.assertEqual(event.ip, "203.0.113.45")
        self.assertEqual(event.timestamp, datetime(2026, 10, 20, 2, 41, 10))

    def test_invalid_user(self):
        line = "Oct  4 04:05:02 srv sshd[1310]: Failed password for invalid user oracle from 198.51.100.77 port 50211 ssh2"
        event = parse_log([line], year=2026).events[0]
        self.assertTrue(event.invalid_user)
        self.assertEqual(event.user, "oracle")
        self.assertEqual(event.timestamp.day, 4)

    def test_accepted_publickey(self):
        line = "Oct 20 08:14:02 srv sshd[1422]: Accepted publickey for sysadmin from 10.20.9.92 port 53210 ssh2"
        event = parse_log([line], year=2026).events[0]
        self.assertTrue(event.success)
        self.assertEqual(event.method, "publickey")

    def test_ignores_unrelated_lines(self):
        lines = [
            "Oct 20 08:14:02 srv sshd[1]: pam_unix(sshd:session): session opened for user x",
            "Oct 20 08:14:02 srv cron[9]: job started",
            "garbage",
            "",
        ]
        result = parse_log(lines, year=2026)
        self.assertEqual(result.events, [])
        self.assertEqual(result.total_lines, 3)  # blank line is not counted
        self.assertEqual(result.ignored_lines, 3)

    def test_invalid_ip_is_skipped(self):
        line = "Oct 20 08:14:02 srv sshd[1]: Failed password for root from not-an-ip port 22 ssh2"
        self.assertEqual(parse_log([line], year=2026).events, [])

    def test_control_characters_in_username_are_neutralised(self):
        line = "Oct 20 08:14:02 srv sshd[1]: Failed password for invalid user \x1b[31mevil from 198.51.100.1 port 22 ssh2"
        # \x1b[31mevil has no space so it is parsed as the username
        event = parse_log([line], year=2026).events[0]
        self.assertNotIn("\x1b", event.user)

    def test_year_rollover(self):
        lines = [
            "Dec 31 23:59:59 srv sshd[1]: Failed password for root from 198.51.100.1 port 22 ssh2",
            "Jan  1 00:00:05 srv sshd[1]: Failed password for root from 198.51.100.1 port 22 ssh2",
        ]
        events = parse_log(lines, year=2026).events
        self.assertEqual(events[0].timestamp.year, 2026)
        self.assertEqual(events[1].timestamp.year, 2027)


if __name__ == "__main__":
    unittest.main()
