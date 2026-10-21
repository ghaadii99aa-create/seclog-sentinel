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


class ParserEdgeCaseTests(unittest.TestCase):
    ACCEPTED = "Oct 20 08:14:02 srv sshd[1]: Accepted publickey for ops from 10.0.0.5 port 22 ssh2"

    def test_empty_input(self):
        result = parse_log([], year=2026)
        self.assertEqual((len(result.events), result.total_lines, result.ignored_lines), (0, 0, 0))

    def test_blank_lines_are_skipped_not_counted(self):
        result = parse_log(["", "   ", self.ACCEPTED], year=2026)
        self.assertEqual((len(result.events), result.total_lines, result.ignored_lines), (1, 1, 0))

    def test_garbage_and_other_daemons_are_ignored(self):
        lines = [
            "this is not a log line",
            "Oct 20 08:14:02 srv cron[1]: (root) CMD (run-parts /etc/cron.hourly)",
            "Oct 20 08:14:02 srv sshd[1]: Connection closed by 203.0.113.9 port 1 [preauth]",
            self.ACCEPTED,
        ]
        result = parse_log(lines, year=2026)
        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.ignored_lines, 3)

    def test_missing_fields_do_not_raise(self):
        lines = [
            "Oct 20 08:14:02 srv sshd[1]: Failed password for from 203.0.113.9 port 22 ssh2",
            "Oct 20 08:14:02 srv sshd[1]: Failed password for root from 203.0.113.9",
            "Oct 20 08:14:02 srv sshd[1]: Failed password for root from port 22",
            "Oct 20 08:14:02 srv sshd[1]: Accepted",
        ]
        result = parse_log(lines, year=2026)
        self.assertEqual(result.events, [])
        self.assertEqual(result.ignored_lines, 4)

    def test_invalid_address_and_impossible_dates_are_ignored(self):
        lines = [
            "Oct 20 08:14:02 srv sshd[1]: Failed password for root from 999.1.1.1 port 22 ssh2",
            "Feb 30 08:14:02 srv sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2",
            "Oct 20 25:61:02 srv sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2",
        ]
        result = parse_log(lines, year=2026)
        self.assertEqual((len(result.events), result.ignored_lines), (0, 3))

    def test_over_long_line_is_ignored(self):
        long_user = "a" * 5000
        line = f"Oct 20 08:14:02 srv sshd[1]: Failed password for {long_user} from 203.0.113.9 port 22 ssh2"
        result = parse_log([line], year=2026)
        self.assertEqual((len(result.events), result.ignored_lines), (0, 1))

    def test_long_username_is_truncated(self):
        user = "b" * 200
        line = f"Oct 20 08:14:02 srv sshd[1]: Failed password for {user} from 203.0.113.9 port 22 ssh2"
        self.assertEqual(len(parse_log([line], year=2026).events[0].user), 64)

    def test_iso_timestamp_with_offset_and_fraction(self):
        line = "2026-10-20T08:14:02.123456+03:00 srv sshd[1]: Accepted publickey for ops from 10.0.0.5 port 22 ssh2"
        event = parse_log([line], year=1999).events[0]
        self.assertEqual(event.timestamp, datetime(2026, 10, 20, 8, 14, 2))

    def test_iso_timestamp_zulu_and_no_fraction(self):
        line = "2026-01-05T23:59:59Z srv sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2"
        self.assertEqual(parse_log([line]).events[0].timestamp, datetime(2026, 1, 5, 23, 59, 59))

    def test_iso_impossible_date_is_ignored(self):
        line = "2026-02-30T08:14:02Z srv sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2"
        self.assertEqual(parse_log([line]).ignored_lines, 1)

    def test_ipv6_source(self):
        line = "Oct 20 08:14:02 srv sshd[1]: Failed password for root from 2001:db8::1 port 22 ssh2"
        self.assertEqual(parse_log([line], year=2026).events[0].ip, "2001:db8::1")

    def test_control_characters_in_username_are_neutralised(self):
        line = "Oct 20 08:14:02 srv sshd[1]: Failed password for ro\x1b[31mot from 203.0.113.9 port 22 ssh2"
        user = parse_log([line], year=2026).events
        # The escape byte may split the token, but it must never survive into an event.
        for event in user:
            self.assertNotIn("\x1b", event.user)


class ParserRobustnessTests(unittest.TestCase):
    """Seeded random mutations of real lines. The parser must never raise and never emit bad events."""

    def test_mutated_lines_never_crash_and_events_stay_valid(self):
        import ipaddress
        import random
        from pathlib import Path

        sample = (Path(__file__).resolve().parent.parent / "sample_data" / "auth.log").read_text().splitlines()
        rng = random.Random(1234)
        junk = list("\x00\x1b\r\t'\"<>&%{}$;`\\/ é‮\U0001f600") + ["999.999.999.999", "::", "port", "for", "from"]
        accepted = 0
        for _ in range(4000):
            chars = list(rng.choice(sample))
            for _ in range(rng.randint(1, 6)):
                pos = rng.randrange(len(chars) + 1)
                action = rng.choice(("insert", "delete", "replace"))
                if action == "insert":
                    chars.insert(pos, rng.choice(junk))
                elif action == "delete" and chars:
                    del chars[min(pos, len(chars) - 1)]
                elif chars:
                    chars[min(pos, len(chars) - 1)] = rng.choice(junk)
            result = parse_log(["".join(chars)], year=2026)
            for event in result.events:
                accepted += 1
                ipaddress.ip_address(event.ip)  # raises if the parser let a bad address through
                self.assertLessEqual(len(event.user), 64)
                self.assertTrue(event.user.isprintable())
                self.assertTrue(event.host.isprintable())
        self.assertGreater(accepted, 100)  # the mutations were not so heavy that nothing parsed
