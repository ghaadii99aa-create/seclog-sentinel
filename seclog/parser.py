"""Parse OpenSSH authentication events from syslog-style log lines.

Supported line shapes (as written by sshd to /var/log/auth.log or /var/log/secure):

    Oct 20 02:41:10 host sshd[1201]: Failed password for root from 203.0.113.45 port 40122 ssh2
    Oct 20 04:05:02 host sshd[1310]: Failed password for invalid user oracle from 198.51.100.77 port 50211 ssh2
    Oct 20 08:14:02 host sshd[1422]: Accepted publickey for sysadmin from 10.20.1.5 port 53210 ssh2

Syslog timestamps carry no year, so the caller supplies one. A December -> January
rollover inside a single file is handled automatically.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, List, Optional

from .models import Event

_LINE_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+(?P<msg>.*)$"
)
_FAILED_RE = re.compile(
    r"^Failed (?P<method>[\w-]+) for (?P<invalid>invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)
_ACCEPTED_RE = re.compile(
    r"^Accepted (?P<method>[\w-]+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)

_MONTHS = {
    name: index
    for index, name in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
        start=1,
    )
}
_MAX_USER_LEN = 64


@dataclass
class ParseResult:
    events: List[Event] = field(default_factory=list)
    total_lines: int = 0
    ignored_lines: int = 0


def _clean(value: str) -> str:
    """Neutralise control characters and cap length.

    Usernames in auth logs are attacker-controlled, so they must never be able to
    inject terminal escape sequences or oversized strings into our output.
    """
    cleaned = "".join(ch if ch.isprintable() else "?" for ch in value)
    return cleaned[:_MAX_USER_LEN]


def _valid_ip(value: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def parse_log(lines: Iterable[str], year: Optional[int] = None) -> ParseResult:
    """Parse an iterable of log lines into :class:`Event` objects."""
    current_year = year if year is not None else datetime.now().year
    result = ParseResult()
    previous_month: Optional[int] = None

    for raw in lines:
        line = raw.rstrip("\r\n")
        if not line.strip():
            continue
        result.total_lines += 1

        match = _LINE_RE.match(line)
        if not match:
            result.ignored_lines += 1
            continue

        message = match.group("msg")
        failed = _FAILED_RE.match(message)
        accepted = None if failed else _ACCEPTED_RE.match(message)
        if not failed and not accepted:
            result.ignored_lines += 1
            continue

        month = _MONTHS.get(match.group("month"))
        if month is None:
            result.ignored_lines += 1
            continue

        if previous_month == 12 and month == 1:
            current_year += 1
        previous_month = month

        try:
            timestamp = datetime.strptime(
                f"{current_year} {month} {match.group('day')} {match.group('time')}",
                "%Y %m %d %H:%M:%S",
            )
        except ValueError:
            result.ignored_lines += 1
            continue

        detail = failed or accepted
        ip = _valid_ip(detail.group("ip"))
        if ip is None:
            result.ignored_lines += 1
            continue

        result.events.append(
            Event(
                timestamp=timestamp,
                host=_clean(match.group("host")),
                user=_clean(detail.group("user")),
                ip=ip,
                success=accepted is not None,
                method=_clean(detail.group("method")),
                invalid_user=bool(failed and failed.group("invalid")),
            )
        )

    return result
