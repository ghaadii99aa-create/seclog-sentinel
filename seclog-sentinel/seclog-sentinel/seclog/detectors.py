"""Detection rules.

Every detector takes a list of events sorted by timestamp plus a :class:`Thresholds`
object and returns a list of :class:`Finding`. Rules are mapped to MITRE ATT&CK
techniques so findings can be fed into existing SOC workflows.
"""

from __future__ import annotations

import ipaddress
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from datetime import timedelta
from typing import Dict, List, Sequence, Tuple

from .models import SEVERITY_ORDER, Event, Finding, Thresholds

MITRE_PASSWORD_GUESSING = ("T1110.001", "Password Guessing")
MITRE_PASSWORD_SPRAYING = ("T1110.003", "Password Spraying")
MITRE_VALID_ACCOUNTS = ("T1078", "Valid Accounts")


def _fmt(ts) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S")


def _max_window(events: Sequence[Event], window: timedelta) -> Tuple[int, int, int]:
    """Return (count, lo, hi) for the densest sliding window of events."""
    best = (0, 0, 0)
    left = 0
    for right in range(len(events)):
        while events[right].timestamp - events[left].timestamp > window:
            left += 1
        count = right - left + 1
        if count > best[0]:
            best = (count, left, right)
    return best


def _is_internal(ip: str, networks: Sequence[ipaddress._BaseNetwork]) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in network for network in networks)


def detect_brute_force(events: Sequence[Event], t: Thresholds) -> List[Finding]:
    """Many failed logins from one IP against one account in a short window."""
    groups: Dict[Tuple[str, str], List[Event]] = defaultdict(list)
    for event in events:
        if not event.success:
            groups[(event.ip, event.user)].append(event)

    findings: List[Finding] = []
    for (ip, user), group in groups.items():
        count, lo, hi = _max_window(group, t.brute_force_window)
        if count < t.brute_force_failures:
            continue
        privileged = user in t.privileged_users
        severity = "high" if privileged or count >= 20 else "medium"
        first, last = group[lo].timestamp, group[hi].timestamp
        seconds = max(int((last - first).total_seconds()), 1)
        findings.append(
            Finding(
                rule="brute_force",
                title=f"Brute-force attempt against '{user}'",
                severity=severity,
                ip=ip,
                users=[user],
                count=count,
                first_seen=first,
                last_seen=last,
                mitre_id=MITRE_PASSWORD_GUESSING[0],
                mitre_name=MITRE_PASSWORD_GUESSING[1],
                description=(
                    f"{count} failed logins for '{user}' from {ip} within {seconds}s "
                    f"({_fmt(first)} to {_fmt(last)})."
                    + (" The target is a privileged account." if privileged else "")
                ),
                recommendation=(
                    "Block or rate-limit the source IP (fail2ban or firewall), prefer "
                    "key-based authentication, and confirm the account was not accessed."
                ),
            )
        )
    return findings


def detect_password_spraying(events: Sequence[Event], t: Thresholds) -> List[Finding]:
    """One IP trying many different accounts in a short window."""
    failures_by_ip: Dict[str, List[Event]] = defaultdict(list)
    successes_by_ip: Dict[str, List[Event]] = defaultdict(list)
    for event in events:
        (successes_by_ip if event.success else failures_by_ip)[event.ip].append(event)

    findings: List[Finding] = []
    for ip, group in failures_by_ip.items():
        counts: Counter = Counter()
        left = 0
        best = (0, 0, 0)  # distinct users, lo, hi
        for right, event in enumerate(group):
            counts[event.user] += 1
            while event.timestamp - group[left].timestamp > t.spray_window:
                gone = group[left].user
                counts[gone] -= 1
                if counts[gone] == 0:
                    del counts[gone]
                left += 1
            if len(counts) > best[0]:
                best = (len(counts), left, right)

        distinct, lo, hi = best
        if distinct < t.spray_users:
            continue

        window_events = group[lo : hi + 1]
        users = sorted({e.user for e in window_events})
        first, last = window_events[0].timestamp, window_events[-1].timestamp
        followed_by_login = [s for s in successes_by_ip.get(ip, []) if s.timestamp >= first]

        severity = "critical" if followed_by_login else ("high" if distinct >= 10 else "medium")
        extra = ""
        if followed_by_login:
            who = ", ".join(sorted({s.user for s in followed_by_login}))
            extra = f" The same IP later logged in successfully as: {who}."

        findings.append(
            Finding(
                rule="password_spraying",
                title=f"Password spraying from {ip}",
                severity=severity,
                ip=ip,
                users=users,
                count=len(window_events),
                first_seen=first,
                last_seen=last,
                mitre_id=MITRE_PASSWORD_SPRAYING[0],
                mitre_name=MITRE_PASSWORD_SPRAYING[1],
                description=(
                    f"{len(window_events)} failed logins across {distinct} different "
                    f"accounts from {ip} between {_fmt(first)} and {_fmt(last)}." + extra
                ),
                recommendation=(
                    "Block the source, enforce MFA and account lockout, and verify none of "
                    "the targeted accounts logged in successfully from this IP."
                ),
            )
        )
    return findings


def detect_success_after_failures(events: Sequence[Event], t: Thresholds) -> List[Finding]:
    """A successful login right after repeated failures: likely compromised account."""
    failures: Dict[Tuple[str, str], List] = defaultdict(list)
    for event in events:
        if not event.success:
            failures[(event.ip, event.user)].append(event.timestamp)

    findings: List[Finding] = []
    for event in events:
        if not event.success:
            continue
        stamps = failures.get((event.ip, event.user))
        if not stamps:
            continue
        lo = bisect_left(stamps, event.timestamp - t.compromise_window)
        hi = bisect_right(stamps, event.timestamp)
        count = hi - lo
        if count < t.compromise_failures:
            continue
        findings.append(
            Finding(
                rule="success_after_failures",
                title=f"Possible account compromise: '{event.user}'",
                severity="critical",
                ip=event.ip,
                users=[event.user],
                count=count + 1,
                first_seen=stamps[lo],
                last_seen=event.timestamp,
                mitre_id=MITRE_VALID_ACCOUNTS[0],
                mitre_name=MITRE_VALID_ACCOUNTS[1],
                description=(
                    f"{count} failed logins for '{event.user}' from {event.ip} were followed "
                    f"by a successful {event.method} login at {_fmt(event.timestamp)}."
                ),
                recommendation=(
                    "Treat the account as compromised: force a password reset, terminate "
                    "active sessions, review activity after the login, and block the IP."
                ),
            )
        )
    return findings


def detect_privileged_external_login(events: Sequence[Event], t: Thresholds) -> List[Finding]:
    """Privileged account logging in from outside the internal network ranges."""
    networks = [ipaddress.ip_network(n) for n in t.internal_networks]
    groups: Dict[Tuple[str, str], List[Event]] = defaultdict(list)
    for event in events:
        if (
            event.success
            and event.user in t.privileged_users
            and not _is_internal(event.ip, networks)
        ):
            groups[(event.ip, event.user)].append(event)

    findings: List[Finding] = []
    for (ip, user), group in groups.items():
        first, last = group[0].timestamp, group[-1].timestamp
        findings.append(
            Finding(
                rule="privileged_external_login",
                title=f"Privileged login from external IP: '{user}'",
                severity="high",
                ip=ip,
                users=[user],
                count=len(group),
                first_seen=first,
                last_seen=last,
                mitre_id=MITRE_VALID_ACCOUNTS[0],
                mitre_name=MITRE_VALID_ACCOUNTS[1],
                description=(
                    f"Privileged account '{user}' logged in {len(group)} time(s) from "
                    f"{ip}, which is outside the configured internal networks "
                    f"(first at {_fmt(first)})."
                ),
                recommendation=(
                    "Confirm the login was expected. Restrict privileged SSH access to a VPN "
                    "or bastion host and disable direct root/admin logins."
                ),
            )
        )
    return findings


DETECTORS = (
    detect_brute_force,
    detect_password_spraying,
    detect_success_after_failures,
    detect_privileged_external_login,
)


def run_all(events: Sequence[Event], t: Thresholds) -> List[Finding]:
    """Run every detector and return findings sorted by severity, then time."""
    findings: List[Finding] = []
    for detector in DETECTORS:
        findings.extend(detector(events, t))
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.first_seen, f.ip))
    return findings
