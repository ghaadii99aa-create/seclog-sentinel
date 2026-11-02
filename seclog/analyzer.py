"""Turn parsed events into an :class:`Analysis` ready for reporting."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .detectors import run_all
from .models import SEVERITY_ORDER, Analysis, Event, Finding, Thresholds

# Only events that support a finding are kept, and no more than this many.
MAX_FLAGGED_EVENTS = 1000

# Which kind of event each rule is built from.
_RULE_EVENT_KIND = {
    "brute_force": "failed",
    "password_spraying": "failed",
    "success_after_failures": "both",
    "privileged_external_login": "accepted",
}


_BUCKET_HOURS = (1, 3, 6, 12, 24, 24 * 7)
MAX_BUCKETS = 48


def flag_events(
    events: Sequence[Event], findings: Sequence[Finding], limit: int = MAX_FLAGGED_EVENTS
) -> Tuple[List[Dict[str, Any]], int, List[datetime]]:
    """Return (flagged events kept, total flagged, timestamps of all flagged events).

    Each flagged event carries the worst finding it supports.
    """
    by_ip: Dict[str, List[Finding]] = defaultdict(list)
    for finding in findings:
        by_ip[finding.ip].append(finding)

    flagged: List[Dict[str, Any]] = []
    flagged_times: List[datetime] = []
    for event in events:
        matches = []
        for finding in by_ip.get(event.ip, ()):
            kind = _RULE_EVENT_KIND.get(finding.rule, "both")
            if kind == "failed" and event.success:
                continue
            if kind == "accepted" and not event.success:
                continue
            if event.user in finding.users and finding.first_seen <= event.timestamp <= finding.last_seen:
                matches.append(finding)
        if not matches:
            continue
        worst = max(matches, key=lambda f: SEVERITY_ORDER[f.severity])
        flagged_times.append(event.timestamp)
        flagged.append(
            {
                "time": event.timestamp.isoformat(),
                "type": "accepted login" if event.success else "failed login",
                "user": event.user,
                "ip": event.ip,
                "method": event.method,
                "severity": worst.severity,
                "rules": sorted({m.rule for m in matches}),
                "reason": worst.title,
                "recommendation": worst.recommendation,
            }
        )
    return flagged[:limit], len(flagged), flagged_times


def events_for_finding(finding: Dict[str, Any], events: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The stored suspicious events that support one finding (given as its dict form)."""
    kind = _RULE_EVENT_KIND.get(finding["rule"], "both")
    first, last = finding["first_seen"], finding["last_seen"]
    users = set(finding["users"])
    matched = []
    for event in events:
        if event["ip"] != finding["ip"] or event["user"] not in users:
            continue
        if kind == "failed" and event["type"] != "failed login":
            continue
        if kind == "accepted" and event["type"] != "accepted login":
            continue
        if first <= event["time"] <= last:
            matched.append(event)
    return matched


def classify_events(events: Sequence[Event]) -> List[Dict[str, Any]]:
    """Count every event by what it was, so the distribution reflects the whole log."""
    counts: Counter = Counter()
    for e in events:
        if e.success:
            counts[("accepted", f"Accepted login ({e.method})")] += 1
        elif e.invalid_user:
            counts[("failed", "Failed login (unknown account)")] += 1
        else:
            counts[("failed", "Failed login (existing account)")] += 1
    return [
        {"kind": kind, "label": label, "count": count}
        for (kind, label), count in sorted(counts.items(), key=lambda item: (-item[1], item[0][1]))
    ]


def build_timeline(events: Sequence[Event], flagged_times: Sequence[datetime]) -> List[Dict[str, Any]]:
    """Events per time bucket, with the suspicious ones counted separately.

    The bucket size grows with the length of the log so the chart always has at most 48 bars.
    """
    if not events:
        return []
    start, end = events[0].timestamp, events[-1].timestamp
    span_hours = max((end - start).total_seconds() / 3600, 0)
    hours = next((h for h in _BUCKET_HOURS if span_hours / h <= MAX_BUCKETS), _BUCKET_HOURS[-1])
    midnight = start.replace(hour=0, minute=0, second=0, microsecond=0)
    if hours >= 24:
        origin, step = midnight, timedelta(hours=hours)
    else:
        offset = int((start - midnight).total_seconds() // (hours * 3600))
        origin, step = midnight + timedelta(hours=offset * hours), timedelta(hours=hours)

    def index(moment: datetime) -> int:
        return int((moment - origin) // step)

    count = index(end) + 1
    buckets = [
        {"start": (origin + step * i).isoformat(), "hours": hours, "failed": 0, "accepted": 0, "suspicious": 0}
        for i in range(count)
    ]
    for e in events:
        buckets[index(e.timestamp)]["accepted" if e.success else "failed"] += 1
    for moment in flagged_times:
        buckets[index(moment)]["suspicious"] += 1
    return buckets


def analyze(
    events: Iterable[Event],
    thresholds: Optional[Thresholds] = None,
    ignored_lines: int = 0,
) -> Analysis:
    t = thresholds or Thresholds()
    ordered = sorted(events, key=lambda e: e.timestamp)

    failed_events = [e for e in ordered if not e.success]
    failures_per_ip = Counter(e.ip for e in failed_events)
    users_per_ip = defaultdict(set)
    for e in failed_events:
        users_per_ip[e.ip].add(e.user)

    top_sources = [
        {"ip": ip, "failures": count, "distinct_users": len(users_per_ip[ip])}
        for ip, count in failures_per_ip.most_common(10)
    ]

    hourly = [{"hour": h, "failed": 0, "accepted": 0} for h in range(24)]
    for e in ordered:
        hourly[e.timestamp.hour]["accepted" if e.success else "failed"] += 1

    findings = run_all(ordered, t)
    flagged, flagged_total, flagged_times = flag_events(ordered, findings)
    suspicious_hourly = [0] * 24
    for moment in flagged_times:
        suspicious_hourly[moment.hour] += 1

    return Analysis(
        total_events=len(ordered),
        failed=len(failed_events),
        accepted=len(ordered) - len(failed_events),
        unique_ips=len({e.ip for e in ordered}),
        unique_users=len({e.user for e in ordered}),
        start=ordered[0].timestamp if ordered else None,
        end=ordered[-1].timestamp if ordered else None,
        top_sources=top_sources,
        hourly=hourly,
        findings=findings,
        ignored_lines=ignored_lines,
        flagged_events=flagged,
        flagged_total=flagged_total,
        event_types=classify_events(ordered),
        timeline=build_timeline(ordered, flagged_times),
        suspicious_hourly=suspicious_hourly,
    )
