"""Turn parsed events into an :class:`Analysis` ready for reporting."""

from __future__ import annotations

from collections import Counter, defaultdict
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


def flag_events(
    events: Sequence[Event], findings: Sequence[Finding], limit: int = MAX_FLAGGED_EVENTS
) -> Tuple[List[Dict[str, Any]], int]:
    """Return (flagged events, total). Each event carries the worst finding it supports."""
    by_ip: Dict[str, List[Finding]] = defaultdict(list)
    for finding in findings:
        by_ip[finding.ip].append(finding)

    flagged: List[Dict[str, Any]] = []
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
    return flagged[:limit], len(flagged)


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
    flagged, flagged_total = flag_events(ordered, findings)

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
    )
