"""Turn parsed events into an :class:`Analysis` ready for reporting."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Iterable, Optional

from .detectors import run_all
from .models import Analysis, Event, Thresholds


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
        findings=run_all(ordered, t),
        ignored_lines=ignored_lines,
    )
