"""Data models shared across the package."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

SEVERITY_ORDER: Dict[str, int] = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Event:
    """A single SSH authentication event parsed from a log line."""

    timestamp: datetime
    host: str
    user: str
    ip: str
    success: bool
    method: str
    invalid_user: bool = False


@dataclass
class Finding:
    """A detection result produced by one of the detection rules."""

    rule: str
    title: str
    severity: str
    ip: str
    users: List[str]
    count: int
    first_seen: datetime
    last_seen: datetime
    mitre_id: str
    mitre_name: str
    description: str
    recommendation: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        return cls(
            rule=data["rule"],
            title=data["title"],
            severity=data["severity"],
            ip=data["ip"],
            users=list(data["users"]),
            count=int(data["count"]),
            first_seen=datetime.fromisoformat(data["first_seen"]),
            last_seen=datetime.fromisoformat(data["last_seen"]),
            mitre_id=data["mitre"]["id"],
            mitre_name=data["mitre"]["name"],
            description=data["description"],
            recommendation=data["recommendation"],
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule": self.rule,
            "title": self.title,
            "severity": self.severity,
            "ip": self.ip,
            "users": list(self.users),
            "count": self.count,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "mitre": {"id": self.mitre_id, "name": self.mitre_name},
            "description": self.description,
            "recommendation": self.recommendation,
        }


@dataclass(frozen=True)
class Thresholds:
    """Tunable detection thresholds."""

    brute_force_failures: int = 5
    brute_force_window: timedelta = timedelta(minutes=5)
    spray_users: int = 5
    spray_window: timedelta = timedelta(minutes=10)
    compromise_failures: int = 3
    compromise_window: timedelta = timedelta(minutes=10)
    privileged_users: FrozenSet[str] = frozenset(
        {"root", "admin", "administrator", "sysadmin"}
    )
    internal_networks: Tuple[str, ...] = (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "::1/128",
        "fe80::/10",
    )


@dataclass
class Analysis:
    """Aggregated analysis result used by the report generators."""

    total_events: int
    failed: int
    accepted: int
    unique_ips: int
    unique_users: int
    start: Optional[datetime]
    end: Optional[datetime]
    top_sources: List[Dict[str, Any]] = field(default_factory=list)
    hourly: List[Dict[str, int]] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    ignored_lines: int = 0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Analysis":
        """Rebuild an Analysis from :meth:`to_dict` output (extra keys are ignored)."""
        summary = data["summary"]
        return cls(
            total_events=summary["total_events"],
            failed=summary["failed"],
            accepted=summary["accepted"],
            unique_ips=summary["unique_ips"],
            unique_users=summary["unique_users"],
            start=datetime.fromisoformat(summary["start"]) if summary["start"] else None,
            end=datetime.fromisoformat(summary["end"]) if summary["end"] else None,
            top_sources=list(data.get("top_sources", [])),
            hourly=list(data.get("hourly", [])),
            findings=[Finding.from_dict(f) for f in data.get("findings", [])],
            ignored_lines=summary.get("ignored_lines", 0),
        )

    def severity_counts(self) -> Dict[str, int]:
        counts = {name: 0 for name in ("critical", "high", "medium", "low")}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": {
                "total_events": self.total_events,
                "failed": self.failed,
                "accepted": self.accepted,
                "unique_ips": self.unique_ips,
                "unique_users": self.unique_users,
                "start": self.start.isoformat() if self.start else None,
                "end": self.end.isoformat() if self.end else None,
                "ignored_lines": self.ignored_lines,
                "findings_by_severity": self.severity_counts(),
            },
            "top_sources": self.top_sources,
            "hourly": self.hourly,
            "findings": [f.to_dict() for f in self.findings],
        }
