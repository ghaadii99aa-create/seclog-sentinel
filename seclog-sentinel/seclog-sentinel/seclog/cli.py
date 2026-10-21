"""Command-line interface for SecLog Sentinel."""

from __future__ import annotations

import argparse
import sys
from datetime import timedelta
from pathlib import Path
from typing import List, Optional

from . import __version__
from .analyzer import analyze
from .models import SEVERITY_ORDER, Thresholds
from .parser import parse_log
from .report import render_html, render_json

_COLORS = {
    "critical": "\033[1;31m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[34m",
}
_RESET = "\033[0m"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="seclog",
        description="Detect SSH brute-force, password-spraying and account-compromise "
        "patterns in auth logs.",
    )
    parser.add_argument("logfile", help="Path to an sshd auth log, or '-' for stdin")
    parser.add_argument("--year", type=int, help="Year of the log (syslog lines have none). Default: current year")
    parser.add_argument("--html", metavar="FILE", help="Write an HTML report to FILE")
    parser.add_argument("--json", metavar="FILE", help="Write a JSON report to FILE")
    parser.add_argument(
        "--fail-on",
        choices=sorted(SEVERITY_ORDER, key=SEVERITY_ORDER.get),
        help="Exit with code 2 if any finding is at or above this severity (useful in CI)",
    )
    parser.add_argument("--brute-force-threshold", type=int, default=5, metavar="N",
                        help="Failed logins per IP+account to flag (default: 5)")
    parser.add_argument("--brute-force-window", type=int, default=5, metavar="MIN",
                        help="Brute-force window in minutes (default: 5)")
    parser.add_argument("--spray-users", type=int, default=5, metavar="N",
                        help="Distinct accounts per IP to flag as spraying (default: 5)")
    parser.add_argument("--spray-window", type=int, default=10, metavar="MIN",
                        help="Spraying window in minutes (default: 10)")
    parser.add_argument("--privileged", action="append", default=[], metavar="USER",
                        help="Additional privileged account name (repeatable)")
    parser.add_argument("--internal-network", action="append", default=[], metavar="CIDR",
                        help="Additional internal network, e.g. 100.64.0.0/10 (repeatable)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Do not print the terminal summary")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _read_lines(path: str) -> List[str]:
    if path == "-":
        return sys.stdin.read().splitlines()
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read().splitlines()


def _colorize(text: str, severity: str, enabled: bool) -> str:
    return f"{_COLORS[severity]}{text}{_RESET}" if enabled else text


def _print_summary(analysis, source: str) -> None:
    color = sys.stdout.isatty()
    counts = analysis.severity_counts()
    print(f"SecLog Sentinel v{__version__} - {source}")
    period = (
        f"{analysis.start:%Y-%m-%d %H:%M} to {analysis.end:%Y-%m-%d %H:%M}"
        if analysis.start and analysis.end
        else "no events"
    )
    print(
        f"{analysis.total_events} auth events ({analysis.failed} failed, "
        f"{analysis.accepted} accepted) | {period}"
    )
    print(
        f"Findings: {len(analysis.findings)} "
        f"(critical {counts['critical']}, high {counts['high']}, "
        f"medium {counts['medium']}, low {counts['low']})\n"
    )
    for finding in analysis.findings:
        tag = _colorize(f"[{finding.severity.upper()}]", finding.severity, color)
        print(f"{tag} {finding.title}")
        print(f"    {finding.description}")
        print(f"    MITRE {finding.mitre_id} ({finding.mitre_name})")
    if analysis.findings:
        print()


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    thresholds = Thresholds(
        brute_force_failures=args.brute_force_threshold,
        brute_force_window=timedelta(minutes=args.brute_force_window),
        spray_users=args.spray_users,
        spray_window=timedelta(minutes=args.spray_window),
        privileged_users=Thresholds.privileged_users | frozenset(args.privileged),
        internal_networks=Thresholds.internal_networks + tuple(args.internal_network),
    )

    try:
        lines = _read_lines(args.logfile)
    except OSError as exc:
        print(f"seclog: cannot read {args.logfile}: {exc.strerror or exc}", file=sys.stderr)
        return 1

    parsed = parse_log(lines, year=args.year)
    try:
        analysis = analyze(parsed.events, thresholds, ignored_lines=parsed.ignored_lines)
    except ValueError as exc:  # e.g. an invalid --internal-network CIDR
        print(f"seclog: invalid configuration: {exc}", file=sys.stderr)
        return 1

    source_name = "stdin" if args.logfile == "-" else Path(args.logfile).name
    if not args.quiet:
        _print_summary(analysis, source_name)

    try:
        if args.html:
            Path(args.html).write_text(render_html(analysis, source_name), encoding="utf-8")
            if not args.quiet:
                print(f"HTML report written to {args.html}")
        if args.json:
            Path(args.json).write_text(render_json(analysis), encoding="utf-8")
            if not args.quiet:
                print(f"JSON report written to {args.json}")
    except OSError as exc:
        print(f"seclog: cannot write report: {exc.strerror or exc}", file=sys.stderr)
        return 1

    if args.fail_on:
        limit = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f.severity] >= limit for f in analysis.findings):
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
