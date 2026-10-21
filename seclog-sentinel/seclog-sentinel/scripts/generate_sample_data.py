#!/usr/bin/env python3
"""Generate a synthetic sshd auth log with realistic noise and four injected attacks.

All data is fabricated. External attacker addresses come from the RFC 5737
documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), which are
reserved for examples and never route on the real internet.

Usage:
    python scripts/generate_sample_data.py --out sample_data/auth.log
"""

from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta
from pathlib import Path

HOST = "srv-app-01"

STAFF = {
    "dr.sara": "10.20.1.11",
    "dr.fahad": "10.20.1.12",
    "dr.nouf": "10.20.1.13",
    "dr.khalid": "10.20.1.14",
    "nurse.omar": "10.20.2.21",
    "nurse.huda": "10.20.2.22",
    "lab.tech1": "10.20.3.31",
    "pharm.lina": "10.20.3.32",
    "radiology1": "10.20.4.41",
    "billing.mona": "10.20.5.51",
    "it.support": "10.20.9.91",
    "sysadmin": "10.20.9.92",
}


class LogBuilder:
    def __init__(self, rng: random.Random) -> None:
        self.rng = rng
        self.rows: list[tuple[datetime, str]] = []

    def _add(self, ts: datetime, message: str) -> None:
        pid = self.rng.randint(1000, 32000)
        stamp = f"{ts.strftime('%b')} {ts.day:2d} {ts.strftime('%H:%M:%S')}"
        self.rows.append((ts, f"{stamp} {HOST} sshd[{pid}]: {message}"))

    def failed(self, ts: datetime, user: str, ip: str, invalid: bool = False) -> None:
        port = self.rng.randint(30000, 65000)
        who = f"invalid user {user}" if invalid else user
        self._add(ts, f"Failed password for {who} from {ip} port {port} ssh2")

    def accepted(self, ts: datetime, user: str, ip: str, method: str = "password") -> None:
        port = self.rng.randint(30000, 65000)
        self._add(ts, f"Accepted {method} for {user} from {ip} port {port} ssh2")

    def noise(self, ts: datetime, message: str) -> None:
        """Non-authentication sshd chatter that the parser should ignore."""
        self._add(ts, message)


def build(day: datetime, seed: int) -> list[str]:
    rng = random.Random(seed)
    log = LogBuilder(rng)

    # --- Normal staff activity: day-shift sessions with the odd typo ---------------
    for user, ip in STAFF.items():
        for _ in range(rng.randint(2, 5)):
            ts = day + timedelta(hours=7, seconds=rng.randint(0, 10 * 3600 + 1800))
            if rng.random() < 0.15:
                for i in range(rng.randint(1, 2)):
                    log.failed(ts - timedelta(seconds=12 * (i + 1)), user, ip)
            method = "publickey" if user in ("sysadmin", "it.support") else "password"
            log.accepted(ts, user, ip, method)
            log.noise(ts + timedelta(seconds=1), f"pam_unix(sshd:session): session opened for user {user}")

    # --- Harmless background noise that must NOT trigger anything -------------------
    for i in range(2):  # a lone scanner poking twice
        log.failed(day + timedelta(hours=11, minutes=30, seconds=20 * i), "root", "192.0.2.150")
    for i in range(3):  # staff member fat-fingering a password
        log.failed(day + timedelta(hours=9, minutes=5, seconds=8 * i), "dr.nouf", "10.20.1.13")

    # --- Attack 1: brute force against root (203.0.113.45) --------------------------
    start = day + timedelta(hours=2, minutes=41, seconds=10)
    for i in range(38):
        log.failed(start + timedelta(seconds=i * 4 + rng.randint(0, 2)), "root", "203.0.113.45")

    # --- Attack 2: password spraying (198.51.100.77) --------------------------------
    sprayed = ["admin", "test", "oracle", "ubuntu", "postgres", "guest", "support",
               "info", "backup", "dev", "dr.sara", "nurse.omar", "pharm.lina", "ftpuser"]
    valid = {"dr.sara", "nurse.omar", "pharm.lina"}
    start = day + timedelta(hours=4, minutes=5)
    for i, user in enumerate(sprayed):
        log.failed(start + timedelta(seconds=i * 38), user, "198.51.100.77", invalid=user not in valid)

    # --- Attack 3: account compromise (192.0.2.88 -> dr.fahad) -----------------------
    start = day + timedelta(hours=22, minutes=14)
    for i in range(7):
        log.failed(start + timedelta(seconds=i * 6), "dr.fahad", "192.0.2.88")
    log.accepted(start + timedelta(seconds=52), "dr.fahad", "192.0.2.88")

    # --- Attack 4: privileged login from an external address ------------------------
    log.accepted(day + timedelta(hours=3, minutes=12, seconds=44), "sysadmin", "198.51.100.23", "publickey")

    log.rows.sort(key=lambda row: row[0])
    return [line for _, line in log.rows]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default="sample_data/auth.log")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--date", default="2026-10-20", help="Day to simulate (YYYY-MM-DD)")
    args = parser.parse_args()

    day = datetime.strptime(args.date, "%Y-%m-%d")
    lines = build(day, args.seed)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {len(lines)} lines to {out}")


if __name__ == "__main__":
    main()
