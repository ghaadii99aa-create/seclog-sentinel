"""SQLite storage for analysis results.

Only the *results* of an analysis are stored (findings, counts, top sources). The raw
log file is analysed in memory and discarded, so no usernames or lines from the
uploaded file are kept beyond what appears in a finding.
"""

from __future__ import annotations

import json
import secrets
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from typing import Any, Dict, List, Optional

RETENTION_DAYS = 7
MAX_ROWS = 1000

_SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id         TEXT PRIMARY KEY,
    owner      TEXT NOT NULL,
    filename   TEXT NOT NULL,
    created_at REAL NOT NULL,
    data       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_analyses_owner ON analyses (owner, created_at DESC);
"""


class Store:
    def __init__(self, path: str) -> None:
        self.path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as conn:
            conn.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        # One short-lived connection per call keeps this safe under threaded servers.
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "owner": row["owner"],
            "filename": row["filename"],
            "created_at": row["created_at"],
            "data": json.loads(row["data"]),
        }

    def save(self, owner: str, filename: str, data: Dict[str, Any], now: Optional[float] = None) -> str:
        analysis_id = secrets.token_urlsafe(9)
        created = time.time() if now is None else now
        with closing(self._connect()) as conn, conn:
            conn.execute(
                "INSERT INTO analyses (id, owner, filename, created_at, data) VALUES (?, ?, ?, ?, ?)",
                (analysis_id, owner, filename, created, json.dumps(data)),
            )
        self.prune()
        return analysis_id

    def get(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        with closing(self._connect()) as conn:
            row = conn.execute("SELECT * FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
        return self._row(row) if row else None

    def list_for_owner(self, owner: str, limit: int = 50) -> List[Dict[str, Any]]:
        with closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT * FROM analyses WHERE owner = ? ORDER BY created_at DESC LIMIT ?",
                (owner, limit),
            ).fetchall()
        return [self._row(r) for r in rows]

    def delete(self, analysis_id: str, owner: str) -> bool:
        with closing(self._connect()) as conn, conn:
            cursor = conn.execute(
                "DELETE FROM analyses WHERE id = ? AND owner = ?", (analysis_id, owner)
            )
        return cursor.rowcount > 0

    def prune(self, now: Optional[float] = None) -> int:
        """Drop results older than the retention period and cap the table size."""
        cutoff = (time.time() if now is None else now) - RETENTION_DAYS * 86400
        with closing(self._connect()) as conn, conn:
            removed = conn.execute("DELETE FROM analyses WHERE created_at < ?", (cutoff,)).rowcount
            removed += conn.execute(
                "DELETE FROM analyses WHERE id NOT IN "
                "(SELECT id FROM analyses ORDER BY created_at DESC LIMIT ?)",
                (MAX_ROWS,),
            ).rowcount
        return removed
