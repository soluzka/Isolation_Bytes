"""Persistent file-discovery ledger for YARA/ML correlation."""
from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from hash_verify import HashVerifier

_DB_ENV = "ISOLATION_BYTES_DISCOVERY_DB"
_DEFAULT_DB = os.path.join(
    tempfile.gettempdir(), "Isolation_Bytes", "file_discovery.sqlite3"
)


class FileDiscoveryLedger:
    """Thread/process-safe ledger of exact file identities and evidence."""

    def __init__(self, db_path: Optional[str] = None):
        configured = db_path or os.environ.get(_DB_ENV, _DEFAULT_DB)
        self.db_path = os.path.abspath(configured)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._initialize()

    def _connect(self):
        connection = sqlite3.connect(self.db_path, timeout=10.0)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=10000")
        return connection

    def _initialize(self):
        with self._lock, self._connect() as db:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS file_observations (
                    sha256 TEXT PRIMARY KEY, sha512 TEXT NOT NULL,
                    sha3_256 TEXT NOT NULL, sha3_512 TEXT NOT NULL,
                    size INTEGER NOT NULL, extension TEXT NOT NULL,
                    path TEXT NOT NULL, first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL, seen_count INTEGER NOT NULL DEFAULT 1,
                    yara_severity TEXT NOT NULL DEFAULT '', yara_rules TEXT NOT NULL DEFAULT '[]',
                    code_score REAL NOT NULL DEFAULT 0.0, ml_score REAL NOT NULL DEFAULT 0.0,
                    threat_level TEXT NOT NULL DEFAULT 'low', novelty_score REAL NOT NULL DEFAULT 1.0,
                    contained INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS idx_file_observations_path "
                "ON file_observations(path)"
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS idx_file_observations_last_seen "
                "ON file_observations(last_seen)"
            )
            db.commit()

    @staticmethod
    def _normalise_rules(yara_rules: Optional[Iterable[str]]) -> list[str]:
        return sorted({str(rule) for rule in (yara_rules or []) if rule})

    @staticmethod
    def _next_observation(db, sha256: str, now: float) -> tuple[bool, int, float, float]:
        row = db.execute(
            "SELECT seen_count, first_seen FROM file_observations WHERE sha256 = ?",
            (sha256,),
        ).fetchone()
        is_new = row is None
        seen_count = 1 if is_new else int(row[0]) + 1
        first_seen = now if is_new else float(row[1])
        novelty = 1.0 if is_new else 1.0 / min(seen_count, 20)
        return is_new, seen_count, first_seen, novelty

    def observe(
        self,
        filepath: str,
        *,
        yara_severity: str = "",
        yara_rules: Optional[Iterable[str]] = None,
        code_score: float = 0.0,
        ml_score: float = 0.0,
        threat_level: str = "low",
        contained: bool = False,
    ) -> Dict[str, Any]:
        """Fingerprint and record exact content without loading it whole."""
        identity = HashVerifier.fingerprint_file(filepath)
        now = time.time()
        absolute_path = os.path.abspath(filepath)
        extension = os.path.splitext(filepath)[1].lower()
        rules = self._normalise_rules(yara_rules)

        with self._lock, self._connect() as db:
            is_new, seen_count, first_seen, novelty = self._next_observation(
                db, identity["sha256"], now
            )
            db.execute(
                """
                INSERT INTO file_observations
                (sha256, sha512, sha3_256, sha3_512, size, extension, path,
                 first_seen, last_seen, seen_count, yara_severity, yara_rules,
                 code_score, ml_score, threat_level, novelty_score, contained)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(sha256) DO UPDATE SET
                 sha512=excluded.sha512, sha3_256=excluded.sha3_256,
                 sha3_512=excluded.sha3_512, size=excluded.size,
                 extension=excluded.extension, path=excluded.path,
                 last_seen=excluded.last_seen, seen_count=excluded.seen_count,
                 yara_severity=excluded.yara_severity, yara_rules=excluded.yara_rules,
                 code_score=excluded.code_score, ml_score=excluded.ml_score,
                 threat_level=excluded.threat_level, novelty_score=excluded.novelty_score,
                 contained=MAX(file_observations.contained, excluded.contained)
                """,
                (
                    identity["sha256"],
                    identity["sha512"],
                    identity["sha3_256"],
                    identity["sha3_512"],
                    identity["size"],
                    extension,
                    absolute_path,
                    first_seen,
                    now,
                    seen_count,
                    yara_severity or "",
                    json.dumps(rules),
                    float(code_score or 0.0),
                    float(ml_score or 0.0),
                    threat_level or "low",
                    novelty,
                    int(bool(contained)),
                ),
            )
            db.commit()

        return {
            **identity,
            "path": absolute_path,
            "extension": extension,
            "is_new": is_new,
            "seen_count": seen_count,
            "novelty_score": novelty,
            "first_seen": first_seen,
            "last_seen": now,
        }

    def mark_contained(self, sha256: str, contained: bool = True) -> bool:
        """Record verified containment for an exact SHA-256 identity."""
        with self._lock, self._connect() as db:
            cursor = db.execute(
                "UPDATE file_observations SET contained = ? WHERE sha256 = ?",
                (int(bool(contained)), str(sha256).lower()),
            )
            db.commit()
            return cursor.rowcount > 0

    def lookup(self, sha256: str) -> Optional[Dict[str, Any]]:
        """Return the persisted evidence record for an exact SHA-256."""
        with self._lock, self._connect() as db:
            row = db.execute(
                "SELECT * FROM file_observations WHERE sha256 = ?",
                (sha256.lower(),),
            ).fetchone()
            if row is None:
                return None
            columns = [item[1] for item in db.execute(
                "PRAGMA table_info(file_observations)"
            ).fetchall()]
            record = dict(zip(columns, row))
            try:
                record["yara_rules"] = json.loads(record["yara_rules"])
            except (TypeError, ValueError):
                record["yara_rules"] = []
            return record


ledger = FileDiscoveryLedger()


def discover_file(filepath: str, **evidence: Any) -> Dict[str, Any]:
    """Record one scanned file through the process-wide discovery ledger."""
    return ledger.observe(filepath, **evidence)
