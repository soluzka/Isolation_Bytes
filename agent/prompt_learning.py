"""Privacy-aware prompt learning for the local security agent.

This module intentionally does not fine-tune or retrain a model from arbitrary
user prompts. It builds a bounded local memory of sanitized task patterns and
feedback so future agent decisions can retrieve useful prior experience.

Security properties:
- secrets/tokens/password-like values are redacted before persistence
- bounded retention and row count
- SQLite WAL mode with restrictive file permissions
- prompt text is never sent to the cloud by this module
- only explicit feedback increases a lesson's weight
- no executable instructions are learned or automatically replayed
"""

from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import time
from pathlib import Path
from typing import Any


_SECRET_PATTERNS = [
    re.compile(r"(?i)\b(api[_-]?key|token|secret|password|passwd|authorization)\s*[:=]\s*[^\s,;]+"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)\b(sk|pk)_[A-Za-z0-9_-]{16,}\b"),
]

_MAX_PROMPT = 4000
_MAX_RESPONSE = 4000
_MAX_ROWS = 2000
_RETENTION_SECONDS = 90 * 24 * 60 * 60


class PromptLearningStore:
    """Bounded local memory for reusable prompt/feedback patterns."""

    def __init__(self, path: str | os.PathLike[str] | None = None):
        default = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "Isolation_Bytes" / "agent_prompt_memory.db"
        self.path = Path(path or os.environ.get("AGENT_PROMPT_MEMORY_DB", default))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        try:
            if os.name != "nt":
                self.path.chmod(0o600)
        except OSError:
            pass

    @staticmethod
    def sanitize(text: Any, limit: int = _MAX_PROMPT) -> str:
        value = str(text or "")
        for pattern in _SECRET_PATTERNS:
            value = pattern.sub(lambda m: m.group(1) + "=<REDACTED>", value)
        return value[:limit]

    @staticmethod
    def _fingerprint(prompt: str) -> str:
        normalized = re.sub(r"\s+", " ", prompt.strip().lower())
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    @staticmethod
    def _tokens(text: str) -> set[str]:
        return {t for t in re.findall(r"[a-zA-Z0-9_]{3,}", text.lower())}

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=5)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA busy_timeout=5000")
        return db

    def _init_db(self) -> None:
        with self._connect() as db:
            db.execute(
                """CREATE TABLE IF NOT EXISTS prompt_lessons (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fingerprint TEXT NOT NULL,
                    prompt TEXT NOT NULL,
                    response TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    feedback INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL,
                    last_used REAL NOT NULL
                )"""
            )
            db.execute("CREATE INDEX IF NOT EXISTS idx_prompt_lessons_time ON prompt_lessons(last_used)")
            db.commit()
        self.prune()

    def learn(
        self,
        prompt: str,
        response: str = "",
        *,
        outcome: str = "completed",
        feedback: int = 0,
    ) -> None:
        """Store a sanitized experience; feedback is constrained to -1/0/+1."""
        prompt_s = self.sanitize(prompt)
        if not prompt_s.strip():
            return
        response_s = self.sanitize(response, _MAX_RESPONSE)
        feedback = max(-1, min(1, int(feedback)))
        now = time.time()
        fp = self._fingerprint(prompt_s)
        with self._connect() as db:
            row = db.execute(
                "SELECT id, feedback FROM prompt_lessons WHERE fingerprint=? ORDER BY id DESC LIMIT 1",
                (fp,),
            ).fetchone()
            if row:
                db.execute(
                    "UPDATE prompt_lessons SET response=?, outcome=?, feedback=?, last_used=? WHERE id=?",
                    (response_s, str(outcome)[:64], feedback, now, row[0]),
                )
            else:
                db.execute(
                    """INSERT INTO prompt_lessons
                       (fingerprint,prompt,response,outcome,feedback,created_at,last_used)
                       VALUES (?,?,?,?,?,?,?)""",
                    (fp, prompt_s, response_s, str(outcome)[:64], feedback, now, now),
                )
            db.commit()
        self.prune()

    @staticmethod
    def _rank_lesson(query: set[str], row: tuple) -> tuple[float, tuple] | None:
        tokens = PromptLearningStore._tokens(row[1])
        if not tokens:
            return None
        overlap = len(query & tokens) / max(1, len(query | tokens))
        score = overlap + (0.15 if row[4] > 0 else 0.0) - (0.15 if row[4] < 0 else 0.0)
        return (score, row) if score >= 0.10 else None

    def retrieve(self, prompt: str, limit: int = 5) -> list[dict[str, Any]]:
        """Retrieve similar prior lessons using token overlap, never execution."""
        query = self._tokens(self.sanitize(prompt))
        if not query:
            return []
        limit = max(1, min(10, int(limit)))
        with self._connect() as db:
            rows = db.execute(
                """SELECT id,prompt,response,outcome,feedback,last_used
                   FROM prompt_lessons
                   WHERE last_used >= ?""",
                (time.time() - _RETENTION_SECONDS,),
            ).fetchall()
        ranked = [self._rank_lesson(query, row) for row in rows]
        ranked = sorted(
            (item for item in ranked if item is not None),
            key=lambda item: item[0],
            reverse=True,
        )
        return [
            {
                "id": row[0],
                "prompt": row[1],
                "response": row[2],
                "outcome": row[3],
                "feedback": row[4],
                "similarity": round(score, 4),
            }
            for score, row in ranked[:limit]
        ]

    def prune(self) -> None:
        cutoff = time.time() - _RETENTION_SECONDS
        with self._connect() as db:
            db.execute("DELETE FROM prompt_lessons WHERE last_used < ?", (cutoff,))
            db.execute(
                """DELETE FROM prompt_lessons
                   WHERE id NOT IN (
                       SELECT id FROM prompt_lessons
                       ORDER BY feedback DESC, last_used DESC
                       LIMIT ?
                   )""",
                (_MAX_ROWS,),
            )
            db.commit()


prompt_learning = PromptLearningStore()


def learn_from_prompt(prompt: str, response: str = "", *, outcome: str = "completed", feedback: int = 0) -> None:
    prompt_learning.learn(prompt, response, outcome=outcome, feedback=feedback)


def recall_prompt_lessons(prompt: str, limit: int = 5) -> list[dict[str, Any]]:
    return prompt_learning.retrieve(prompt, limit=limit)
