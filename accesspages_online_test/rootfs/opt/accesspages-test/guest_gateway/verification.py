"""Short-lived email verification challenges and guest sessions."""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import hmac
import secrets
import sqlite3
from threading import Lock


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: datetime) -> int:
    return int(value.timestamp())


class VerificationStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._initialized = False
        self._initialize_lock = Lock()

    def _connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=10)
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    def _initialize(self):
        if self._initialized:
            return
        with self._initialize_lock:
            if self._initialized:
                return
            with self._connect() as db:
                db.executescript("""
                CREATE TABLE IF NOT EXISTS challenges (
                    page_id TEXT NOT NULL, grant_id TEXT NOT NULL,
                    code_hash TEXT NOT NULL, expires_at INTEGER NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    sent_at INTEGER NOT NULL,
                    PRIMARY KEY (page_id, grant_id)
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY, page_id TEXT NOT NULL,
                    grant_id TEXT NOT NULL, expires_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS sessions_grant
                    ON sessions(page_id, grant_id);
                """)
            self._initialized = True

    def issue_challenge(
        self, page_id: str, grant_id: str, *, replace: bool = False,
    ) -> str | None:
        self._initialize()
        now = _timestamp(_now())
        with self._connect() as db:
            # Serialize the complete read/check/write, including across store
            # instances. SQLite's implicit transaction starts only at UPDATE.
            db.execute("BEGIN IMMEDIATE")
            now = _timestamp(_now())
            current = db.execute(
                "SELECT expires_at, attempts, sent_at FROM challenges "
                "WHERE page_id=? AND grant_id=?",
                (page_id, grant_id),
            ).fetchone()
            if current and current[0] > now and current[1] < 5 and not replace:
                return None
            if current and now - current[2] < 60:
                raise ValueError("Wait 60 seconds before requesting another code")
            code = f"{secrets.randbelow(1_000_000):06d}"
            db.execute(
                "INSERT OR REPLACE INTO challenges "
                "(page_id, grant_id, code_hash, expires_at, attempts, sent_at) "
                "VALUES (?, ?, ?, ?, 0, ?)",
                (page_id, grant_id, sha256(code.encode()).hexdigest(), now + 600, now),
            )
        return code

    def cancel_challenge(self, page_id: str, grant_id: str) -> None:
        self._initialize()
        with self._connect() as db:
            db.execute(
                "DELETE FROM challenges WHERE page_id=? AND grant_id=?",
                (page_id, grant_id),
            )

    def verify(self, page_id: str, grant_id: str, code: str, grant_expires: datetime):
        self._initialize()
        now = _timestamp(_now())
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            # Time may have advanced while waiting for another writer.
            now = _timestamp(_now())
            if _timestamp(grant_expires) <= now:
                raise ValueError("The verification code is invalid or expired")
            row = db.execute(
                "SELECT code_hash, expires_at, attempts FROM challenges "
                "WHERE page_id=? AND grant_id=?",
                (page_id, grant_id),
            ).fetchone()
            if not row or row[1] <= now or row[2] >= 5:
                raise ValueError("The verification code is invalid or expired")
            db.execute(
                "UPDATE challenges SET attempts=attempts+1 WHERE page_id=? AND grant_id=?",
                (page_id, grant_id),
            )
            matched = hmac.compare_digest(
                row[0], sha256(code.encode()).hexdigest(),
            )
            if not matched:
                db.commit()
                raise ValueError("The verification code is invalid or expired")
            token = secrets.token_urlsafe(32)
            session_expires = min(now + 12 * 3600, _timestamp(grant_expires))
            db.execute(
                "DELETE FROM challenges WHERE page_id=? AND grant_id=?",
                (page_id, grant_id),
            )
            db.execute(
                "INSERT INTO sessions(token_hash,page_id,grant_id,expires_at) "
                "VALUES(?,?,?,?)",
                (sha256(token.encode()).hexdigest(), page_id, grant_id, session_expires),
            )
        return token, session_expires

    def valid_session(self, token: str, page_id: str, grant_id: str) -> bool:
        if not token:
            return False
        self._initialize()
        now = _timestamp(_now())
        with self._connect() as db:
            db.execute("DELETE FROM sessions WHERE expires_at<=?", (now,))
            row = db.execute(
                "SELECT 1 FROM sessions WHERE token_hash=? AND page_id=? "
                "AND grant_id=? AND expires_at>?",
                (sha256(token.encode()).hexdigest(), page_id, grant_id, now),
            ).fetchone()
        return row is not None

    def revoke(self, page_id: str, grant_id: str) -> None:
        self._initialize()
        with self._connect() as db:
            db.execute("DELETE FROM challenges WHERE page_id=? AND grant_id=?", (page_id, grant_id))
            db.execute("DELETE FROM sessions WHERE page_id=? AND grant_id=?", (page_id, grant_id))
