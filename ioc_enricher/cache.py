import json
import math
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path

DEFAULT_DB = Path.home() / ".cache" / "iocforge-lab" / "cache.db"


@dataclass(frozen=True)
class CacheLookup:
    value: dict
    stale: bool
    age_seconds: float


def _reject_json_constant(value):
    raise ValueError(f"invalid JSON numeric constant: {value}")


class Cache:
    """sqlite backed cache for source results.

    accessed concurrently by the engine's thread pool, so the connection
    is opened with check_same_thread=False and all access goes through
    a lock (sqlite connections aren't safe for concurrent statements
    even when cross-thread use is allowed).
    """

    def __init__(self, path=DEFAULT_DB, ttl=3600):
        self.path = Path(path)
        self.ttl = ttl
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        with self._lock:
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS entries ("
                "  k TEXT PRIMARY KEY,"
                "  value TEXT NOT NULL,"
                "  ts REAL NOT NULL"
                ")"
            )
            self.conn.commit()

    @staticmethod
    def _key(source, ioc):
        return f"{source}:{ioc}"

    def get(self, source, ioc):
        lookup = self.lookup(source, ioc)
        return lookup.value if lookup else None

    def lookup(self, source, ioc, allow_stale=False):
        """Return a cache entry and age metadata; stale entries are opt-in."""
        key = self._key(source, ioc)
        with self._lock:
            row = self.conn.execute(
                "SELECT value, ts FROM entries WHERE k = ?", (key,)
            ).fetchone()
            if not row:
                return None
            value, ts = row
            try:
                stored_at = float(ts)
                decoded = json.loads(value, parse_constant=_reject_json_constant)
            except (TypeError, ValueError, UnicodeDecodeError, OverflowError):
                self._delete_key(key)
                return None
            if not math.isfinite(stored_at) or not isinstance(decoded, dict):
                self._delete_key(key)
                return None
            age_seconds = max(0.0, time.time() - stored_at)
            stale = bool(self.ttl and age_seconds > self.ttl)
            if stale and not allow_stale:
                return None
            return CacheLookup(decoded, stale, age_seconds)

    def _delete_key(self, key):
        self.conn.execute("DELETE FROM entries WHERE k = ?", (key,))
        self.conn.commit()

    def delete(self, source, ioc):
        """Remove one provider result that failed schema validation."""
        with self._lock:
            self._delete_key(self._key(source, ioc))

    def purge_expired(self):
        cutoff = time.time() - self.ttl
        with self._lock:
            self.conn.execute("DELETE FROM entries WHERE ts < ?", (cutoff,))
            self.conn.commit()

    def set(self, source, ioc, value):
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO entries (k, value, ts) VALUES (?, ?, ?)",
                (self._key(source, ioc), json.dumps(value), time.time()),
            )
            self.conn.commit()

    def close(self):
        self.conn.close()
