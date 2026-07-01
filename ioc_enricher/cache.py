import json
import sqlite3
import time
from pathlib import Path

DEFAULT_DB = Path.home() / ".cache" / "ioc-enricher" / "cache.db"


class Cache:
    """sqlite backed cache for source results."""

    def __init__(self, path=DEFAULT_DB, ttl=3600):
        self.path = Path(path)
        self.ttl = ttl
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self._init_db()

    def _init_db(self):
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
        row = self.conn.execute(
            "SELECT value, ts FROM entries WHERE k = ?", (self._key(source, ioc),)
        ).fetchone()
        if not row:
            return None
        value, ts = row
        if self.ttl and (time.time() - ts) > self.ttl:
            self.conn.execute(
                "DELETE FROM entries WHERE k = ?", (self._key(source, ioc),)
            )
            self.conn.commit()
            return None
        return json.loads(value)

    def purge_expired(self):
        cutoff = time.time() - self.ttl
        self.conn.execute("DELETE FROM entries WHERE ts < ?", (cutoff,))
        self.conn.commit()

    def set(self, source, ioc, value):
        self.conn.execute(
            "INSERT OR REPLACE INTO entries (k, value, ts) VALUES (?, ?, ?)",
            (self._key(source, ioc), json.dumps(value), time.time()),
        )
        self.conn.commit()

    def close(self):
        self.conn.close()
