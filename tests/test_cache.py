import time
from concurrent.futures import ThreadPoolExecutor

from ioc_enricher.cache import Cache


def test_set_get_roundtrip(tmp_path):
    c = Cache(path=tmp_path / "c.db", ttl=3600)
    c.set("src", "1.2.3.4", {"found": True})
    assert c.get("src", "1.2.3.4") == {"found": True}


def test_missing_key_returns_none(tmp_path):
    c = Cache(path=tmp_path / "c.db", ttl=3600)
    assert c.get("src", "nope") is None


def test_expired_entry_returns_none(tmp_path):
    c = Cache(path=tmp_path / "c.db", ttl=0.01)
    c.set("src", "1.2.3.4", {"found": True})
    time.sleep(0.05)
    assert c.get("src", "1.2.3.4") is None


def test_purge_expired_removes_old_rows(tmp_path):
    c = Cache(path=tmp_path / "c.db", ttl=0.01)
    c.set("src", "1.2.3.4", {"found": True})
    time.sleep(0.05)
    c.purge_expired()
    row = c.conn.execute("SELECT COUNT(*) FROM entries").fetchone()
    assert row[0] == 0


def test_concurrent_access_from_multiple_threads(tmp_path):
    """regression test: the cache is shared across the engine's thread
    pool, so it must survive concurrent get/set from different threads
    without raising sqlite's cross-thread ProgrammingError."""
    c = Cache(path=tmp_path / "c.db", ttl=3600)

    def worker(i):
        c.set("src", f"k{i}", {"x": i})
        return c.get("src", f"k{i}")

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(worker, range(20)))

    assert results == [{"x": i} for i in range(20)]
