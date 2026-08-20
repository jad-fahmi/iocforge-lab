from ioc_enricher.cache import Cache
from ioc_enricher.config import Config
from ioc_enricher.connectors.base import Connector
from ioc_enricher.engine import Engine
from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import SourceResult


class RecordingConnector(Connector):
    name = "recorder"
    supported = (IocType.DOMAIN,)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.calls = []

    def enrich(self, ioc, ioc_type):
        self.calls.append(ioc)
        return SourceResult(source=self.name, ioc=ioc, ioc_type=ioc_type,
                             found=True, malicious=False)


class OtherConnector(RecordingConnector):
    name = "other"


class CrashingConnector(Connector):
    name = "crasher"
    supported = (IocType.DOMAIN,)

    def enrich(self, ioc, ioc_type):
        raise RuntimeError("boom")


def _engine(connectors):
    engine = Engine(Config(), sources=None)
    engine.connectors = connectors
    return engine


def test_enrich_refangs_before_dispatch():
    """regression test: defanged input must be refanged before it's
    handed to connectors, or requests get built against the literal
    defanged string (e.g. /domains/evil[.]com)."""
    conn = RecordingConnector(api_key="x")
    result = _engine([conn]).enrich("evil[.]com")

    assert result.ioc == "evil.com"
    assert conn.calls == ["evil.com"]


def test_enrich_normalizes_case_for_domains():
    conn = RecordingConnector(api_key="x")
    result = _engine([conn]).enrich("EVIL.com")

    assert result.ioc == "evil.com"
    assert conn.calls == ["evil.com"]


def test_crashing_connector_does_not_sink_lookup():
    result = _engine([CrashingConnector(api_key="x")]).enrich("evil.com")

    assert result.sources[0].error == "boom"
    assert result.verdict == "clean"


def test_enrich_many_dedupes_and_preserves_order():
    conn = RecordingConnector(api_key="x")
    results = _engine([conn]).enrich_many(["evil.com", "good.com", "evil.com"])

    assert [r.ioc for r in results] == ["evil.com", "good.com"]
    assert sorted(conn.calls) == ["evil.com", "good.com"]


def test_enrich_with_real_cache_and_multiple_connectors(tmp_path):
    """regression test: the engine runs connectors concurrently via a
    thread pool, so a shared cache must not crash across threads."""
    cache = Cache(path=tmp_path / "cache.db", ttl=3600)
    engine = Engine(Config(), cache=cache, sources=None)
    engine.connectors = [RecordingConnector(api_key="x"), OtherConnector(api_key="x")]

    result = engine.enrich("evil.com")

    assert len(result.sources) == 2
    assert result.verdict == "clean"
