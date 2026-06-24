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
        return SourceResult(
            source=self.name, ioc=ioc, ioc_type=ioc_type, found=True, malicious=False
        )


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
    assert result.sources[0].latency_ms is not None
    assert result.sources[0].latency_ms >= 0
    assert result.verdict == "clean"


def test_engine_records_per_source_latency():
    result = _engine([RecordingConnector(api_key="x")]).enrich("evil.com")

    assert result.sources[0].latency_ms is not None
    assert result.sources[0].latency_ms >= 0
    assert result.sources[0].cache_hit is False


def test_engine_reports_optional_sources_skipped_by_policy():
    connector = RecordingConnector(api_key="x")
    engine = Engine(
        Config(
            providers={connector.name: {"optional": True}},
            scheduler={"include_optional": False},
        ),
        sources=[],
    )
    engine.connectors = [connector]

    try:
        result = engine.enrich("evil.com")
        assert result.sources[0].error == "optional provider skipped by scheduler policy"
        unavailable = result.decision_trace["unavailable_providers"]
        assert {
            "source": connector.name,
            "state": "skipped",
            "reason": "optional_sources_disabled_by_scheduler",
        } in unavailable
        assert connector.calls == []
    finally:
        engine.close()


def test_decision_trace_records_disabled_and_unselected_providers():
    disabled = Engine(
        Config(providers={"virustotal": {"enabled": False}}),
        sources=["virustotal"],
    )
    try:
        result = disabled.enrich("evil.com")
        statuses = {item["source"]: item for item in result.unavailable_providers}
        assert statuses["virustotal"] == {
            "source": "virustotal",
            "state": "disabled",
            "reason": "disabled_in_configuration",
        }
        assert result.decision_trace["unavailable_providers"] == (
            result.unavailable_providers
        )
    finally:
        disabled.close()

    selected = Engine(Config(), sources=["virustotal"])
    try:
        result = selected.enrich("evil.com")
        statuses = {item["source"]: item for item in result.unavailable_providers}
        assert statuses["otx"]["state"] == "not_selected"
        assert statuses["otx"]["reason"] == "excluded_by_source_filter"
        assert statuses["virustotal"]["state"] == "unavailable"
        assert statuses["virustotal"]["reason"] == "required_credentials_missing"
    finally:
        selected.close()


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
    cached = engine.enrich("evil.com")

    assert len(result.sources) == 2
    assert result.verdict == "clean"
    assert len(cached.sources) == 2
    assert all(source.cache_hit for source in cached.sources)
    assert all(source.latency_ms is not None for source in cached.sources)


def test_cached_results_do_not_consume_provider_quota(tmp_path):
    class RequestRecordingConnector(RecordingConnector):
        def enrich(self, ioc, ioc_type):
            self._admit_request()
            return super().enrich(ioc, ioc_type)

    cache = Cache(path=tmp_path / "quota-cache.db", ttl=3600)
    config = Config(
        providers={"recorder": {"requests_per_window": 1, "window_seconds": 60}}
    )
    engine = Engine(config, cache=cache, sources=[])
    connector = RequestRecordingConnector(api_key="x")
    engine.connectors = [connector]

    try:
        first = engine.enrich("evil.com")
        admitted = len(engine.scheduler._starts["recorder"])
        cached = engine.enrich("evil.com")

        assert first.sources[0].cache_hit is False
        assert cached.sources[0].cache_hit is True
        assert len(engine.scheduler._starts["recorder"]) == admitted == 1
        assert connector.calls == ["evil.com"]
    finally:
        engine.close()
        cache.close()
