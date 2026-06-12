from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import EnrichmentResult, SourceResult
from ioc_enricher.scoring import score, verdict_for


def _res(sources):
    r = EnrichmentResult(ioc="x", ioc_type=IocType.IPV4)
    for s in sources:
        r.add(s)
    return r


def test_clean_when_nothing_flags():
    r = _res([SourceResult("virustotal", "x", IocType.IPV4, found=True,
                           malicious=False, score=0.0)])
    val, verdict = score(r)
    assert verdict == "clean"
    assert val == 0.0


def test_malicious_from_strong_source():
    r = _res([SourceResult("virustotal", "x", IocType.IPV4, found=True,
                           malicious=True, score=1.0)])
    val, verdict = score(r)
    assert verdict == "malicious"


def test_shodan_does_not_move_score():
    r = _res([SourceResult("shodan", "x", IocType.IPV4, found=True,
                           malicious=None)])
    val, _ = score(r)
    assert val == 0.0


def test_verdict_buckets():
    assert verdict_for(0.7) == "malicious"
    assert verdict_for(0.3) == "suspicious"
    assert verdict_for(0.05) == "low"
    assert verdict_for(0.0) == "clean"
