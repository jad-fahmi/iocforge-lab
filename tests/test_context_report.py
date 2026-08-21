from ioc_enricher.context import InternalContext
from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import EnrichmentResult, SourceResult
from ioc_enricher.output.markdown import render
from ioc_enricher.scoring import score


def test_internal_context_tags_business_assets(tmp_path):
    inventory = tmp_path / "assets.csv"
    inventory.write_text('ip,name,tags\n198.51.100.10,vpn-1,"vpn_endpoint,known_vendor"\n')
    ctx = InternalContext.from_files(
        paths=[],
        asset_inventory=inventory,
    )

    result = ctx.evaluate("https://login.example.com/path", IocType.URL)
    ip_result = ctx.evaluate("198.51.100.10", IocType.IPV4)

    assert result["tags"] == []
    assert "vpn_endpoint" in ip_result["tags"]
    assert "allowlisted_asset" in ip_result["reasons"]


def test_markdown_report_contains_soc_sections():
    r = EnrichmentResult(ioc="evil.com", ioc_type=IocType.DOMAIN)
    r.add(SourceResult("virustotal", "evil.com", IocType.DOMAIN, found=True,
                       malicious=True, score=1.0,
                       raw={"stats": {"malicious": 5}}))
    score(r)

    report = render([r], summary={"duplicates": 1})

    assert "## Executive summary" in report
    assert "## IOC table" in report
    assert "## High-risk findings" in report
    assert "## Source evidence" in report
    assert "## Recommended next steps" in report
    assert "## Errors and blind spots" in report
