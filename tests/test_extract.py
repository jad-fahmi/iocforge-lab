from ioc_enricher.ioc.extract import extract_iocs
from ioc_enricher.ioc.types import IocType


def test_extracts_messy_alert_text_with_context():
    text = """Slack: can someone check hxxp://evil[.]com/a?b=1
proxy allowed dst=203.0.113.9 user=analyst@example[.]com
EDR hash d41d8cd98f00b204e9800998ecf8427e exploit CVE-2024-12345 ASN AS15169"""

    results = extract_iocs(text)
    values = {r.normalized: r for r in results}

    assert values["http://evil.com/a?b=1"].ioc_type == IocType.URL
    assert values["203.0.113.9"].line_number == 2
    assert values["analyst@example.com"].original == "analyst@example[.]com"
    assert values["CVE-2024-12345"].ioc_type == IocType.CVE
    assert values["AS15169"].ioc_type == IocType.ASN
    assert "proxy allowed" in values["203.0.113.9"].context


def test_extract_dedupes_normalized_values():
    results = extract_iocs("evil[.]com then evil.com")

    assert [r.normalized for r in results] == ["evil.com"]
