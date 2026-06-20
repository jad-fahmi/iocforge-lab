import httpx
import respx
from ioc_enricher.connectors.abuseipdb import AbuseIPDB
from ioc_enricher.connectors.greynoise import GreyNoise
from ioc_enricher.connectors.virustotal import VirusTotal
from ioc_enricher.ioc.types import IocType


@respx.mock
def test_virustotal_malicious():
    respx.get("https://www.virustotal.com/api/v3/ip_addresses/6.6.6.6").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 5,
                            "harmless": 60,
                            "suspicious": 1,
                            "undetected": 4,
                        },
                        "tags": ["malware"],
                    }
                }
            },
        )
    )
    c = VirusTotal(api_key="x")
    r = c.enrich("6.6.6.6", IocType.IPV4)
    assert r.found is True
    assert r.malicious is True
    assert r.score > 0


@respx.mock
def test_virustotal_not_found():
    respx.get("https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4").mock(
        return_value=httpx.Response(404)
    )
    c = VirusTotal(api_key="x")
    r = c.enrich("1.2.3.4", IocType.IPV4)
    assert r.found is False
    assert r.error is None


@respx.mock
def test_abuseipdb_uses_key_header():
    route = respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "abuseConfidenceScore": 80,
                    "totalReports": 12,
                    "usageType": "Data Center",
                }
            },
        )
    )
    c = AbuseIPDB(api_key="secret")
    r = c.enrich("9.9.9.9", IocType.IPV4)
    assert route.calls.last.request.headers["Key"] == "secret"
    assert r.malicious is True


def test_missing_key_is_soft_error():
    c = GreyNoise(api_key=None)
    r = c.enrich("8.8.8.8", IocType.IPV4)
    assert r.error == "missing api key"
    assert r.found is False
