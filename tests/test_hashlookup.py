import httpx
import respx
from ioc_enricher.connectors.hashlookup import Hashlookup
from ioc_enricher.ioc.types import IocType


@respx.mock
def test_hashlookup_returns_known_file_metadata_without_verdict_signal():
    respx.get("https://hashlookup.circl.lu/lookup/sha256/" + "a" * 64).mock(
        return_value=httpx.Response(
            200,
            json={
                "FileName": "openssl",
                "FileSize": "723944",
                "SHA-256": "A" * 64,
                "source": "NSRL",
                "db": "nsrl_modern_rds",
            },
        )
    )

    result = Hashlookup().enrich("a" * 64, IocType.SHA256)

    assert result.found is True
    assert result.malicious is None
    assert result.raw["file_name"] == "openssl"
    assert result.tags == ["NSRL", "nsrl_modern_rds"]


@respx.mock
def test_hashlookup_not_found_is_no_data():
    respx.get("https://hashlookup.circl.lu/lookup/md5/" + "a" * 32).mock(
        return_value=httpx.Response(404)
    )

    result = Hashlookup().enrich("a" * 32, IocType.MD5)

    assert result.found is False
    assert result.error is None
