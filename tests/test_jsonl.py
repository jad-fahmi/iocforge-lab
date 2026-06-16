import json

from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import EnrichmentResult
from ioc_enricher.output.jsonl_out import render


def test_jsonl_emits_one_valid_json_object_per_result():
    results = [
        EnrichmentResult(ioc="one.example", ioc_type=IocType.DOMAIN),
        EnrichmentResult(ioc="two.example", ioc_type=IocType.DOMAIN),
    ]

    lines = render(results).splitlines()

    assert [json.loads(line)["ioc"] for line in lines] == ["one.example", "two.example"]
