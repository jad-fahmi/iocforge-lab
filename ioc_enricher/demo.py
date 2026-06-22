"""Build a provider-free T1/T2 investigation bundle for the analyst walkthrough."""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ioc_enricher.bundles import build_bundle, inspect_bundle
from ioc_enricher.history import HistoryStore
from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import EnrichmentResult, SourceResult
from ioc_enricher.scoring import score

DEMO_IOC = "login-update.example"


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _source(
    name: str,
    collected_at: str,
    raw: dict[str, Any],
    *,
    found: bool = True,
    malicious: bool | None = None,
    source_score: float | None = None,
    related_entities: list[dict[str, Any]] | None = None,
) -> SourceResult:
    return SourceResult(
        source=name,
        ioc=DEMO_IOC,
        ioc_type=IocType.DOMAIN,
        found=found,
        malicious=malicious,
        score=source_score,
        raw=raw,
        observed_at=collected_at,
        collected_at=collected_at,
        connector_version="offline-demo/1",
        normalization_version="1",
        confidence=0.95 if malicious is not None else 0.8,
        freshness={"state": "fresh", "basis": "synthetic scenario time"},
        related_entities=related_entities or [],
    )


def _add_sources(result: EnrichmentResult, sources: list[SourceResult]) -> None:
    for source in sources:
        result.add(source)


def create_demo_bundle() -> tuple[bytes, dict[str, Any]]:
    """Create and independently inspect a repeatable synthetic case bundle.

    The database exists only in a temporary directory. No live connector or
    default IOCForge history path is opened.
    """
    scenario_start = datetime.now(timezone.utc).replace(microsecond=0)
    t1 = scenario_start + timedelta(minutes=1)
    t2 = scenario_start + timedelta(days=1)
    t1_text, t2_text = _timestamp(t1), _timestamp(t2)

    with tempfile.TemporaryDirectory(prefix="iocforge-t1-t2-") as temporary:
        store = HistoryStore(Path(temporary) / "demo-history.db")
        try:
            investigation = store.create_investigation(
                "T1/T2 phishing infrastructure walkthrough",
                "Synthetic offline scenario: benign provider result at T1, then "
                "new malicious classifications and infrastructure evidence at T2.",
            )
            investigation_id = int(investigation["id"])
            store.add_investigation_indicator(investigation_id, DEMO_IOC)

            t1_result = EnrichmentResult(ioc=DEMO_IOC, ioc_type=IocType.DOMAIN)
            _add_sources(
                t1_result,
                [
                    _source(
                        "virustotal",
                        t1_text,
                        {"positives": 0, "total": 70, "classification": "benign"},
                        malicious=False,
                        source_score=0.0,
                    ),
                    _source(
                        "passive_dns",
                        t1_text,
                        {"records": [{"address": "203.0.113.42", "seen": "T1"}]},
                        related_entities=[
                            {
                                "source_ioc": DEMO_IOC,
                                "target_ioc": "203.0.113.42",
                                "relationship_type": "resolves_to",
                                "confidence": 0.8,
                                "valid_from": _timestamp(t1 - timedelta(days=2)),
                                "valid_to": _timestamp(t1 + timedelta(minutes=30)),
                                "attributes": {"record_type": "A", "scenario": "T1"},
                            }
                        ],
                    ),
                ],
            )
            score(t1_result, as_of=t1_text)
            t1_id = store.record(t1_result, looked_up_at=t1_text)

            t2_result = EnrichmentResult(ioc=DEMO_IOC, ioc_type=IocType.DOMAIN)
            _add_sources(
                t2_result,
                [
                    _source(
                        "virustotal",
                        t2_text,
                        {"positives": 6, "total": 70, "classification": "phishing"},
                        malicious=True,
                        source_score=0.93,
                    ),
                    _source(
                        "threatfox",
                        t2_text,
                        {"campaign": "credential-harvest-17", "confidence": 97},
                        malicious=True,
                        source_score=0.97,
                    ),
                    _source(
                        "passive_dns",
                        t2_text,
                        {"records": [{"address": "198.51.100.27", "seen": "T2"}]},
                        related_entities=[
                            {
                                "source_ioc": DEMO_IOC,
                                "target_ioc": "198.51.100.27",
                                "relationship_type": "resolves_to",
                                "confidence": 0.96,
                                "valid_from": _timestamp(t2 - timedelta(minutes=5)),
                                "attributes": {"record_type": "A", "scenario": "T2"},
                            }
                        ],
                    ),
                    _source(
                        "crtsh",
                        t2_text,
                        {"certificate_id": "991", "subject": "login-update.example"},
                        related_entities=[
                            {
                                "source_ioc": DEMO_IOC,
                                "target_ioc": "certificate:crtsh:991",
                                "relationship_type": "has_certificate",
                                "confidence": 0.99,
                                "valid_from": _timestamp(t2 - timedelta(minutes=5)),
                                "target_entity_type": "certificate",
                            },
                            {
                                "source_ioc": "certificate:crtsh:991",
                                "target_ioc": "shared-login.example.net",
                                "relationship_type": "certificate_name",
                                "confidence": 0.99,
                                "valid_from": _timestamp(t2 - timedelta(minutes=5)),
                                "source_entity_type": "certificate",
                                "target_entity_type": "hostname",
                            },
                        ],
                    ),
                ],
            )
            score(t2_result, as_of=t2_text)
            t2_id = store.record(t2_result, looked_up_at=t2_text)

            comparison = store.compare_enrichments(t1_id, t2_id)
            if comparison is None:
                raise RuntimeError("demo snapshots could not be compared")
            payload = store.investigation_bundle_payload(investigation_id)
            if payload is None:
                raise RuntimeError("demo investigation could not be exported")
            bundle = build_bundle(payload)
            inspection = inspect_bundle(bundle)

            def snapshot_summary(enrichment_id: int) -> dict[str, Any]:
                replay = store.replay_enrichment(enrichment_id)
                if replay is None:
                    raise RuntimeError(
                        f"demo enrichment {enrichment_id} could not be replayed"
                    )
                history = next(
                    item
                    for item in store.list_enrichments(DEMO_IOC)
                    if item["id"] == enrichment_id
                )
                result = history["result"]
                return {
                    "enrichment_id": enrichment_id,
                    "looked_up_at": history["looked_up_at"],
                    "verdict": result["verdict"],
                    "score": result["score"],
                    "evidence": result["evidence"],
                    "counter_evidence": result["counter_evidence"],
                    "decision_trace": result["decision_trace"],
                    "replay": {
                        "replayable": replay["replayable"],
                        "matches_original": replay.get("matches_original"),
                    },
                }

            report = {
                "scenario": {
                    "indicator": DEMO_IOC,
                    "description": "Provider-free synthetic T1/T2 investigation",
                    "t1": t1_text,
                    "t2": t2_text,
                },
                "snapshots": [snapshot_summary(t1_id), snapshot_summary(t2_id)],
                "comparison": {
                    "verdict_changed": comparison["verdict_changed"],
                    "score_delta": comparison["score_delta"],
                    "evidence_added": comparison["evidence"]["added"],
                    "evidence_removed_from_snapshot": comparison["evidence"][
                        "removed_from_snapshot"
                    ],
                    "provider_changes": comparison["evidence"]["provider_changes"],
                    "graph": comparison["graph"],
                    "replay": comparison["replay"],
                },
                "offline_bundle_inspection": inspection,
                "bundle": {
                    "format": "iocforge",
                    "bytes": len(bundle),
                    "sha256": hashlib.sha256(bundle).hexdigest(),
                },
            }
            return bundle, report
        finally:
            store.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Create a synthetic T1/T2 IOCForge investigation bundle without "
            "contacting threat intelligence providers."
        )
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="path for the generated .iocforge bundle",
    )
    args = parser.parse_args(argv)
    bundle, report = create_demo_bundle()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(bundle)
    report["bundle"]["path"] = str(args.output)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
