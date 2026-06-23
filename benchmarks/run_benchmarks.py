"""Run deterministic, offline benchmarks for the investigation data path.

Run from the repository root with ``python -m benchmarks.run_benchmarks``.
Provider calls are simulated locally; this command never contacts threat-intel
services and writes its history database only to a temporary directory.
"""

import argparse
import hashlib
import json
import math
import os
import platform
import statistics
import tempfile
import threading
from contextlib import ExitStack, closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from time import perf_counter, sleep
from typing import Any

from ioc_enricher.config import Config
from ioc_enricher.connectors.base import Connector
from ioc_enricher.engine import Engine
from ioc_enricher.history import HistoryStore
from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import SourceResult

METHODOLOGY = "iocforge-local-benchmark-v2"
PROVIDERS = ("benchmark_primary", "benchmark_secondary")
BASE_TIME = datetime(2024, 1, 1, tzinfo=timezone.utc)
PIVOT_PATH = (
    (
        "bench-000000.example",
        "pivot-000000.related.example",
        "resolves_to",
        "domain",
        "domain",
    ),
    (
        "pivot-000000.related.example",
        "certificate:benchmark:000000",
        "has_certificate",
        "domain",
        "certificate",
    ),
    (
        "certificate:benchmark:000000",
        "pivot-leaf-000000.related.example",
        "certificate_name",
        "certificate",
        "hostname",
    ),
)


class Activity:
    """Count simulated provider work and observe concurrent in-flight calls."""

    def __init__(self):
        self._lock = threading.Lock()
        self._active = 0
        self._active_by_provider: dict[str, int] = {}
        self.requests_by_provider: dict[str, int] = {}
        self.maximum_active = 0
        self.maximum_by_provider: dict[str, int] = {}

    def start(self, provider: str) -> None:
        with self._lock:
            self._active += 1
            active = self._active_by_provider.get(provider, 0) + 1
            self._active_by_provider[provider] = active
            self.requests_by_provider[provider] = (
                self.requests_by_provider.get(provider, 0) + 1
            )
            self.maximum_active = max(self.maximum_active, self._active)
            self.maximum_by_provider[provider] = max(
                self.maximum_by_provider.get(provider, 0), active
            )

    def finish(self, provider: str) -> None:
        with self._lock:
            self._active -= 1
            self._active_by_provider[provider] -= 1

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "simulated_requests": dict(sorted(self.requests_by_provider.items())),
                "max_active_tasks": self.maximum_active,
                "max_active_by_provider": dict(sorted(self.maximum_by_provider.items())),
            }


class SyntheticProvider(Connector):
    """Local connector that creates stable evidence without network access."""

    supported = (IocType.DOMAIN,)
    requires_api_key = False

    def __init__(self, name, activity, delay_seconds):
        super().__init__(timeout=1)
        self.name = name
        self.activity = activity
        self.delay_seconds = delay_seconds

    def enrich(self, ioc: str, ioc_type: IocType) -> SourceResult:
        self.activity.start(self.name)
        try:
            if self.delay_seconds:
                sleep(self.delay_seconds)
            index = int(ioc.removeprefix("bench-").split(".", 1)[0])
            observed_at = (BASE_TIME + timedelta(seconds=index)).isoformat()
            raw = {
                "sample": index,
                "provider": self.name,
                "verdict": "malicious" if index % 17 == 0 else "benign",
            }
            relationships = []
            if self.name == PROVIDERS[0]:
                relationships.append(
                    {
                        "source_ioc": ioc,
                        "target_ioc": f"pivot-{index:06d}.related.example",
                        "relationship_type": "resolves_to",
                        "source_entity_type": "domain",
                        "target_entity_type": "domain",
                        "confidence": 0.9,
                        "valid_from": observed_at,
                        "attributes": {"benchmark_sample": index},
                    }
                )
            return SourceResult(
                source=self.name,
                ioc=ioc,
                ioc_type=ioc_type,
                found=True,
                malicious=(index % 17 == 0),
                score=1.0 if index % 17 == 0 else 0.0,
                raw=raw,
                observed_at=observed_at,
                collected_at=(BASE_TIME + timedelta(days=1, seconds=index)).isoformat(),
                connector_version="benchmark-1",
                normalization_version="1",
                related_entities=relationships,
            )
        finally:
            self.activity.finish(self.name)


def _providers(activity: Activity, delay_seconds: float) -> list[SyntheticProvider]:
    return [
        SyntheticProvider(name, activity, delay_seconds)
        for name in PROVIDERS
    ]


def _percentile(samples: list[float], quantile: float) -> float | None:
    if not samples:
        return None
    ordered = sorted(samples)
    index = max(0, min(len(ordered) - 1, math.ceil(len(ordered) * quantile) - 1))
    return round(ordered[index], 3)


def _timings(samples: list[float]) -> dict[str, Any]:
    return {
        "sample_count": len(samples),
        "mean_ms": round(statistics.mean(samples), 3) if samples else None,
        "p50_ms": _percentile(samples, 0.5),
        "p95_ms": _percentile(samples, 0.95),
    }


def _storage_counts(store: HistoryStore) -> dict[str, int]:
    tables = (
        "enrichments",
        "evidence_observations",
        "enrichment_observations",
        "indicator_relationships",
        "graph_entities",
        "indicator_events",
        "investigation_events",
    )
    return {
        table: int(store.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
        for table in tables
    }


def run_benchmarks(
    indicators: int = 100,
    lookup_workers: int = 4,
    scheduler_concurrency: int = 8,
    max_pending: int = 32,
    provider_delay_ms: float = 1,
    replay_samples: int = 20,
) -> dict[str, Any]:
    """Execute the same generated workload across scheduler and SQLite paths."""
    if indicators < 1 or lookup_workers < 1:
        raise ValueError("indicators and lookup_workers must be positive")
    if scheduler_concurrency < 1 or max_pending < 1:
        raise ValueError("scheduler limits must be positive")
    if (
        not math.isfinite(provider_delay_ms)
        or provider_delay_ms < 0
        or replay_samples < 0
    ):
        raise ValueError("delay and replay sample count must be non-negative")
    if replay_samples > indicators:
        raise ValueError("replay_samples cannot exceed indicators")

    iocs = [f"bench-{index:06d}.example" for index in range(indicators)]
    workload_digest = hashlib.sha256(
        json.dumps(
            {"indicators": iocs, "pivot_path": PIVOT_PATH},
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    scheduler_settings = {
        "max_concurrency": scheduler_concurrency,
        "max_pending": max_pending,
    }
    delay_seconds = provider_delay_ms / 1000

    online_activity = Activity()
    online_engine = Engine(Config(scheduler=scheduler_settings), sources=[])
    online_engine.connectors = _providers(online_activity, delay_seconds)
    started = perf_counter()
    online_results = online_engine.enrich_many(iocs, workers=lookup_workers)
    enrichment_seconds = perf_counter() - started
    online_engine.close()
    scheduler_report = online_activity.snapshot()

    with tempfile.TemporaryDirectory(
        prefix="iocforge-benchmark-"
    ) as temporary, ExitStack() as cleanup:
        database_path = Path(temporary) / "history.sqlite3"
        store = cleanup.enter_context(closing(HistoryStore(database_path)))
        baseline_database_bytes = database_path.stat().st_size
        investigation = store.create_investigation(
            "Synthetic benchmark", "Generated locally for performance measurement"
        )
        investigation_id = investigation["id"]
        started = perf_counter()
        for ioc in iocs:
            store.add_investigation_indicator(investigation_id, ioc)
        case_link_seconds = perf_counter() - started

        persistent_activity = Activity()
        persistent_engine = Engine(
            Config(scheduler=scheduler_settings), sources=[], history=store
        )
        persistent_engine.connectors = _providers(persistent_activity, delay_seconds)
        started = perf_counter()
        persisted_results = persistent_engine.enrich_many(iocs, workers=lookup_workers)
        persisted_seconds = perf_counter() - started

        enrichment_ids = [
            int(row[0])
            for row in store.conn.execute(
                "SELECT id FROM enrichments ORDER BY id DESC LIMIT ?",
                (replay_samples,),
            ).fetchall()
        ]
        replay_ms = []
        for enrichment_id in enrichment_ids:
            replay_started = perf_counter()
            replay = store.replay_enrichment(enrichment_id)
            replay_ms.append((perf_counter() - replay_started) * 1000)
            if replay is None or not replay.get("replayable"):
                raise RuntimeError(f"benchmark snapshot {enrichment_id} did not replay")

        for source, target, relationship, source_type, target_type in PIVOT_PATH[1:]:
            store.add_relationship(
                source,
                target,
                relationship,
                confidence=0.9,
                evidence_source="benchmark_fixture",
                source_entity_type=source_type,
                target_entity_type=target_type,
            )

        graph_started = perf_counter()
        pivots = store.suggest_pivots(iocs[0], limit=100)
        graph_query_ms = (perf_counter() - graph_started) * 1000
        path_started = perf_counter()
        pivot_paths = store.suggest_pivot_paths(iocs[0], limit=100, max_depth=4)
        path_query_ms = (perf_counter() - path_started) * 1000
        counts = _storage_counts(store)
        pivot_count = len(pivots["candidates"])
        pivot_path_count = len(pivot_paths["candidates"])
        persistent_scheduler_report = persistent_activity.snapshot()
        persistent_engine.close()
        database_bytes = database_path.stat().st_size

    if len(online_results) != indicators or len(persisted_results) != indicators:
        raise RuntimeError("benchmark did not process every generated IOC")
    return {
        "methodology": METHODOLOGY,
        "workload_sha256": workload_digest,
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "logical_cpus": os.cpu_count(),
        },
        "parameters": {
            "indicators": indicators,
            "providers_per_indicator": len(PROVIDERS),
            "lookup_workers": lookup_workers,
            "scheduler_concurrency": scheduler_concurrency,
            "max_pending": max_pending,
            "provider_delay_ms": provider_delay_ms,
            "replay_samples": replay_samples,
        },
        "offline_enrichment": {
            "elapsed_seconds": round(enrichment_seconds, 6),
            "indicators_per_second": round(indicators / enrichment_seconds, 3),
            "results": len(online_results),
            "scheduler": scheduler_report,
        },
        "scheduler_with_history": {
            "elapsed_seconds": round(persisted_seconds, 6),
            "indicators_per_second": round(indicators / persisted_seconds, 3),
            "results": len(persisted_results),
            "scheduler": persistent_scheduler_report,
        },
        "case_linking": {
            "indicator_count": indicators,
            "elapsed_seconds": round(case_link_seconds, 6),
            "indicators_per_second": round(indicators / case_link_seconds, 3),
        },
        "replay": {
            **_timings(replay_ms),
            "total_samples": len(replay_ms),
        },
        "graph": {
            "root": iocs[0],
            "pivots_returned": pivot_count,
            "elapsed_ms": round(graph_query_ms, 3),
            "pivot_paths_returned": pivot_path_count,
            "pivot_path_elapsed_ms": round(path_query_ms, 3),
            "pivot_path_expansions": pivot_paths["budget"]["expansions"],
            "pivot_path_truncated": pivot_paths["budget"]["truncated"],
        },
        "storage": {
            "database_bytes": database_bytes,
            "baseline_schema_bytes": baseline_database_bytes,
            "growth_bytes": database_bytes - baseline_database_bytes,
            "growth_bytes_per_indicator": round(
                (database_bytes - baseline_database_bytes) / indicators, 3
            ),
            "bytes_per_indicator": round(database_bytes / indicators, 3),
            "rows": counts,
        },
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--indicators", type=int, default=100)
    parser.add_argument("--lookup-workers", type=int, default=4)
    parser.add_argument("--scheduler-concurrency", type=int, default=8)
    parser.add_argument("--max-pending", type=int, default=32)
    parser.add_argument("--provider-delay-ms", type=float, default=1)
    parser.add_argument("--replay-samples", type=int, default=20)
    parser.add_argument("--json-output", type=Path)
    args = parser.parse_args(argv)
    try:
        report = run_benchmarks(
            indicators=args.indicators,
            lookup_workers=args.lookup_workers,
            scheduler_concurrency=args.scheduler_concurrency,
            max_pending=args.max_pending,
            provider_delay_ms=args.provider_delay_ms,
            replay_samples=args.replay_samples,
        )
    except (OSError, ValueError, RuntimeError) as error:
        parser.error(str(error))
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.json_output:
        try:
            args.json_output.write_text(rendered + "\n", encoding="utf-8")
        except OSError as error:
            parser.error(str(error))
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
