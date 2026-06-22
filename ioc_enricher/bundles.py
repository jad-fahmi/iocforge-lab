"""Portable, checksummed investigation bundles and offline replay."""

import hashlib
import hmac
import io
import json
import math
import zipfile
import zlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ioc_enricher.history import _event_hash
from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import EnrichmentResult, SourceResult
from ioc_enricher.scoring import METHODOLOGY_VERSION, score

BUNDLE_FORMAT = "iocforge"
BUNDLE_VERSION = 1
MAX_BUNDLE_BYTES = 100 * 1024 * 1024
DECISION_FIELDS = (
    "score",
    "verdict",
    "confidence",
    "evidence",
    "counter_evidence",
    "no_data",
    "errors",
    "reason_codes",
    "recommended_action",
    "decision_trace",
)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key in bundle: {key}")
        result[key] = value
    return result


def build_bundle(payload: dict[str, Any]) -> bytes:
    """Serialize a payload into a single-entry .iocforge ZIP archive."""
    payload_bytes = _canonical_json(payload)
    envelope = {
        "format": BUNDLE_FORMAT,
        "format_version": BUNDLE_VERSION,
        "payload_sha256": hashlib.sha256(payload_bytes).hexdigest(),
        "payload": payload,
    }
    bundle_json = _canonical_json(envelope)
    if len(bundle_json) > MAX_BUNDLE_BYTES:
        raise ValueError("investigation bundle exceeds the 100 MiB size limit")
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        info = zipfile.ZipInfo("bundle.json", date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o600 << 16
        archive.writestr(info, bundle_json)
    return output.getvalue()


def read_bundle(source: bytes | bytearray | str | Path) -> dict[str, Any]:
    """Read and validate a bundle without extracting any archive paths."""
    if isinstance(source, (str, Path)):
        bundle_path = Path(source)
        if bundle_path.stat().st_size > MAX_BUNDLE_BYTES:
            raise ValueError("investigation bundle exceeds the 100 MiB size limit")
        bundle_bytes = bundle_path.read_bytes()
    else:
        bundle_bytes = bytes(source)
    if len(bundle_bytes) > MAX_BUNDLE_BYTES:
        raise ValueError("investigation bundle exceeds the 100 MiB size limit")
    try:
        with zipfile.ZipFile(io.BytesIO(bundle_bytes), "r") as archive:
            entries = archive.infolist()
            if len(entries) != 1 or entries[0].filename != "bundle.json":
                raise ValueError("bundle must contain only bundle.json")
            if entries[0].file_size > MAX_BUNDLE_BYTES:
                raise ValueError("investigation bundle exceeds the 100 MiB size limit")
            document = json.loads(
                archive.read(entries[0]), object_pairs_hook=_unique_object
            )
    except (
        OSError,
        RuntimeError,
        UnicodeDecodeError,
        zipfile.BadZipFile,
        json.JSONDecodeError,
        zlib.error,
    ) as error:
        raise ValueError("invalid IOCForge bundle archive") from error
    if not isinstance(document, dict):
        raise ValueError("invalid IOCForge bundle envelope")
    if document.get("format") != BUNDLE_FORMAT:
        raise ValueError("unsupported bundle format")
    if document.get("format_version") != BUNDLE_VERSION:
        raise ValueError("unsupported bundle version")
    payload = document.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("bundle payload must be an object")
    expected = hashlib.sha256(_canonical_json(payload)).hexdigest()
    supplied = document.get("payload_sha256")
    if not isinstance(supplied, str) or not hmac.compare_digest(expected, supplied):
        raise ValueError("bundle payload checksum does not match")
    if payload.get("bundle_schema") != BUNDLE_VERSION:
        raise ValueError("unsupported investigation payload schema")
    if not isinstance(payload.get("investigation"), dict) or not isinstance(
        payload["investigation"].get("id"), int
    ):
        raise ValueError("bundle investigation metadata is invalid")
    if not isinstance(payload.get("exported_at"), str):
        raise ValueError("bundle export timestamp is invalid")
    if not isinstance(payload.get("snapshots", []), list):
        raise ValueError("bundle snapshots must be a list")
    graph = payload.get("graph")
    if not isinstance(graph, dict) or not isinstance(graph.get("edges"), list):
        raise ValueError("bundle graph must be an object")
    case_events = payload.get("investigation_events", [])
    if not isinstance(case_events, list):
        raise ValueError("bundle investigation events must be a list")
    event_streams = payload.get("indicator_events", {})
    if not isinstance(event_streams, dict) or any(
        not isinstance(events, list) for events in event_streams.values()
    ):
        raise ValueError("bundle indicator events must be lists")
    for event in [*case_events, *(item for stream in event_streams.values() for item in stream)]:
        if not isinstance(event, dict) or not all(
            key in event
            for key in (
                "id",
                "event_type",
                "data_json",
                "created_at",
                "previous_hash",
                "event_hash",
            )
        ):
            raise ValueError("bundle event record is invalid")
    observations = payload.get("observations", [])
    if not isinstance(observations, list):
        raise ValueError("bundle observations must be a list")

    for snapshot in payload.get("snapshots", []):
        if (
            not isinstance(snapshot, dict)
            or type(snapshot.get("id")) is not int
            or not isinstance(snapshot.get("ioc"), str)
            or not isinstance(snapshot.get("ioc_type"), str)
            or not isinstance(snapshot.get("looked_up_at"), str)
            or _bundle_time(snapshot.get("looked_up_at")) is None
            or not isinstance(snapshot.get("result"), dict)
            or not isinstance(snapshot.get("observations", []), list)
        ):
            raise ValueError("bundle snapshot metadata is invalid")
        if not isinstance(snapshot["result"].get("decision_trace", {}), dict):
            raise ValueError("bundle snapshot decision trace is invalid")
        snapshot_result = snapshot["result"]
        if (
            not isinstance(snapshot_result.get("verdict"), str)
            or not isinstance(snapshot_result.get("score"), (int, float))
            or not math.isfinite(float(snapshot_result["score"]))
        ):
            raise ValueError("bundle snapshot decision is invalid")
        trace_observations = snapshot_result.get("decision_trace", {}).get(
            "observations", []
        )
        if not isinstance(trace_observations, list) or any(
            not isinstance(item, dict) for item in trace_observations
        ):
            raise ValueError("bundle snapshot decision trace is invalid")
        for item in snapshot.get("observations", []):
            if (
                not isinstance(item, dict)
                or type(item.get("id")) is not int
                or not isinstance(item.get("observation"), dict)
            ):
                raise ValueError("bundle snapshot evidence is invalid")

    edge_ids = set()
    for edge in graph["edges"]:
        if (
            not isinstance(edge, dict)
            or type(edge.get("id")) is not int
            or type(edge.get("source_entity_id")) is not int
            or type(edge.get("target_entity_id")) is not int
            or not all(
                isinstance(edge.get(key), str)
                for key in (
                    "source_ioc",
                    "target_ioc",
                    "relationship_type",
                    "source_entity_type",
                    "target_entity_type",
                    "evidence_source",
                    "created_at",
                    "valid_from",
                )
            )
            or not isinstance(edge.get("confidence"), (int, float))
            or not math.isfinite(float(edge["confidence"]))
            or not isinstance(edge.get("attributes", {}), dict)
            or _bundle_time(edge.get("created_at")) is None
            or _bundle_time(edge.get("valid_from")) is None
            or (
                edge.get("valid_to") is not None
                and _bundle_time(edge.get("valid_to")) is None
            )
        ):
            raise ValueError("bundle graph edge is invalid")
        if edge["id"] in edge_ids:
            raise ValueError("bundle graph contains duplicate edge IDs")
        edge_ids.add(edge["id"])

    def check_raw_hash(item: dict[str, Any]) -> None:
        observation = item.get("observation", {})
        if not isinstance(observation, dict):
            raise ValueError("bundle evidence observation is invalid")
        raw = json.dumps(
            observation.get("raw", {}),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        expected_raw_hash = hashlib.sha256(raw).hexdigest()
        if observation.get("raw_response_sha256") != expected_raw_hash:
            raise ValueError("raw observation hash does not match bundle evidence")

    for item in observations:
        if not isinstance(item, dict):
            raise ValueError("bundle observations must contain objects")
        check_raw_hash(item)
    for snapshot in payload.get("snapshots", []):
        if not isinstance(snapshot, dict) or not isinstance(
            snapshot.get("observations", []), list
        ):
            raise ValueError("bundle snapshot evidence is invalid")
        for item in snapshot.get("observations", []):
            if not isinstance(item, dict):
                raise ValueError("bundle snapshot evidence is invalid")
            check_raw_hash(item)
    return payload


def verify_event_stream(
    table: str, scope_column: str, scope_id: str | int, events: list[dict[str, Any]]
) -> dict[str, Any]:
    """Verify one exported, ordered event stream against its SHA-256 chain."""
    if table not in {"indicator_events", "investigation_events"}:
        raise ValueError("unsupported event stream")
    previous_hash = "0" * 64
    first_invalid: int | None = None
    for event in sorted(events, key=lambda item: int(item["id"])):
        expected = _event_hash(
            table,
            str(scope_id),
            int(event["id"]),
            str(event["event_type"]),
            str(event["data_json"]),
            str(event["created_at"]),
            previous_hash,
        )
        if (
            event.get("previous_hash") != previous_hash
            or event.get("event_hash") != expected
        ):
            first_invalid = int(event["id"])
            break
        previous_hash = str(event["event_hash"])
    return {
        "scope_id": scope_id,
        "valid": first_invalid is None,
        "checked_events": len(events),
        "first_invalid_event_id": first_invalid,
        "head_hash": previous_hash if first_invalid is None else None,
    }


def replay_bundle(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Replay all supported snapshots from embedded evidence only."""
    results = []
    for snapshot in payload.get("snapshots", []):
        original = snapshot["result"]
        config = original.get("scoring_config")
        scored_at = original.get("scored_at")
        version = original.get("scoring_version")
        if version != METHODOLOGY_VERSION:
            results.append(
                {
                    "enrichment_id": snapshot["id"],
                    "replayable": False,
                    "reason": "scoring_methodology_unavailable",
                }
            )
            continue
        if not config or not scored_at:
            results.append(
                {
                    "enrichment_id": snapshot["id"],
                    "replayable": False,
                    "reason": "scoring_inputs_missing",
                }
            )
            continue
        observations = snapshot["observations"]
        if len(observations) != len(original.get("sources", [])):
            results.append(
                {
                    "enrichment_id": snapshot["id"],
                    "replayable": False,
                    "reason": "evidence_observations_missing",
                }
            )
            continue
        sources = []
        for item in observations:
            source = dict(item["observation"])
            source["ioc_type"] = IocType(source["ioc_type"])
            sources.append(SourceResult(**source))
        replayed = EnrichmentResult(
            ioc=original["ioc"],
            ioc_type=IocType(original["ioc_type"]),
            sources=sources,
            internal_context=original.get("internal_context", {}),
        )
        score(replayed, settings=config, as_of=scored_at)
        recalculated = replayed.to_dict()
        trace = recalculated["decision_trace"].get("observations", [])
        for ordinal, observation in enumerate(observations):
            if ordinal < len(trace):
                trace[ordinal]["observation_id"] = observation["id"]
        matches = all(
            original.get(field) == recalculated.get(field) for field in DECISION_FIELDS
        )
        results.append(
            {
                "enrichment_id": snapshot["id"],
                "replayable": True,
                "matches_original": matches,
                "scoring_version": version,
                "scored_at": scored_at,
            }
        )
    return results


def _bundle_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _edge_key(edge: dict[str, Any]) -> str:
    identity = {
        key: edge.get(key)
        for key in (
            "source_ioc",
            "target_ioc",
            "relationship_type",
            "confidence",
            "evidence_source",
            "evidence_observation_id",
            "valid_from",
            "valid_to",
            "attributes",
        )
    }
    return json.dumps(identity, sort_keys=True, separators=(",", ":"))


def _snapshot_graph(
    ioc: str, ioc_type: str, at: datetime, bundle_graph: dict[str, Any]
) -> dict[str, Any]:
    """Rebuild one bounded typed graph view from exported temporal edges."""
    entity_type = {
        "ipv4": "ip",
        "ipv6": "ip",
        "sha256": "file_hash",
        "sha1": "file_hash",
        "md5": "file_hash",
    }.get(ioc_type, ioc_type)
    edges = []
    for edge in bundle_graph.get("edges", []):
        if not isinstance(edge, dict):
            continue
        created = _bundle_time(edge.get("created_at"))
        valid_from = _bundle_time(edge.get("valid_from"))
        valid_to = _bundle_time(edge.get("valid_to"))
        if created is None or valid_from is None or created > at or valid_from > at:
            continue
        if valid_to is not None and valid_to < at:
            continue
        edges.append(edge)

    root_ids: set[int] = set()
    for edge in edges:
        for value_key, type_key, id_key in (
            ("source_ioc", "source_entity_type", "source_entity_id"),
            ("target_ioc", "target_entity_type", "target_entity_id"),
        ):
            if edge.get(value_key) == ioc and edge.get(type_key) == entity_type:
                entity_id = edge.get(id_key)
                if isinstance(entity_id, int):
                    root_ids.add(entity_id)
    if not root_ids:
        return {"nodes": [], "edges": [], "max_depth": 5, "as_of": at.isoformat()}

    by_entity: dict[int, list[dict[str, Any]]] = {}
    for edge in edges:
        for key in ("source_entity_id", "target_entity_id"):
            entity_id = edge.get(key)
            if isinstance(entity_id, int):
                by_entity.setdefault(entity_id, []).append(edge)

    visited = set(root_ids)
    frontier = sorted(root_ids)
    selected_edges: dict[int, dict[str, Any]] = {}
    depth = 0
    while frontier and depth < 5 and len(selected_edges) < 500:
        next_frontier: dict[int, float] = {}
        for current in frontier:
            incident = by_entity.get(current, [])
            incident.sort(
                key=lambda item: (-float(item.get("confidence", 0)), -int(item.get("id", 0)))
            )
            for edge in incident:
                edge_id = edge.get("id")
                if isinstance(edge_id, int):
                    selected_edges.setdefault(edge_id, edge)
                source_id = edge.get("source_entity_id")
                target_id = edge.get("target_entity_id")
                other = target_id if source_id == current else source_id
                if isinstance(other, int) and other not in visited:
                    visited.add(other)
                    next_frontier[other] = max(
                        next_frontier.get(other, 0.0),
                        float(edge.get("confidence", 0)),
                    )
                if len(selected_edges) >= 500:
                    break
            if len(selected_edges) >= 500:
                break
        frontier = sorted(next_frontier, key=lambda item: (-next_frontier[item], item))
        depth += 1

    selected = sorted(selected_edges.values(), key=lambda item: int(item.get("id", 0)))
    nodes_by_id: dict[int, dict[str, Any]] = {}
    for edge in selected:
        for value_key, type_key, id_key in (
            ("source_ioc", "source_entity_type", "source_entity_id"),
            ("target_ioc", "target_entity_type", "target_entity_id"),
        ):
            entity_id = edge.get(id_key)
            if isinstance(entity_id, int):
                nodes_by_id[entity_id] = {
                    "entity_id": entity_id,
                    "id": edge.get(value_key),
                    "entity_type": edge.get(type_key),
                }
    return {
        "nodes": sorted(
            nodes_by_id.values(), key=lambda item: (item["id"], item["entity_type"])
        ),
        "edges": selected,
        "max_depth": 5,
        "as_of": at.isoformat(),
        "truncated": len(selected_edges) >= 500 or bundle_graph.get("truncated", False),
    }


def compare_bundle_snapshots(
    payload: dict[str, Any], replay_results: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Compare adjacent snapshots using only evidence embedded in a bundle."""
    groups: dict[str, list[dict[str, Any]]] = {}
    for snapshot in payload.get("snapshots", []):
        if isinstance(snapshot, dict) and isinstance(snapshot.get("ioc"), str):
            groups.setdefault(snapshot["ioc"], []).append(snapshot)
    replay_by_id = {item.get("enrichment_id"): item for item in replay_results}
    comparisons = []
    for ioc, snapshots in sorted(groups.items()):
        snapshots.sort(
            key=lambda item: (
                _bundle_time(item.get("looked_up_at")) or datetime.min.replace(tzinfo=timezone.utc),
                int(item.get("id", 0)),
            )
        )
        for baseline, comparison in zip(snapshots, snapshots[1:], strict=False):
            baseline_time = _bundle_time(baseline.get("looked_up_at"))
            comparison_time = _bundle_time(comparison.get("looked_up_at"))
            if baseline_time is None or comparison_time is None:
                continue
            if comparison_time < baseline_time:
                continue
            baseline_result = baseline.get("result", {})
            comparison_result = comparison.get("result", {})
            baseline_observations = baseline.get("observations", [])
            comparison_observations = comparison.get("observations", [])
            before = {item.get("id"): item for item in baseline_observations if isinstance(item, dict)}
            after = {item.get("id"): item for item in comparison_observations if isinstance(item, dict)}
            before_ids, after_ids = set(before), set(after)

            def trace_by_id(result: dict[str, Any]) -> dict[Any, dict[str, Any]]:
                trace = result.get("decision_trace", {}).get("observations", [])
                return {
                    item.get("observation_id"): item
                    for item in trace
                    if isinstance(item, dict) and item.get("observation_id") is not None
                }

            before_trace = trace_by_id(baseline_result)
            after_trace = trace_by_id(comparison_result)

            def evidence_items(
                ids: set[Any],
                observations: dict[Any, dict[str, Any]],
                traces: dict[Any, dict[str, Any]],
            ) -> list[dict[str, Any]]:
                ordered = sorted(
                    ids,
                    key=lambda item: (
                        observations[item].get("ordinal") is None,
                        observations[item].get("ordinal") or 0,
                        item if isinstance(item, int) else 0,
                    ),
                )
                return [
                    {
                        **observations[item],
                        "decision_contribution": traces.get(item),
                    }
                    for item in ordered
                ]

            ioc_type = str(baseline.get("ioc_type", baseline_result.get("ioc_type", "unknown")))
            before_graph = _snapshot_graph(ioc, ioc_type, baseline_time, payload["graph"])
            after_graph = _snapshot_graph(ioc, ioc_type, comparison_time, payload["graph"])
            before_edges = {_edge_key(edge): edge for edge in before_graph["edges"]}
            after_edges = {_edge_key(edge): edge for edge in after_graph["edges"]}
            before_nodes = {node["entity_id"]: node for node in before_graph["nodes"]}
            after_nodes = {node["entity_id"]: node for node in after_graph["nodes"]}
            baseline_id, comparison_id = baseline.get("id"), comparison.get("id")
            score_delta = round(
                float(comparison_result.get("score", 0))
                - float(baseline_result.get("score", 0)),
                3,
            )
            comparisons.append(
                {
                    "ioc": ioc,
                    "baseline": {
                        "enrichment_id": baseline_id,
                        "looked_up_at": baseline.get("looked_up_at"),
                        "verdict": baseline_result.get("verdict"),
                        "score": baseline_result.get("score"),
                        "confidence": baseline_result.get("confidence"),
                        "scoring_version": baseline_result.get("scoring_version"),
                        "scoring_config": baseline_result.get("scoring_config"),
                    },
                    "comparison": {
                        "enrichment_id": comparison_id,
                        "looked_up_at": comparison.get("looked_up_at"),
                        "verdict": comparison_result.get("verdict"),
                        "score": comparison_result.get("score"),
                        "confidence": comparison_result.get("confidence"),
                        "scoring_version": comparison_result.get("scoring_version"),
                        "scoring_config": comparison_result.get("scoring_config"),
                    },
                    "verdict_changed": baseline_result.get("verdict")
                    != comparison_result.get("verdict"),
                    "score_delta": score_delta,
                    "scoring_configuration_changed": (
                        baseline_result.get("scoring_version")
                        != comparison_result.get("scoring_version")
                        or baseline_result.get("scoring_config")
                        != comparison_result.get("scoring_config")
                    ),
                    "replay": {
                        "baseline": replay_by_id.get(baseline_id),
                        "comparison": replay_by_id.get(comparison_id),
                    },
                    "evidence": {
                        "added": evidence_items(after_ids - before_ids, after, after_trace),
                        "removed_from_snapshot": evidence_items(
                            before_ids - after_ids, before, before_trace
                        ),
                        "unchanged_observation_ids": sorted(
                            item for item in before_ids & after_ids if isinstance(item, int)
                        ),
                        "decision_contribution_changes": [
                            {
                                "observation_id": item,
                                "source": before[item]["observation"].get("source"),
                                "baseline": before_trace.get(item),
                                "comparison": after_trace.get(item),
                            }
                            for item in sorted(
                                before_ids & after_ids,
                                key=lambda value: value if isinstance(value, int) else 0,
                            )
                            if before_trace.get(item) != after_trace.get(item)
                        ],
                    },
                    "graph": {
                        "baseline": before_graph,
                        "comparison": after_graph,
                        "added_edges": [
                            after_edges[key]
                            for key in sorted(after_edges.keys() - before_edges.keys())
                        ],
                        "removed_edges": [
                            before_edges[key]
                            for key in sorted(before_edges.keys() - after_edges.keys())
                        ],
                        "added_nodes": [
                            after_nodes[key]
                            for key in sorted(after_nodes.keys() - before_nodes.keys())
                        ],
                        "removed_nodes": [
                            before_nodes[key]
                            for key in sorted(before_nodes.keys() - after_nodes.keys())
                        ],
                    },
                }
            )
    return comparisons


def inspect_bundle(source: bytes | bytearray | str | Path) -> dict[str, Any]:
    """Validate integrity and replay a bundle without provider access."""
    payload = read_bundle(source)
    investigation = payload["investigation"]
    event_integrity = {
        "investigation": verify_event_stream(
            "investigation_events",
            "investigation_id",
            investigation["id"],
            payload.get("investigation_events", []),
        ),
        "indicators": {
            ioc: verify_event_stream(
                "indicator_events", "ioc", ioc, events
            )
            for ioc, events in payload.get("indicator_events", {}).items()
        },
    }
    replay_results = replay_bundle(payload)
    return {
        "format": BUNDLE_FORMAT,
        "format_version": BUNDLE_VERSION,
        "exported_at": payload["exported_at"],
        "investigation": investigation,
        "indicators": payload["indicators"],
        "snapshot_count": len(payload.get("snapshots", [])),
        "observation_count": len(payload.get("observations", [])),
        "graph": payload["graph"],
        "event_integrity": event_integrity,
        "replay": replay_results,
        "comparisons": compare_bundle_snapshots(payload, replay_results),
    }
