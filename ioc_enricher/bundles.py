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


def _check_raw_hash(item: dict[str, Any]) -> None:
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

    for item in observations:
        if not isinstance(item, dict):
            raise ValueError("bundle observations must contain objects")
        _check_raw_hash(item)
    for snapshot in payload.get("snapshots", []):
        if not isinstance(snapshot, dict) or not isinstance(
            snapshot.get("observations", []), list
        ):
            raise ValueError("bundle snapshot evidence is invalid")
        for item in snapshot.get("observations", []):
            if not isinstance(item, dict):
                raise ValueError("bundle snapshot evidence is invalid")
            _check_raw_hash(item)
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
            unavailable_providers=original.get("unavailable_providers", []),
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


def _bundle_events_at(
    events: list[dict[str, Any]], table: str, scope_id: str | int, at: datetime
) -> tuple[list[dict[str, Any]], dict[str, Any], bool]:
    eligible = []
    invalid_timestamps = []
    for event in events:
        event_time = _bundle_time(event.get("created_at"))
        if event_time is None:
            invalid_timestamps.append(event.get("id"))
        elif event_time <= at:
            eligible.append(event)
    scope_column = {
        "investigation_events": "investigation_id",
        "indicator_events": "ioc",
    }[table]
    integrity = verify_event_stream(table, scope_column, scope_id, eligible)
    state_complete = integrity["valid"] and not invalid_timestamps
    events_at_time = []
    invalid_id = integrity["first_invalid_event_id"]
    for source in sorted(eligible, key=lambda item: int(item["id"])):
        if invalid_id is not None and int(source["id"]) >= invalid_id:
            break
        event = dict(source)
        try:
            data = json.loads(event.pop("data_json"))
        except (TypeError, ValueError):
            state_complete = False
            integrity["valid"] = False
            integrity["first_invalid_event_id"] = event.get("id")
            break
        if not isinstance(data, dict):
            state_complete = False
            integrity["valid"] = False
            integrity["first_invalid_event_id"] = event.get("id")
            break
        event["data"] = data
        events_at_time.append(event)
    integrity["unparseable_timestamp_event_ids"] = invalid_timestamps
    integrity["valid"] = bool(integrity["valid"] and not invalid_timestamps)
    if invalid_timestamps:
        integrity["head_hash"] = None
    return events_at_time, integrity, state_complete


def replay_bundle_investigation(
    payload: dict[str, Any], as_of: str, replay_results: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    """Reconstruct a complete investigation at a time using bundle contents only."""
    at = _bundle_time(as_of)
    if at is None:
        raise ValueError("as_of must be an ISO 8601 timestamp")
    timestamp = at.isoformat()
    investigation_id = payload["investigation"]["id"]
    case_events, case_integrity, state_complete = _bundle_events_at(
        payload.get("investigation_events", []),
        "investigation_events",
        investigation_id,
        at,
    )
    case_state: dict[str, Any] = {
        "id": investigation_id,
        "title": None,
        "description": None,
        "status": None,
    }
    members: dict[str, str] = {}
    exists = False
    metadata_complete = False
    for event in case_events:
        data = event["data"]
        if event["event_type"] == "investigation_created":
            exists = True
            for key in ("title", "description", "status"):
                if key in data:
                    case_state[key] = data[key]
            metadata_complete = all(
                key in data for key in ("title", "description", "status")
            )
        elif event["event_type"] in {
            "investigation_updated",
            "investigation_status_updated",
        }:
            for key in ("title", "description", "status"):
                if key in data:
                    case_state[key] = data[key]
        elif event["event_type"] == "indicator_added" and isinstance(
            data.get("ioc"), str
        ):
            members.setdefault(data["ioc"], event["created_at"])

    if not exists:
        creation_status: bool | None = (
            False if case_integrity["valid"] and state_complete else None
        )
        return {
            "investigation_id": investigation_id,
            "as_of": timestamp,
            "exists_at_time": creation_status,
            "replayable": False,
            "reason": (
                "investigation_not_yet_created"
                if creation_status is False
                else "investigation_creation_event_untrusted"
            ),
            "state_complete": False,
            "event_integrity": {"investigation": case_integrity, "indicators": {}},
        }

    if replay_results is None:
        replay_results = replay_bundle(payload)
    replay_by_id = {item["enrichment_id"]: item for item in replay_results}
    snapshots_by_ioc: dict[str, list[dict[str, Any]]] = {}
    for snapshot in payload.get("snapshots", []):
        if isinstance(snapshot, dict) and isinstance(snapshot.get("ioc"), str):
            snapshots_by_ioc.setdefault(snapshot["ioc"], []).append(snapshot)

    indicator_states: list[dict[str, Any]] = []
    indicator_integrity = {}
    graph_nodes: dict[int, dict[str, Any]] = {}
    graph_edges: dict[int, dict[str, Any]] = {}
    graph_truncated = False
    state_complete = state_complete and metadata_complete
    for ioc, added_at in members.items():
        indicator_events, integrity, indicator_complete = _bundle_events_at(
            payload.get("indicator_events", {}).get(ioc, []),
            "indicator_events",
            ioc,
            at,
        )
        indicator_integrity[ioc] = integrity
        state_complete = state_complete and indicator_complete
        analyst_state: dict[str, Any] = {
            "status": "open",
            "tags": [],
            "analyst_notes": "",
            "verdict_override": None,
            "override_reason": None,
            "override_at": None,
        }
        for event in indicator_events:
            data = event["data"]
            if event["event_type"] == "indicator_updated":
                for key in ("status", "analyst_notes"):
                    if key in data:
                        analyst_state[key] = data[key]
                if "tags" in data:
                    try:
                        tags = json.loads(data["tags"])
                    except (TypeError, ValueError):
                        state_complete = False
                    else:
                        if isinstance(tags, list) and all(
                            isinstance(tag, str) for tag in tags
                        ):
                            analyst_state["tags"] = tags
                        else:
                            state_complete = False
            elif event["event_type"] == "verdict_override_set":
                analyst_state.update(
                    {
                        "verdict_override": data.get("verdict_override"),
                        "override_reason": data.get("override_reason"),
                        "override_at": data.get("override_at"),
                    }
                )
            elif event["event_type"] == "verdict_override_cleared":
                analyst_state.update(
                    {
                        "verdict_override": None,
                        "override_reason": None,
                        "override_at": None,
                    }
                )

        eligible_snapshots = []
        invalid_snapshot_times = []
        for snapshot in snapshots_by_ioc.get(ioc, []):
            snapshot_time = _bundle_time(snapshot.get("looked_up_at"))
            if snapshot_time is None:
                invalid_snapshot_times.append(snapshot.get("id"))
            elif snapshot_time <= at:
                eligible_snapshots.append((snapshot_time, snapshot))
        eligible_snapshots.sort(
            key=lambda item: (item[0], int(item[1].get("id", 0)))
        )
        latest = eligible_snapshots[-1][1] if eligible_snapshots else None
        if invalid_snapshot_times:
            state_complete = False
        latest_replay = replay_by_id.get(latest["id"]) if latest else None
        observations = latest.get("observations", []) if latest else []
        for observation in observations:
            _check_raw_hash(observation)
        indicator_states.append(
            {
                "ioc": ioc,
                "added_at": added_at,
                "analyst_state": analyst_state,
                "analyst_events": indicator_events,
                "event_integrity": integrity,
                "invalid_snapshot_timestamp_ids": invalid_snapshot_times,
                "latest_enrichment": (
                    {
                        "enrichment_id": latest["id"],
                        "looked_up_at": latest["looked_up_at"],
                        "source_verdict": latest["result"].get("verdict"),
                        "source_score": latest["result"].get("score"),
                        "decision_trace": latest["result"].get("decision_trace", {}),
                        "replay": latest_replay,
                        "observations": observations,
                    }
                    if latest is not None
                    else None
                ),
            }
        )
        ioc_type = (
            latest.get("ioc_type", "unknown")
            if latest
            else payload.get("indicators", {}).get(ioc, {}).get("ioc_type", "unknown")
        )
        graph = _snapshot_graph(ioc, ioc_type, at, payload["graph"])
        graph_nodes.update(
            {
                node["entity_id"]: node
                for node in graph["nodes"]
                if isinstance(node.get("entity_id"), int)
            }
        )
        graph_edges.update(
            {edge["id"]: edge for edge in graph["edges"] if isinstance(edge.get("id"), int)}
        )
        graph_truncated = graph_truncated or bool(graph.get("truncated", False))

    if len(graph_edges) > 500:
        graph_edges = dict(sorted(graph_edges.items())[:500])
        graph_truncated = True
    retained_entity_ids = {
        entity_id
        for edge in graph_edges.values()
        for entity_id in (edge.get("source_entity_id"), edge.get("target_entity_id"))
        if isinstance(entity_id, int)
    }
    graph_nodes = {
        entity_id: node
        for entity_id, node in graph_nodes.items()
        if entity_id in retained_entity_ids
    }
    return {
        "investigation_id": investigation_id,
        "as_of": timestamp,
        "exists_at_time": True,
        "replayable": state_complete
        and all(
            item["latest_enrichment"] is None
            or item["latest_enrichment"]["replay"].get("replayable", False)
            for item in indicator_states
        ),
        "state_complete": state_complete,
        "investigation": case_state,
        "events": case_events,
        "indicators": indicator_states,
        "indicator_count": len(indicator_states),
        "graph": {
            "nodes": [graph_nodes[key] for key in sorted(graph_nodes)],
            "edges": [graph_edges[key] for key in sorted(graph_edges)],
            "max_depth": 5,
            "edge_limit": 500,
            "truncated": graph_truncated,
            "as_of": timestamp,
        },
        "event_integrity": {
            "investigation": case_integrity,
            "indicators": indicator_integrity,
        },
        "methodology": "bundle_investigation_event_prefix_and_snapshot_replay_v1",
    }


def compare_bundle_investigations(
    payload: dict[str, Any],
    baseline_as_of: str,
    comparison_as_of: str,
    replay_results: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Compare two whole-case reconstructions using only an exported bundle."""
    baseline_time = _bundle_time(baseline_as_of)
    comparison_time = _bundle_time(comparison_as_of)
    if baseline_time is None or comparison_time is None:
        raise ValueError("both comparison timestamps must use ISO 8601 format")
    if comparison_time < baseline_time:
        raise ValueError("comparison time must not precede the baseline")
    baseline = replay_bundle_investigation(payload, baseline_as_of, replay_results)
    comparison = replay_bundle_investigation(payload, comparison_as_of, replay_results)
    before = {item["ioc"]: item for item in baseline.get("indicators", [])}
    after = {item["ioc"]: item for item in comparison.get("indicators", [])}
    before_iocs, after_iocs = set(before), set(after)
    indicator_deltas = []
    for ioc in sorted(before_iocs | after_iocs):
        earlier, later = before.get(ioc), after.get(ioc)
        before_latest = earlier.get("latest_enrichment") if earlier else None
        after_latest = later.get("latest_enrichment") if later else None
        before_observations = {
            item["id"]: item
            for item in (before_latest or {}).get("observations", [])
            if isinstance(item.get("id"), int)
        }
        after_observations = {
            item["id"]: item
            for item in (after_latest or {}).get("observations", [])
            if isinstance(item.get("id"), int)
        }
        before_ids, after_ids = set(before_observations), set(after_observations)
        before_trace = {
            item.get("observation_id"): item
            for item in (before_latest or {}).get("decision_trace", {}).get(
                "observations", []
            )
            if isinstance(item, dict) and isinstance(item.get("observation_id"), int)
        }
        after_trace = {
            item.get("observation_id"): item
            for item in (after_latest or {}).get("decision_trace", {}).get(
                "observations", []
            )
            if isinstance(item, dict) and isinstance(item.get("observation_id"), int)
        }
        before_state = earlier.get("analyst_state") if earlier else None
        after_state = later.get("analyst_state") if later else None
        before_verdict = before_latest.get("source_verdict") if before_latest else None
        after_verdict = after_latest.get("source_verdict") if after_latest else None
        before_score = before_latest.get("source_score") if before_latest else None
        after_score = after_latest.get("source_score") if after_latest else None
        indicator_deltas.append(
            {
                "ioc": ioc,
                "membership": (
                    "added" if earlier is None else "removed" if later is None else "retained"
                ),
                "baseline": {
                    "added_at": earlier.get("added_at") if earlier else None,
                    "latest_enrichment": before_latest,
                    "analyst_state": before_state,
                },
                "comparison": {
                    "added_at": later.get("added_at") if later else None,
                    "latest_enrichment": after_latest,
                    "analyst_state": after_state,
                },
                "decision": {
                    "verdict_changed": before_verdict != after_verdict,
                    "baseline_verdict": before_verdict,
                    "comparison_verdict": after_verdict,
                    "score_delta": (
                        round(float(after_score) - float(before_score), 3)
                        if before_score is not None and after_score is not None
                        else None
                    ),
                    "baseline_replay_matches": (before_latest or {}).get("replay", {}).get(
                        "matches_original"
                    ),
                    "comparison_replay_matches": (after_latest or {}).get("replay", {}).get(
                        "matches_original"
                    ),
                },
                "analyst_state_changed": before_state != after_state,
                "evidence": {
                    "added": [
                        {
                            **after_observations[observation_id],
                            "decision_contribution": after_trace.get(observation_id),
                        }
                        for observation_id in sorted(after_ids - before_ids)
                    ],
                    "absent_from_later_snapshot": [
                        {
                            **before_observations[observation_id],
                            "decision_contribution": before_trace.get(observation_id),
                        }
                        for observation_id in sorted(before_ids - after_ids)
                    ],
                    "unchanged_observation_ids": sorted(before_ids & after_ids),
                    "decision_contribution_changes": [
                        {
                            "observation_id": observation_id,
                            "baseline": before_trace.get(observation_id),
                            "comparison": after_trace.get(observation_id),
                        }
                        for observation_id in sorted(before_ids & after_ids)
                        if before_trace.get(observation_id)
                        != after_trace.get(observation_id)
                    ],
                },
                "analyst_events_added": [
                    event
                    for event in (later or {}).get("analyst_events", [])
                    if event["id"]
                    not in {
                        previous["id"]
                        for previous in (earlier or {}).get("analyst_events", [])
                    }
                ],
            }
        )

    before_graph = {
        edge["id"]: edge for edge in baseline.get("graph", {}).get("edges", [])
    }
    after_graph = {
        edge["id"]: edge for edge in comparison.get("graph", {}).get("edges", [])
    }
    before_case_events = {event["id"]: event for event in baseline.get("events", [])}
    after_case_events = {event["id"]: event for event in comparison.get("events", [])}
    old_metadata = baseline.get("investigation", {}) or {}
    new_metadata = comparison.get("investigation", {}) or {}
    metadata_changes = {
        key: {"baseline": old_metadata.get(key), "comparison": new_metadata.get(key)}
        for key in ("title", "description", "status")
        if old_metadata.get(key) != new_metadata.get(key)
    }
    return {
        "investigation_id": payload["investigation"]["id"],
        "baseline": baseline,
        "comparison": comparison,
        "metadata_changes": metadata_changes,
        "membership": {
            "added": sorted(after_iocs - before_iocs),
            "removed": sorted(before_iocs - after_iocs),
            "retained": sorted(before_iocs & after_iocs),
        },
        "indicators": indicator_deltas,
        "investigation_events_added": [
            after_case_events[event_id]
            for event_id in sorted(after_case_events.keys() - before_case_events.keys())
        ],
        "graph": {
            "added_edges": [
                after_graph[edge_id]
                for edge_id in sorted(after_graph.keys() - before_graph.keys())
            ],
            "no_longer_valid_edges": [
                before_graph[edge_id]
                for edge_id in sorted(before_graph.keys() - after_graph.keys())
            ],
        },
        "replayable": baseline.get("replayable", False)
        and comparison.get("replayable", False),
        "methodology": "bundle_investigation_state_diff_v1",
    }


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


def inspect_bundle(
    source: bytes | bytearray | str | Path,
    as_of: str | None = None,
    baseline_as_of: str | None = None,
    comparison_as_of: str | None = None,
) -> dict[str, Any]:
    """Validate integrity and replay a bundle without provider access."""
    if (baseline_as_of is None) != (comparison_as_of is None):
        raise ValueError("both bundle comparison timestamps are required")
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
    report = {
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
    if as_of is not None:
        report["investigation_replay"] = replay_bundle_investigation(
            payload, as_of, replay_results
        )
    if baseline_as_of is not None and comparison_as_of is not None:
        report["investigation_comparison"] = compare_bundle_investigations(
            payload, baseline_as_of, comparison_as_of, replay_results
        )
    return report
