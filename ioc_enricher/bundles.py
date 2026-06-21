"""Portable, checksummed investigation bundles and offline replay."""

import hashlib
import hmac
import io
import json
import zipfile
import zlib
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
        "replay": replay_bundle(payload),
    }
