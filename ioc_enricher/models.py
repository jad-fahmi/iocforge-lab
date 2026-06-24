import hashlib
import json
import math
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from ioc_enricher.ioc.types import IocType


@dataclass
class SourceResult:
    """One provider observation about an IOC.

    ``observed_at`` is provider-supplied event time. ``collected_at`` records
    when IOCForge received the observation. The response hash fingerprints the
    structured raw payload retained by this connector; it is not a claim that
    an unretained HTTP body can be reconstructed from the hash.
    """

    source: str
    ioc: str
    ioc_type: IocType
    found: bool = False
    malicious: Optional[bool] = None
    score: Optional[float] = None
    raw: dict = field(default_factory=dict)
    error: Optional[str] = None
    tags: list = field(default_factory=list)
    observed_at: Optional[str] = None
    collected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    raw_response_sha256: Optional[str] = None
    connector_version: str = "unknown"
    normalization_version: str = "1"
    confidence: Optional[float] = None
    freshness: Optional[dict] = None
    extraction_metadata: dict = field(default_factory=dict)
    related_entities: list = field(default_factory=list)
    latency_ms: Optional[float] = None
    cache_hit: bool = False

    def __post_init__(self):
        if self.latency_ms is not None and (
            not math.isfinite(self.latency_ms) or self.latency_ms < 0
        ):
            raise ValueError("latency_ms must be finite and non-negative")
        if self.raw_response_sha256 is None:
            canonical = json.dumps(
                self.raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
            self.raw_response_sha256 = hashlib.sha256(canonical).hexdigest()

    def to_dict(self):
        canonical = json.dumps(
            self.raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        self.raw_response_sha256 = hashlib.sha256(canonical).hexdigest()
        d = asdict(self)
        d["ioc_type"] = self.ioc_type.value
        return d


@dataclass
class EnrichmentResult:
    """aggregated result across all sources for one ioc."""

    ioc: str
    ioc_type: IocType
    sources: list = field(default_factory=list)
    verdict: str = "unknown"
    score: float = 0.0
    confidence: str = "low"
    scoring_version: str = "2"
    scoring_config: Optional[dict] = None
    scored_at: Optional[str] = None
    evidence: list = field(default_factory=list)
    counter_evidence: list = field(default_factory=list)
    no_data: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    reason_codes: list = field(default_factory=list)
    decision_trace: dict = field(default_factory=dict)
    unavailable_providers: list[dict[str, Any]] = field(default_factory=list)
    recommended_action: str = "Review manually; insufficient evidence."
    source_context: Optional[dict] = None
    internal_context: dict = field(default_factory=dict)

    def add(self, result: SourceResult):
        self.sources.append(result)

    def hits(self):
        return [s for s in self.sources if s.found]

    def to_dict(self) -> dict[str, Any]:
        serialized_sources = [source.to_dict() for source in self.sources]
        trace_observations = self.decision_trace.get("observations", [])
        for ordinal, source in enumerate(serialized_sources):
            if ordinal < len(trace_observations):
                trace_observations[ordinal]["raw_response_sha256"] = source[
                    "raw_response_sha256"
                ]
        return {
            "ioc": self.ioc,
            "ioc_type": self.ioc_type.value,
            "verdict": self.verdict,
            "score": self.score,
            "confidence": self.confidence,
            "scoring_version": self.scoring_version,
            "scoring_config": self.scoring_config,
            "scored_at": self.scored_at,
            "evidence": self.evidence,
            "counter_evidence": self.counter_evidence,
            "no_data": self.no_data,
            "errors": self.errors,
            "reason_codes": self.reason_codes,
            "decision_trace": self.decision_trace,
            "unavailable_providers": self.unavailable_providers,
            "recommended_action": self.recommended_action,
            "source_context": self.source_context,
            "internal_context": self.internal_context,
            "sources": serialized_sources,
        }
