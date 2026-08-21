from dataclasses import dataclass, field, asdict
from typing import Any, Optional

from ioc_enricher.ioc.types import IocType


@dataclass
class SourceResult:
    """result of enriching one ioc against one source."""
    source: str
    ioc: str
    ioc_type: IocType
    found: bool = False
    malicious: Optional[bool] = None
    score: Optional[float] = None
    raw: dict = field(default_factory=dict)
    error: Optional[str] = None
    tags: list = field(default_factory=list)

    def to_dict(self):
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

    def add(self, result: SourceResult):
        self.sources.append(result)

    def hits(self):
        return [s for s in self.sources if s.found]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ioc": self.ioc,
            "ioc_type": self.ioc_type.value,
            "verdict": self.verdict,
            "score": self.score,
            "sources": [s.to_dict() for s in self.sources],
        }
