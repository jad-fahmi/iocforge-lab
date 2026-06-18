"""Versioned FastAPI application for IOC enrichment."""

from functools import lru_cache
from typing import Any, Literal

from fastapi import APIRouter, FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from ioc_enricher.cache import Cache
from ioc_enricher.config import Config, load_dotenv
from ioc_enricher.engine import Engine
from ioc_enricher.history import HistoryStore
from ioc_enricher.ioc.extract import extract_iocs

app = FastAPI(title="IOCForge API", version="0.1.0")
api = APIRouter(prefix="/api/v1", tags=["enrichment"])


class EnrichRequest(BaseModel):
    ioc: str = Field(min_length=1, max_length=4096, description="IOC to enrich")


class BatchEnrichRequest(BaseModel):
    iocs: list[str] = Field(min_length=1, max_length=1000)


class ExtractRequest(BaseModel):
    text: str = Field(min_length=1, max_length=1_000_000)


class EnrichmentResponse(BaseModel):
    ioc: str
    ioc_type: str
    verdict: str
    score: float
    confidence: str
    scoring_version: str
    evidence: list[dict[str, Any]]
    counter_evidence: list[dict[str, Any]]
    no_data: list[str]
    errors: list[dict[str, str]]
    reason_codes: list[str]
    recommended_action: str
    source_context: dict[str, Any] | None = None
    internal_context: dict[str, Any]
    sources: list[dict[str, Any]]


class ScoreExplanationResponse(BaseModel):
    ioc: str
    ioc_type: str
    scoring_version: str
    score: float
    verdict: str
    confidence: str
    evidence: list[dict[str, Any]]
    counter_evidence: list[dict[str, Any]]
    no_data: list[str]
    errors: list[dict[str, str]]
    reason_codes: list[str]
    recommended_action: str


class BatchEnrichmentResponse(BaseModel):
    results: list[EnrichmentResponse]


class ExtractResponse(BaseModel):
    indicators: list[dict[str, Any]]


class HistoryItem(BaseModel):
    id: int
    ioc: str
    ioc_type: str
    verdict: str
    score: float
    confidence: str
    looked_up_at: str
    result: dict[str, Any]


class HistoryResponse(BaseModel):
    items: list[HistoryItem]
    limit: int
    offset: int


class IndicatorUpdateRequest(BaseModel):
    tags: list[str] | None = Field(default=None, max_length=50)
    status: Literal["open", "triaged", "benign", "malicious", "closed"] | None = None
    analyst_notes: str | None = Field(default=None, max_length=10_000)


class IndicatorResponse(BaseModel):
    ioc: str
    ioc_type: str
    first_seen: str
    last_seen: str
    tags: list[str]
    status: str
    analyst_notes: str
    verdict_override: str | None = None
    override_reason: str | None = None
    override_at: str | None = None


class VerdictOverrideRequest(BaseModel):
    verdict: Literal["clean", "low", "suspicious", "malicious"]
    reason: str = Field(min_length=1, max_length=10_000)


class IndicatorEventResponse(BaseModel):
    id: int
    event_type: str
    data: dict[str, Any]
    created_at: str


class InvestigationCreateRequest(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=10_000)


class InvestigationIndicatorRequest(BaseModel):
    ioc: str = Field(min_length=1, max_length=4096)


class InvestigationResponse(BaseModel):
    id: int
    title: str
    description: str
    status: str
    created_at: str
    updated_at: str
    indicators: list[str]


class InvestigationsResponse(BaseModel):
    items: list[InvestigationResponse]
    limit: int
    offset: int


class RelationshipCreateRequest(BaseModel):
    source_ioc: str = Field(min_length=1, max_length=4096)
    target_ioc: str = Field(min_length=1, max_length=4096)
    relationship_type: str = Field(min_length=1, max_length=100)
    confidence: float = Field(default=1.0, ge=0, le=1)
    evidence_source: str = Field(default="analyst", min_length=1, max_length=100)


class RelationshipResponse(BaseModel):
    id: int
    source_ioc: str
    target_ioc: str
    relationship_type: str
    confidence: float
    evidence_source: str
    created_at: str


class RelationshipGraphResponse(BaseModel):
    nodes: list[dict[str, str]]
    edges: list[RelationshipResponse]


@lru_cache
def get_engine() -> Engine:
    load_dotenv()
    config = Config.load()
    return Engine(config, cache=Cache(ttl=config.cache_ttl), history=HistoryStore())


@app.get("/health", tags=["operations"])
def health() -> dict[str, bool]:
    return {"ok": True}


@app.get("/providers", tags=["operations"])
def providers() -> dict[str, list[dict[str, Any]]]:
    """Compatibility endpoint for provider capability reporting."""
    return {"providers": get_engine().provider_status()}


@api.get("/providers", tags=["operations"])
def provider_status() -> dict[str, list[dict[str, Any]]]:
    return {"providers": get_engine().provider_status()}


@api.post("/enrich", response_model=EnrichmentResponse)
def enrich(request: EnrichRequest) -> dict[str, Any]:
    return get_engine().enrich(request.ioc).to_dict()


@api.post("/score/explain", response_model=ScoreExplanationResponse, tags=["scoring"])
def explain_score(request: EnrichRequest) -> dict[str, Any]:
    """Enrich an IOC and return only the auditable scoring decision."""
    result = get_engine().enrich(request.ioc).to_dict()
    fields = set(ScoreExplanationResponse.model_fields)
    return {key: value for key, value in result.items() if key in fields}


@api.post("/enrich/batch", response_model=BatchEnrichmentResponse)
def enrich_batch(request: BatchEnrichRequest) -> dict[str, list[dict[str, Any]]]:
    results = get_engine().enrich_many(request.iocs)
    return {"results": [result.to_dict() for result in results]}


@api.post("/extract", response_model=ExtractResponse)
def extract(request: ExtractRequest) -> dict[str, list[dict[str, Any]]]:
    return {"indicators": [item.to_dict() for item in extract_iocs(request.text)]}


@api.get("/history", response_model=HistoryResponse, tags=["history"])
def history(
    ioc: str | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    store = get_engine().history
    if store is None:
        raise HTTPException(status_code=503, detail="history storage is unavailable")
    return {
        "items": store.list_enrichments(ioc=ioc, limit=limit, offset=offset),
        "limit": limit,
        "offset": offset,
    }


def _history_store() -> HistoryStore:
    store = get_engine().history
    if store is None:
        raise HTTPException(status_code=503, detail="history storage is unavailable")
    return store


@api.get("/indicators/{ioc}", response_model=IndicatorResponse, tags=["indicators"])
def get_indicator(ioc: str) -> dict[str, Any]:
    indicator = _history_store().indicator(ioc)
    if indicator is None:
        raise HTTPException(status_code=404, detail="indicator not found")
    return indicator


@api.patch("/indicators/{ioc}", response_model=IndicatorResponse, tags=["indicators"])
def update_indicator(ioc: str, request: IndicatorUpdateRequest) -> dict[str, Any]:
    indicator = _history_store().update_indicator(
        ioc,
        tags=request.tags,
        status=request.status,
        analyst_notes=request.analyst_notes,
    )
    if indicator is None:
        raise HTTPException(status_code=404, detail="indicator not found")
    return indicator


@api.put("/indicators/{ioc}/verdict-override", response_model=IndicatorResponse, tags=["indicators"])
def set_verdict_override(ioc: str, request: VerdictOverrideRequest) -> dict[str, Any]:
    indicator = _history_store().set_verdict_override(ioc, request.verdict, request.reason)
    if indicator is None:
        raise HTTPException(status_code=404, detail="indicator not found")
    return indicator


@api.delete("/indicators/{ioc}/verdict-override", response_model=IndicatorResponse, tags=["indicators"])
def clear_verdict_override(ioc: str) -> dict[str, Any]:
    indicator = _history_store().clear_verdict_override(ioc)
    if indicator is None:
        raise HTTPException(status_code=404, detail="indicator not found")
    return indicator


@api.get(
    "/indicators/{ioc}/events",
    response_model=list[IndicatorEventResponse],
    tags=["indicators"],
)
def indicator_events(
    ioc: str, limit: int = Query(default=100, ge=1, le=500)
) -> list[dict[str, Any]]:
    return _history_store().indicator_events(ioc, limit=limit)


@api.post("/relationships", response_model=RelationshipResponse, status_code=201, tags=["relationships"])
def create_relationship(request: RelationshipCreateRequest) -> dict[str, Any]:
    try:
        return _history_store().add_relationship(
            request.source_ioc,
            request.target_ioc,
            request.relationship_type,
            request.confidence,
            request.evidence_source,
        )
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


@api.get(
    "/indicators/{ioc}/relationships",
    response_model=list[RelationshipResponse],
    tags=["relationships"],
)
def indicator_relationships(
    ioc: str, limit: int = Query(default=100, ge=1, le=500)
) -> list[dict[str, Any]]:
    return _history_store().relationships(ioc, limit=limit)


@api.get(
    "/indicators/{ioc}/graph",
    response_model=RelationshipGraphResponse,
    tags=["relationships"],
)
def indicator_graph(
    ioc: str, limit: int = Query(default=100, ge=1, le=500)
) -> dict[str, Any]:
    return _history_store().relationship_graph(ioc, limit=limit)


@api.post(
    "/investigations", response_model=InvestigationResponse, status_code=201, tags=["investigations"]
)
def create_investigation(request: InvestigationCreateRequest) -> dict[str, Any]:
    return _history_store().create_investigation(request.title, request.description)


@api.get("/investigations", response_model=InvestigationsResponse, tags=["investigations"])
def list_investigations(
    limit: int = Query(default=50, ge=1, le=500), offset: int = Query(default=0, ge=0)
) -> dict[str, Any]:
    return {
        "items": _history_store().list_investigations(limit=limit, offset=offset),
        "limit": limit,
        "offset": offset,
    }


@api.get(
    "/investigations/{investigation_id}",
    response_model=InvestigationResponse,
    tags=["investigations"],
)
def get_investigation(investigation_id: int) -> dict[str, Any]:
    investigation = _history_store().investigation(investigation_id)
    if investigation is None:
        raise HTTPException(status_code=404, detail="investigation not found")
    return investigation


@api.post(
    "/investigations/{investigation_id}/indicators",
    response_model=InvestigationResponse,
    tags=["investigations"],
)
def add_investigation_indicator(
    investigation_id: int, request: InvestigationIndicatorRequest
) -> dict[str, Any]:
    investigation = _history_store().add_investigation_indicator(investigation_id, request.ioc)
    if investigation is None:
        raise HTTPException(status_code=404, detail="investigation not found")
    return investigation


@api.get("/investigations/{investigation_id}/events", tags=["investigations"])
def investigation_events(
    investigation_id: int, limit: int = Query(default=100, ge=1, le=500)
) -> list[dict[str, Any]]:
    if _history_store().investigation(investigation_id) is None:
        raise HTTPException(status_code=404, detail="investigation not found")
    return _history_store().investigation_events(investigation_id, limit=limit)


app.include_router(api)


@app.get("/enrich", response_model=EnrichmentResponse, include_in_schema=False)
def legacy_enrich(ioc: str) -> dict[str, Any]:
    """Legacy endpoint; use POST /api/v1/enrich for new integrations."""
    return get_engine().enrich(ioc).to_dict()
