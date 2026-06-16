"""Versioned FastAPI application for IOC enrichment."""

from functools import lru_cache
from typing import Any

from fastapi import APIRouter, FastAPI
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
    evidence: list[dict[str, Any]]
    counter_evidence: list[dict[str, Any]]
    no_data: list[str]
    errors: list[dict[str, str]]
    reason_codes: list[str]
    recommended_action: str
    source_context: dict[str, Any] | None = None
    internal_context: dict[str, Any]
    sources: list[dict[str, Any]]


class BatchEnrichmentResponse(BaseModel):
    results: list[EnrichmentResponse]


class ExtractResponse(BaseModel):
    indicators: list[dict[str, Any]]


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


@api.post("/enrich/batch", response_model=BatchEnrichmentResponse)
def enrich_batch(request: BatchEnrichRequest) -> dict[str, list[dict[str, Any]]]:
    results = get_engine().enrich_many(request.iocs)
    return {"results": [result.to_dict() for result in results]}


@api.post("/extract", response_model=ExtractResponse)
def extract(request: ExtractRequest) -> dict[str, list[dict[str, Any]]]:
    return {"indicators": [item.to_dict() for item in extract_iocs(request.text)]}


app.include_router(api)


@app.get("/enrich", response_model=EnrichmentResponse, include_in_schema=False)
def legacy_enrich(ioc: str) -> dict[str, Any]:
    """Legacy endpoint; use POST /api/v1/enrich for new integrations."""
    return get_engine().enrich(ioc).to_dict()
