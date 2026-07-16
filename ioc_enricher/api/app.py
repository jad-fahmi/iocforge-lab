from functools import lru_cache

from fastapi import FastAPI

from ioc_enricher.cache import Cache
from ioc_enricher.config import Config, load_dotenv
from ioc_enricher.engine import Engine

app = FastAPI(title="ioc-enricher")


@lru_cache
def get_engine():
    load_dotenv()
    config = Config.load()
    return Engine(config, cache=Cache(ttl=config.cache_ttl))


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/enrich/{ioc}")
def enrich(ioc: str):
    result = get_engine().enrich(ioc)
    return result.to_dict()
