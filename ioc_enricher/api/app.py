from fastapi import FastAPI

app = FastAPI(title="ioc-enricher")


@app.get("/health")
def health():
    return {"ok": True}


# TODO enrich endpoint
