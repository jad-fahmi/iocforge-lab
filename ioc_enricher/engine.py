from concurrent.futures import ThreadPoolExecutor
from typing import Any

from ioc_enricher.connectors.abuseipdb import AbuseIPDB
from ioc_enricher.connectors.crtsh import CrtSh
from ioc_enricher.connectors.dns import DNS
from ioc_enricher.connectors.greynoise import GreyNoise
from ioc_enricher.connectors.hashlookup import Hashlookup
from ioc_enricher.connectors.malwarebazaar import MalwareBazaar
from ioc_enricher.connectors.otx import OTX
from ioc_enricher.connectors.rdap import RDAP
from ioc_enricher.connectors.registry import ConnectorRegistry
from ioc_enricher.connectors.shodan import Shodan
from ioc_enricher.connectors.threatfox import ThreatFox
from ioc_enricher.connectors.urlhaus import URLhaus
from ioc_enricher.connectors.virustotal import VirusTotal
from ioc_enricher.context import InternalContext
from ioc_enricher.ioc.defang import refang
from ioc_enricher.ioc.detect import detect, normalize
from ioc_enricher.log import get
from ioc_enricher.models import EnrichmentResult
from ioc_enricher.scoring import score

log = get(__name__)

REGISTRY = ConnectorRegistry(
    [
        VirusTotal,
        AbuseIPDB,
        OTX,
        Shodan,
        GreyNoise,
        RDAP,
        DNS,
        CrtSh,
        Hashlookup,
        URLhaus,
        ThreatFox,
        MalwareBazaar,
    ]
)


class Engine:
    def __init__(
        self, config, cache=None, sources=None, internal_context=None, history=None
    ):
        self.config = config
        self.cache = cache
        self.connectors = self._build(sources)
        self.internal_context = internal_context or InternalContext.empty()
        self.history = history

    def _build(self, sources):
        return REGISTRY.build(self.config, sources)

    def provider_status(self):
        return [status.to_dict() for status in REGISTRY.status(self.config)]

    def enrich(self, ioc, source_context=None):
        ioc = refang(ioc.strip())
        ioc_type = detect(ioc)
        ioc = normalize(ioc, ioc_type)
        log.debug("detected %s as %s", ioc, ioc_type)
        result = EnrichmentResult(ioc=ioc, ioc_type=ioc_type,
                                  source_context=source_context)
        result.internal_context = self.internal_context.evaluate(ioc, ioc_type)

        active = [c for c in self.connectors if c.supports(ioc_type)]

        with ThreadPoolExecutor(max_workers=len(active) or 1) as pool:
            futures = {
                pool.submit(c.run, ioc, ioc_type, self.cache): c for c in active
            }
            for f, conn in futures.items():
                try:
                    result.add(f.result())
                except Exception as exc:
                    # a broken connector should not sink the whole lookup
                    log.exception("connector %s crashed", conn.name)
                    result.add(conn._empty(ioc, ioc_type, error=str(exc)))

        result.score, result.verdict = score(result, settings=self.config.scoring)
        if self.history is not None:
            self.history.record(result)
        return result

    def enrich_many(self, iocs, workers=4, progress=None):
        # dedupe but keep first-seen order
        seen: dict[str, Any] = {}
        contexts: dict[str, Any] = {}
        for item in iocs:
            if isinstance(item, tuple):
                ioc, source_context = item
            else:
                ioc, source_context = item, None
            seen.setdefault(ioc, None)
            contexts.setdefault(ioc, source_context)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(self.enrich, i, contexts.get(i)): i
                for i in seen
            }
            done = 0
            for f in futures:
                seen[futures[f]] = f.result()
                done += 1
                if progress:
                    progress(done, len(futures), futures[f])

        return list(seen.values())
