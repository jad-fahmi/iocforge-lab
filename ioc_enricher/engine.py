from concurrent.futures import ThreadPoolExecutor

from ioc_enricher.connectors.abuseipdb import AbuseIPDB
from ioc_enricher.connectors.greynoise import GreyNoise
from ioc_enricher.connectors.otx import OTX
from ioc_enricher.connectors.shodan import Shodan
from ioc_enricher.connectors.virustotal import VirusTotal
from ioc_enricher.ioc.defang import refang
from ioc_enricher.ioc.detect import detect
from ioc_enricher.log import get
from ioc_enricher.models import EnrichmentResult
from ioc_enricher.scoring import score

log = get(__name__)

REGISTRY = [VirusTotal, AbuseIPDB, OTX, Shodan, GreyNoise]


class Engine:
    def __init__(self, config, cache=None, sources=None):
        self.config = config
        self.cache = cache
        self.connectors = self._build(sources)

    def _build(self, sources):
        built = []
        for cls in REGISTRY:
            if sources and cls.name not in sources:
                continue
            key = self.config.key_for(cls.name)
            built.append(cls(api_key=key))
        return built

    def enrich(self, ioc):
        ioc = refang(ioc.strip())
        ioc_type = detect(ioc)
        log.debug("detected %s as %s", ioc, ioc_type)
        result = EnrichmentResult(ioc=ioc, ioc_type=ioc_type)

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

        result.score, result.verdict = score(result)
        return result

    def enrich_many(self, iocs, workers=4):
        # dedupe but keep first-seen order
        seen = {}
        for i in iocs:
            seen.setdefault(i, None)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(self.enrich, i): i for i in seen}
            for f in futures:
                seen[futures[f]] = f.result()

        return list(seen.values())
