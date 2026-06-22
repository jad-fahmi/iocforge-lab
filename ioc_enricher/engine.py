from concurrent.futures import ThreadPoolExecutor
from time import perf_counter
from typing import Any

from ioc_enricher.connectors.abuseipdb import AbuseIPDB
from ioc_enricher.connectors.base import reset_request_admission, set_request_admission
from ioc_enricher.connectors.crtsh import CrtSh
from ioc_enricher.connectors.dns import DNS
from ioc_enricher.connectors.greynoise import GreyNoise
from ioc_enricher.connectors.hashlookup import Hashlookup
from ioc_enricher.connectors.malwarebazaar import MalwareBazaar
from ioc_enricher.connectors.otx import OTX
from ioc_enricher.connectors.passive_dns import PassiveDNS
from ioc_enricher.connectors.rdap import RDAP
from ioc_enricher.connectors.registry import ConnectorRegistry
from ioc_enricher.connectors.shodan import Shodan
from ioc_enricher.connectors.threatfox import ThreatFox
from ioc_enricher.connectors.urlhaus import URLhaus
from ioc_enricher.connectors.urlscan import Urlscan
from ioc_enricher.connectors.virustotal import VirusTotal
from ioc_enricher.context import InternalContext
from ioc_enricher.ioc.defang import refang
from ioc_enricher.ioc.detect import detect, normalize
from ioc_enricher.log import get
from ioc_enricher.models import EnrichmentResult
from ioc_enricher.scheduler import EnrichmentScheduler
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
        PassiveDNS,
        CrtSh,
        Hashlookup,
        Urlscan,
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
        self.scheduler = EnrichmentScheduler(
            settings=self.config.scheduler, providers=self.config.providers
        )
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
        result = EnrichmentResult(
            ioc=ioc, ioc_type=ioc_type, source_context=source_context
        )
        result.internal_context = self.internal_context.evaluate(ioc, ioc_type)

        active = [c for c in self.connectors if c.supports(ioc_type)]
        cached_results = {}
        needs_lookup = []
        skipped_sources = set()
        for connector in active:
            if self.scheduler.optional(connector.name) and not self.scheduler.include_optional:
                skipped_sources.add(connector)
                continue
            if self.cache is not None:
                started = perf_counter()
                try:
                    cached = connector._cached_result(ioc, self.cache)
                except Exception as exc:
                    log.error("cache lookup for %s failed: %s", connector.name, exc)
                    cached = None
                if cached is None:
                    needs_lookup.append(connector)
                else:
                    cached.latency_ms = round((perf_counter() - started) * 1000, 3)
                    cached_results[connector] = cached
            else:
                needs_lookup.append(connector)

        def collect(connector):
            started = perf_counter()
            admission_token = set_request_admission(
                lambda: self.scheduler.admit_request(connector.name)
            )
            try:
                source_result = connector.run(
                    ioc, ioc_type, self.cache, skip_fresh_cache=True
                )
                error = None
            except Exception as exc:
                source_result = connector._empty(ioc, ioc_type, error=str(exc))
                error = exc
            finally:
                reset_request_admission(admission_token)
            source_result.latency_ms = round((perf_counter() - started) * 1000, 3)
            return source_result, error

        scheduled = needs_lookup
        futures = self.scheduler.submit(scheduled, collect)
        for conn in active:
            if conn in skipped_sources:
                result.add(
                    conn._empty(
                        ioc, ioc_type, error="optional provider skipped by scheduler policy"
                    )
                )
                continue
            if conn in cached_results:
                result.add(cached_results[conn])
                continue
            future = futures.get(conn)
            if future is None:
                result.add(conn._empty(ioc, ioc_type, error="provider was not scheduled"))
                continue
            source_result, error = future.result()
            if error is not None:
                # A broken connector should not sink the whole lookup.
                log.error("connector %s crashed: %s", conn.name, error)
            result.add(source_result)

        result.score, result.verdict = score(result, settings=self.config.scoring)
        if self.history is not None:
            self.history.record(result)
        return result

    def close(self, wait=True):
        """Release scheduler workers when an engine's lifetime ends."""
        self.scheduler.shutdown(wait=wait)
        for connector in self.connectors:
            client = getattr(connector, "_client", None)
            if client is not None:
                client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

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
            futures = {pool.submit(self.enrich, i, contexts.get(i)): i for i in seen}
            done = 0
            for f in futures:
                seen[futures[f]] = f.result()
                done += 1
                if progress:
                    progress(done, len(futures), futures[f])

        return list(seen.values())
