# Architecture

## Current foundations and implementation sequence

The current system already has provider adapters, a concurrent single-process
engine, a SQLite cache, append-only enrichment snapshots, analyst and
investigation event logs, basic indicator relationships, and versioned scoring
explanations. These pieces are the base for the investigation engine; the
history database is not yet a complete temporal evidence store. Relationships
carry validity intervals and link to provider observations. A typed entity table
now classifies graph endpoints while retaining the existing string endpoint
columns for API and storage compatibility.
Snapshot comparison is available. Indicator and investigation events now use
per-scope SHA-256 chains, migration backfill, SQLite append-only guards, and
explicit integrity verification. These local chains detect edits but are not
anchored outside the database, so a privileged database operator could rewrite
or truncate a whole chain.

The transformation proceeds in dependency order:

1. **Evidence identity and retention:** capture provider and collection times,
   response fingerprints, connector and normalization versions, and structured
   extraction and entity metadata for each source observation. Persist evidence
   independently of current lookup views.
2. **Decision trace and replay:** persist complete scoring inputs and methodology
   configuration, then reconstruct and compare decisions from evidence available
   at a chosen time. The first replay path now reproduces a saved score and
   exposes its trace through the CLI and API. Snapshot comparison explains
   evidence changes, decision differences, and temporal graph changes.
3. **Temporal graph and pivots:** typed entity nodes and a bounded, explainable
   one-hop pivot ranking are available. Continue expanding relationship sources
   and pivot evaluation; graph traversal has a depth limit of five and a
   500-edge budget.
4. **Investigation integrity and bundles:** per-indicator and per-investigation
   event chains can now be verified. A versioned `.iocforge` archive packages
   case metadata, linked snapshots and evidence, bounded graph state, and event
   chains; CLI and API inspection verifies and replays it without live providers.
5. **Provider evaluation and scheduling:** a versioned fixture evaluator
   measures coverage, failure, latency, freshness, disagreement, overlap, and
   labeled classification errors. The engine now uses a bounded single-process
   scheduler with per-provider concurrency and sliding-window quotas, priority
   ordering, optional-source control, and configurable request retries/timeouts.
   Repeated evaluations can inform later policy tuning; fixture scores do not
   automatically alter provider weights.
6. **Interfaces and engineering evidence:** expose evidence, timeline, replay,
   graph, and bundle operations through current CLI/API/UI surfaces, with
   adversarial fixtures and measured performance for each subsystem.

The evidence foundation now stores provenance on each `SourceResult` and in a
normalized `evidence_observations` table linked to enrichment snapshots by
stable observation IDs. The SHA-256 value fingerprints the structured `raw`
payload retained by the connector; because connectors currently normalize or
filter upstream responses, it is not a hash of an unretained wire-level HTTP
body. Schema migration backfills observation rows from existing enrichment
snapshots. Scoring now pins the effective thresholds and weights, evaluation
time, per-observation contribution, exclusions, and local-context adjustments.
The CLI and API can replay decisions when those inputs are present and the
methodology version is supported. Both interfaces can compare two stored
snapshots, including evidence-to-decision attribution and graph edges visible
at each snapshot time. Replay reports legacy records with missing inputs as
unavailable instead of silently applying current defaults. DNS,
passive-DNS, and certificate-transparency observations emit relationship
candidates; the history store creates edges linked to their source observation
and stores both provider validity and IOCForge recording times. API graph reads
support bounded-depth traversal, an `as_of` filter, and explicit root type
selection for hostnames or other ambiguous values. Graph nodes classify
domains, IP addresses, URLs, file hashes, ASNs, certificates, hostnames,
provider observations, and investigations. Pivot ranking is a transparent
confidence-times-entity-type heuristic, not a learned provider reliability
score. Event history responses include chain hashes, and integrity endpoints
verify each scope. Bundle checksums detect archive corruption, and raw-response hashes
are checked again on load. The archive checksum is not a digital signature;
authenticity still depends on a trusted transfer channel.

IOCForge has four layers:

1. **IOC handling** refangs, detects, normalizes, and extracts indicators.
2. **Engine** selects enabled connectors, runs compatible providers concurrently,
   applies local context, and aggregates a result.
3. **Connectors** translate provider responses into a common `SourceResult`.
4. **Presentation** exposes the result through the CLI and FastAPI endpoints.

`ConnectorRegistry` is the source of truth for installed providers. Each
provider declares the IOC types it accepts and whether credentials are
required. Configuration can disable any provider without removing its key.

The cache is deliberately in front of individual connectors, so cached provider
answers retain their original source attribution. The engine never lets one
provider failure prevent results from the others.

The scheduler bounds concurrent provider work and queued submissions across
lookups made through the same engine. Provider policy is configured under each
`providers.<name>` object; `requests_per_window` and `window_seconds` enforce an
in-memory sliding-window quota. Priority is applied when each lookup is
dispatched. Optional providers can be skipped with `scheduler.include_optional`
while remaining visible in the result as not run. Retry limits use bounded
exponential backoff, honor numeric or HTTP-date `Retry-After` values, and cap
waits with `max_retry_after_seconds`. HTTP attempts use the configured provider
timeout; DNS resolver calls use that timeout as their lifetime bound.

The `passive_dns` connector uses CIRCL's Passive DNS endpoint for historical
records only. It explicitly sends the provider's `dribble-disable-active-query`
header, retains at most 100 records, and exposes provider-side truncation in
the normalized source response. Historical DNS is context, not a maliciousness
verdict, so it does not independently raise an IOC score.
