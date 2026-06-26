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
explicit integrity verification. Normalized provider observations and their
snapshot links and temporal graph relationships also reject direct SQL updates
and deletes. Enrichment snapshots now reject updates and deletes as well;
observation IDs are projected from the append-only link table into returned
decision traces instead of rewriting a saved snapshot. Event chains detect edits
but are not anchored outside the database, so a privileged database operator
could rewrite or truncate a whole chain.
Indicator integrity checks recompute observation payload hashes and identity keys,
then verify each saved snapshot source still matches its linked evidence. Replay
refuses to score a snapshot when those evidence checks fail.

The transformation proceeds in dependency order:

1. **Evidence identity and retention:** capture provider and collection times,
   response fingerprints, connector and normalization versions, and structured
   extraction and entity metadata for each source observation. Persist evidence
   independently of current lookup views.
2. **Decision trace and replay:** persist complete scoring inputs and methodology
   configuration, then reconstruct and compare decisions from evidence available
   at a chosen time. Snapshot replay reproduces a saved score; investigation
   replay now rebuilds case metadata, membership, analyst state, latest eligible
   snapshots, and graph state from event/evidence prefixes at an `as_of` time.
   Investigation comparison now diffs two replay points across membership,
   metadata, source decisions, observations, analyst state, event history, and
   graph edges. Replay and comparison expose integrity status through the CLI,
   API, and workbench. Snapshot comparison explains evidence changes, decision
   differences, and temporal graph changes. Legacy creation events that did not capture all
   initial metadata are reported as incomplete rather than guessed.
3. **Temporal graph and pivots:** typed entity nodes, direct pivot ranking, and
   bounded multi-hop pivot paths are available. Paths use the weakest edge
   confidence, endpoint type weight, and an explicit depth penalty; every hop
   retains its evidence source, observation ID, and validity interval. Results
   include up to three alternate edge-distinct routes to each pivot. Shared
   providers or observations mean alternate routes are not independent
   corroboration. Graph traversal has a depth limit of five and a 500-edge
   budget; path ranking caps expansions at 5,000.
4. **Investigation integrity and bundles:** per-indicator and per-investigation
   event chains can now be verified. A versioned `.iocforge` archive packages
   case metadata, linked snapshots and evidence, bounded graph state, and event
   chains; CLI, API, and workbench inspection can reconstruct and compare whole
   investigation states at selected times using only the archive. Historical
   membership, source decisions, analyst overrides, and graph changes remain
   available offline without provider access or the originating history database.
5. **Provider evaluation and scheduling:** a versioned fixture evaluator
   measures coverage, failure, latency, freshness, disagreement, overlap, and
   labeled classification errors. The engine now uses a bounded single-process
   scheduler with per-provider concurrency and sliding-window quotas, priority
   ordering, optional-source control, and configurable request retries/timeouts.
   Repeated evaluations can inform later policy tuning; fixture scores do not
   automatically alter provider weights.
6. **Interfaces and engineering evidence:** expose evidence, timeline, replay,
   graph, comparison, integrity, and bundle operations through the CLI, API,
   and browser workbench. The workbench now shows provider provenance and
   decision traces, investigation/indicator timelines, typed graph edges and
   pivots, a bounded time-filterable node-link explorer, historical replay and
   comparison, whole-investigation as-of reconstruction, analyst override
   review, event-chain status, and bundle export/offline inspection. The
   local benchmark runner measures repeated synthetic enrichment and scheduler
   throughput, SQLite history growth, case linking, graph pivots, and deterministic
   replay. Continue expanding workload sizes and graph shapes on target hardware.

The `python -m ioc_enricher.demo --output <path>` walkthrough creates its own
temporary SQLite history, seeds two explicitly timestamped synthetic provider
snapshots and temporal graph states, and exports a portable investigation
bundle. T1 includes conflicting benign and stale malicious classifications and
a provider outage; T2 refreshes those sources and adds malicious agreement and
new infrastructure pivots. A bounded URLScan observation links the T2 domain
to a page URL and a downloaded-file hash. The walkthrough prints ranked T1/T2
paths, evidence and graph diffs, both scoring traces, replay checks, and an
offline whole-investigation comparison of the exported bundle. It does not
construct an engine, load provider credentials, or access the default history
database. Its reserved `.example` domain and documentation IP ranges make it
illustrative rather than an evaluation of provider accuracy or realistic
campaign attribution.

Offline bundle inspection compares each indicator's adjacent snapshots using
the embedded observations and temporally filtered graph edges. It includes
contributing decision-trace rows and relationship provenance in its diffs, so
the workbench can show why the later decision or pivot set changed without
reopening the originating database.

Analyst verdict overrides remain separate from the source-derived score and
verdict, so historical replay continues to reproduce the provider evidence
decision. Setting or clearing an override appends a hash-chained indicator
event. The workbench displays the latest source verdict beside the active
override, its reason, and its recorded time, and exposes the audited set/clear
workflow during case inspection. Bundles include both the current override and
the indicator event history.

The evidence foundation now stores provenance on each `SourceResult` and in a
normalized `evidence_observations` table linked to enrichment snapshots by
stable observation IDs. Repeated identical provider observations share one
stored payload, while a collision with different normalized content receives a
content-derived key so both snapshots keep their own immutable evidence. The
SHA-256 value fingerprints the structured `raw` payload retained by the
connector; because connectors currently normalize or
filter upstream responses, it is not a hash of an unretained wire-level HTTP
body. Schema migration backfills observation rows from existing enrichment
snapshots. Scoring now pins the effective thresholds and weights, evaluation
time, per-observation contribution, exclusions, and local-context adjustments.
The CLI and API can replay decisions when those inputs are present and the
methodology version is supported. Both interfaces can compare two stored
snapshots, including evidence-to-decision attribution and graph edges visible
at each snapshot time. Replay reports legacy records with missing inputs as
unavailable instead of silently applying current defaults. DNS,
passive-DNS, certificate-transparency, RDAP, URLScan, and Shodan observations
emit relationship candidates. RDAP domain observations can link validated
nameservers; URLScan links the search IOC to validated page URLs, hostnames, and
IPs across at most ten search results, then fetches one full result to link the
validated primary page URL to up to 25 response hashes and 25 downloaded-file
hashes (falling back to the search IOC if the page URL is unavailable); Shodan
IP observations can link validated ASNs and hostnames. The history store creates
edges linked to their source observation and stores both provider validity and
IOCForge recording times. A missing or deleted URLScan result leaves search
metadata and page pivots intact. API graph reads
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
provider failure prevent results from the others. Invalid cache JSON, timestamps,
and provider-result shapes are evicted as misses; a corrupt cached record cannot
hide the live provider's result or outage.

The scheduler bounds concurrent provider work and queued submissions across
lookups made through the same engine. Provider policy is configured under each
`providers.<name>` object; `requests_per_window` and `window_seconds` enforce an
in-memory sliding-window quota. A shared bounded queue orders ready work across
concurrent lookups by provider priority and FIFO order within the same priority;
provider concurrency limits are applied when workers select queued jobs.
Optional providers can be skipped with `scheduler.include_optional` while
remaining visible in the result as not run. Retry limits use bounded
exponential backoff, honor numeric or HTTP-date `Retry-After` values, and cap
waits with `max_retry_after_seconds`. HTTP attempts use the configured provider
timeout; DNS resolver calls use that timeout as their lifetime bound.

The `passive_dns` connector uses CIRCL's Passive DNS endpoint for historical
records only. It explicitly sends the provider's `dribble-disable-active-query`
header, retains at most 100 records, and exposes provider-side truncation in
the normalized source response. Historical DNS is context, not a maliciousness
verdict, so it does not independently raise an IOC score.
