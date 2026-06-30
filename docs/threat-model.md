# Threat model

IOCForge is intended for SOC analyst enrichment. It protects credentials and
analyst workflows, but it does not establish that an IOC is malicious.

Key risks and controls:

| Risk | Control |
| --- | --- |
| API-key disclosure | Keys are read locally from environment/config; status output never returns them. |
| Unauthenticated API access | Docker Compose publishes the API on host loopback by default. The API has no built-in authentication; remote deployments need an authenticated access-control boundary. |
| Unsupported graph provenance | Provider-labeled API relationships require a linked evidence observation; unlinked manual relationships are recorded as analyst-created. |
| Rate-limit state exhaustion | The per-peer table has a fixed capacity; excess peers share one bounded overflow window instead of allocating unbounded state. |
| One provider outage | Timeouts, retries, and per-connector error isolation preserve partial results. |
| Upstream rate limits | The connector base honors `Retry-After` and backs off transient failures. |
| Corrupted local cache rows | Invalid JSON, timestamps, or provider-result shapes are evicted and treated as cache misses. |
| Defanged or malformed input | Inputs are refanged, classified, normalized, and connector type support is checked. |
| False positives | Source weighting, freshness discounting, explainable evidence, and local context inform review. |
| Sensitive lookup disclosure | Operators choose providers; the public RDAP connector is keyless but still receives queried IOCs. |

Operators should restrict access to configuration and cache databases, use least-
privileged provider keys, and understand each provider's data-retention policy.
