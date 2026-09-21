# Threat model

IOCForge is intended for SOC analyst enrichment. It protects credentials and
analyst workflows, but it does not establish that an IOC is malicious.

Key risks and controls:

| Risk | Control |
| --- | --- |
| API-key disclosure | Keys are read locally from environment/config; status output never returns them. |
| One provider outage | Timeouts, retries, and per-connector error isolation preserve partial results. |
| Upstream rate limits | The connector base honors `Retry-After` and backs off transient failures. |
| Defanged or malformed input | Inputs are refanged, classified, normalized, and connector type support is checked. |
| False positives | Source weighting, freshness discounting, explainable evidence, and local context inform review. |
| Sensitive lookup disclosure | Operators choose providers; the public RDAP connector is keyless but still receives queried IOCs. |

Operators should restrict access to configuration and cache databases, use least-
privileged provider keys, and understand each provider's data-retention policy.
