# Architecture

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
