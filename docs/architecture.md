# Architecture and design decisions

![Lakehouse Architecture](../assets/architecture.png)

## Data contracts

- **Landing zone**: one JSONL row per source record, containing `source`, `ingested_at` (UTC ISO 8601), and untouched `payload`.
- **Bronze**: append original JSON records as Delta for auditability.
- **Silver (Phase 2)**: standardized CVE entities; de-duplication; normalized metrics; left joins with KEV and latest EPSS.
- **Gold (Phase 3)**: dimensional marts for risk prioritization, exploitation trends, and vendor reporting.

## Production improvements planned

Incremental cursor and overlap window, cloud-volume landing paths, raw response metadata, Delta MERGE idempotency, schema drift alerts, source-specific quarantine datasets, quality checks, and Databricks Jobs orchestration. Avoid interpreting raw CVSS as direct exploitation probability.
