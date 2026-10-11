# Data sources and provenance

| Source | URL | Data | Update behavior |
|---|---|---|---|
| NVD CVE 2.0 | https://nvd.nist.gov/developers/vulnerabilities | CVE, CVSS, description, dates | Query a bounded publication window; use modification dates for production incremental ingestion |
| CISA KEV | https://github.com/cisagov/kev-data | Known exploited CVEs | Catalog updated by CISA as new information arrives |
| FIRST EPSS | https://api.first.org/epss/ | Exploitation probability and percentile | Daily scores; historical as-of date should be tracked |

## Keys and caveats

- Join on CVE ID, keeping records not present in KEV/EPSS via left joins.
- EPSS probabilities change over time: store `date` as a part of its natural key.
- NVD CVSS may have multiple metric versions; select and document a priority rule.
- Sample fixtures are **illustrative, not authoritative snapshots**; EPSS values are fabricated to exercise the pipeline.
- Credit CISA, NIST, and FIRST as the original data providers. Respect their terms, usage guidance, and request limits.
- The complete EPSS daily CSV is available from https://www.first.org/epss/data.html if bulk processing is later needed.
