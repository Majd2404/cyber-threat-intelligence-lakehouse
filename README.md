# Cyber Threat Intelligence Lakehouse

```{=html}
<p align="center">
```
`<strong>`{=html}A data engineering project for unified vulnerability
intelligence`</strong>`{=html}
```{=html}
</p>
```
```{=html}
<p align="center">
```
`<img src="https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white" alt="Python 3.12" />`{=html}
`<img src="https://img.shields.io/badge/Data%20Engineering-ETL-2496ED" alt="Data Engineering" />`{=html}
`<img src="https://img.shields.io/badge/Architecture-Medallion-16A34A" alt="Medallion Architecture" />`{=html}
`<img src="https://img.shields.io/badge/Tests-18%20passing-success" alt="18 passing tests" />`{=html}
`<img src="https://img.shields.io/badge/Status-Active%20Development-orange" alt="Active Development" />`{=html}
```{=html}
</p>
```
## Overview

**Cyber Threat Intelligence Lakehouse** is a data engineering project
that integrates vulnerability information from multiple public
cybersecurity sources into a unified, analysis-ready dataset.

The pipeline collects vulnerability records, validates and standardizes
their structure, removes duplicates, enriches records across sources,
and applies an explainable prioritization model.

It follows the **Medallion Architecture** --- Bronze, Silver, and Gold
--- using Python and JSON Lines for local processing, with a roadmap
toward Apache Spark, Delta Lake, and Databricks.

### Objectives

-   Build reproducible multi-source data ingestion.
-   Apply validation, normalization, and deduplication.
-   Integrate vulnerability intelligence using CVE identifiers.
-   Preserve source coverage and missing-source information.
-   Produce a unified Gold dataset for analysis.
-   Test ingestion and transformation logic automatically.

## Architecture

``` mermaid
flowchart TD
    A["NVD<br/>Vulnerability details"]
    B["CISA KEV<br/>Known exploited vulnerabilities"]
    C["FIRST EPSS<br/>Exploitation probability scores"]

    A --> D["Bronze<br/>Raw JSONL ingestion"]
    B --> D
    C --> D
    D --> E["Silver<br/>Normalization and validation"]
    E --> F["Gold<br/>Unified vulnerability intelligence"]
    F --> G["Priority classification"]
    F --> H["Source coverage analysis"]
    F --> I["Analysis-ready dataset"]
    J["Automated unit tests"] -.-> D
    J -.-> E
    J -.-> F
```

The current implementation uses Python and JSON Lines files. Spark,
Delta Lake, and Databricks are planned extensions, not part of the
current pipeline.

## Data sources

  --------------------------------------------------------------------------------------------------------------------
  Source                                                               Purpose                 Key information
  -------------------------------------------------------------------- ----------------------- -----------------------
  [NVD](https://nvd.nist.gov/)                                         National Vulnerability  CVE IDs, descriptions,
                                                                       Database                CVSS scores, severity,
                                                                                               publication metadata

  [CISA                                                                Known Exploited         Known exploitation,
  KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)   Vulnerabilities         vendor/product details,
                                                                                               remediation dates

  [FIRST EPSS](https://www.first.org/epss/)                            Exploit Prediction      EPSS scores,
                                                                       Scoring System          percentiles, score
                                                                                               dates
  --------------------------------------------------------------------------------------------------------------------

**CVE ID** is the primary key used to correlate records across sources.
NVD provides vulnerability characteristics, KEV identifies
vulnerabilities known to be exploited, and EPSS estimates exploitation
probability.

## Data engineering workflow

### 1. Bronze --- Raw ingestion

The ingestion layer retrieves source data and writes JSON Lines files.

Implemented capabilities:

-   NVD retrieval with configurable publication-date windows and record
    limits.
-   CISA KEV catalog collection.
-   EPSS retrieval for relevant CVE identifiers.
-   Sample mode for repeatable local development.
-   Live mode for current source data.
-   Request batching and retry handling in ingestion clients.

Output:

``` text
data/raw/
├── nvd.jsonl
├── kev.jsonl
└── epss.jsonl
```

### 2. Silver --- Standardization and data quality

Silver transforms source records into consistent, structured datasets.

Implemented transformations:

-   CVE identifier normalization.
-   Extraction of relevant source fields.
-   Record deduplication.
-   EPSS score and percentile validation.
-   Rejection of invalid or out-of-range EPSS values.
-   Separate output files for each source.

Output:

``` text
data/silver/
├── nvd.jsonl
├── kev.jsonl
└── epss.jsonl
```

### 3. Gold --- Unified vulnerability intelligence

Gold integrates the Silver datasets into one analytical dataset.

Implemented capabilities:

-   Joins records using CVE identifiers.
-   Preserves CVEs even when information is missing from a source.
-   Selects the latest available EPSS observation per CVE.
-   Combines technical severity, exploitation evidence, and probability
    scores.
-   Tracks source presence with `has_nvd_data`, `has_kev_data`, and
    `has_epss_data`.
-   Assigns a custom, explainable vulnerability priority.

Output:

``` text
data/gold/
└── vulnerability_intelligence.jsonl
```

### Example Gold record

The following is an illustrative example, not a claim about a specific
live CVE.

``` json
{
  "cve_id": "CVE-2025-1001",
  "description": "Illustrative vulnerability description",
  "cvss_score": 8.5,
  "severity": "HIGH",
  "epss_score": 0.42,
  "epss_percentile": 0.91,
  "is_known_exploited": true,
  "priority": "HIGH",
  "has_nvd_data": true,
  "has_kev_data": true,
  "has_epss_data": true
}
```

The actual Gold output also contains available publication metadata,
vendor/product information, EPSS dates, KEV-related fields, and other
fields extracted by the transformation code.

## Vulnerability prioritization

The project implements a custom rule-based prioritization model.

  -----------------------------------------------------------------------
  Priority                            Rule
  ----------------------------------- -----------------------------------
  **CRITICAL**                        CVSS score is at least 9.0

  **HIGH**                            Known exploited, or EPSS score is
                                      at least 0.5

  **MEDIUM**                          CVSS score is at least 7.0, or EPSS
                                      score is at least 0.1

  **LOW**                             None of the preceding conditions
                                      apply
  -----------------------------------------------------------------------

Rules are evaluated in order; the first matching rule determines
priority.

> **Important:** This is a project-specific prioritization model, not an
> official CVSS classification. CVSS severity and remediation priority
> are separate because technical severity and observed or predicted
> exploitation are different signals.

## Current implementation snapshot

These metrics come from a successful development run. They are a
snapshot, not a continuously refreshed production service.

  Metric                                 Result
  -------------------------------- ------------
  Gold vulnerability records              1,846
  Records with NVD data                   1,846
  Records with KEV data                   1,746
  Records with EPSS data                  1,846
  Records with all three sources          1,746
  Automated unit tests               18 passing

### Priority distribution

  Priority        Records
  ----------- -----------
  CRITICAL            643
  HIGH              1,116
  MEDIUM               27
  LOW                  60
  **Total**     **1,846**

Counts will change as source data and prioritization rules evolve.

## Project structure

``` text
cyber-threat-intelligence-lakehouse/
├── src/
│   ├── ingestion/
│   │   ├── clients.py
│   │   └── run.py
│   └── transformation/
│       ├── silver.py
│       ├── run.py
│       ├── gold.py
│       └── gold_run.py
├── tests/
│   ├── test_ingestion.py
│   ├── test_transformation.py
│   └── test_gold.py
├── scripts/
│   ├── analyze_gold.py
│   └── analyze_source_overlap.py
├── data/
│   ├── samples/
│   ├── raw/
│   ├── silver/
│   └── gold/
├── .gitignore
├── README.md
└── requirements.txt
```

Generated data files may be excluded from version control.

## Getting started

### Prerequisites

-   Python 3.12 or a compatible Python 3 version.
-   Git.
-   Internet connectivity for live ingestion.

### 1. Clone the repository

``` bash
git clone https://github.com/Majd2404/cyber-threat-intelligence-lakehouse.git
cd cyber-threat-intelligence-lakehouse
```

If the repository URL differs, use the clone URL displayed on your
GitHub page.

### 2. Create and activate a virtual environment

``` bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

``` bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Run sample ingestion

``` bash
python -m src.ingestion.run --mode sample
```

Sample mode uses the project's small sample datasets rather than
downloading the full live catalogs.

### 5. Transform Bronze data into Silver

``` bash
python -m src.transformation.run
```

### 6. Build the Gold dataset

``` bash
python -m src.transformation.gold_run
```

### 7. Analyze the results

``` bash
python scripts/analyze_gold.py
python scripts/analyze_source_overlap.py
```

**Execution order:** ingestion → Silver transformation → Gold
transformation → analysis.

## Live ingestion

Example live run for an NVD publication window:

``` bash
python -m src.ingestion.run \
  --mode live \
  --start 2026-09-01 \
  --end 2026-09-03 \
  --limit 100
```

Adjust the dates and limit for your experiment. The workflow also
retrieves the KEV catalog and enriches relevant CVEs with NVD and EPSS
data, so the final dataset can contain more records than the NVD
window's `--limit`.

An optional NVD API key can be provided through the `NVD_API_KEY`
environment variable, subject to NVD's current usage policies:

``` bash
export NVD_API_KEY="your_api_key"
```

Never commit API keys or other secrets to Git.

## Testing and data quality

Run the full test suite:

``` bash
python -m unittest discover -s tests -v
```

The current suite contains 18 passing tests covering:

-   NVD pagination and date-window validation.
-   EPSS request identifier deduplication.
-   Sample ingestion across all three sources.
-   CVE normalization and source extraction.
-   Invalid and out-of-range EPSS values.
-   Silver-layer deduplication.
-   Gold-layer integration across sources.
-   Missing-source handling.
-   Latest EPSS observation selection.
-   Priority rules and KEV-driven prioritization.

## Design decisions

### Why JSON Lines?

JSONL is lightweight and inspectable for local development. Each line
represents one record, allowing straightforward processing without
requiring a database or distributed cluster.

### Why CVE IDs?

CVE identifiers provide a common key across the three datasets and
enable the Gold layer to consolidate related information.

### Why preserve missing-source information?

A missing record in one source should not cause a vulnerability to
disappear from the unified dataset. Source-presence flags help
distinguish incomplete source coverage from a negative finding.

### Why separate severity from priority?

CVSS describes technical severity, while KEV and EPSS contribute
exploitation context. Keeping these concepts separate makes
prioritization easier to explain, test, and refine.

### Why develop locally first?

Local Python development enables rapid iteration and repeatable tests
before adding the complexity of a distributed processing environment.

## Roadmap

The project is being developed incrementally. The current Python
implementation is the baseline.

-   [x] Multi-source ingestion for NVD, KEV, and EPSS.
-   [x] Sample mode for local development.
-   [x] Silver transformations and validation.
-   [x] Unified Gold dataset.
-   [x] Explainable vulnerability prioritization.
-   [x] Automated unit tests.
-   [x] Gold analysis and source-overlap scripts.
-   [ ] Improve logging, configuration, and ingestion observability.
-   [ ] Introduce incremental processing where appropriate.
-   [ ] Implement PySpark transformations.
-   [ ] Evaluate Delta Lake tables and transactional writes.
-   [ ] Port the pipeline to Databricks.
-   [ ] Add scheduled orchestration and pipeline monitoring.
-   [ ] Expand data-quality checks and integration tests.

Unchecked items are planned enhancements, not existing capabilities.

## Technologies

**Currently used**

-   Python
-   REST APIs and JSON
-   JSON Lines
-   Standard-library HTTP and filesystem processing
-   `unittest`
-   Git and GitHub

**Planned or under evaluation**

-   Apache Spark / PySpark
-   Delta Lake
-   Databricks
-   SQL-based analytics
-   Incremental ingestion and orchestration

## Data sources and attribution

This project uses publicly available cybersecurity data from NVD, CISA,
and FIRST EPSS. Consult each source's official documentation and terms
for current access policies, attribution, and permitted use.

-   NVD: https://nvd.nist.gov/
-   CISA KEV:
    https://www.cisa.gov/known-exploited-vulnerabilities-catalog
-   FIRST EPSS: https://www.first.org/epss/

This is an independent educational and portfolio project. It is not an
official product of NVD, CISA, FIRST, Databricks, or any other source
organization.

## Author

**Majd Machlouch**

Data Engineering \| Python \| SQL \| Apache Spark \| Databricks

GitHub: [@Majd2404](https://github.com/Majd2404)

------------------------------------------------------------------------

```{=html}
<p align="center">
```
Built with a focus on reliable ingestion, data quality, traceable
transformations, and explainable vulnerability intelligence.
```{=html}
</p>
```