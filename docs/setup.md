# Quick start

Requirements: Python 3.10+; **no pip packages required for Phase 1**.

```bash
python3 -m src.ingestion.run --mode sample
python3 -m unittest discover -s tests -v
```

Generated raw files live at `data/raw/{nvd,kev,epss}.jsonl` (ignored by git).

Live run, optional NVD key:

```bash
export NVD_API_KEY="YOUR_KEY"  # optional
python3 -m src.ingestion.run --mode live --start 2026-09-01 --end 2026-09-03 --limit 100
```

The live run uses the network and may hit source rate limits. The NVD date range must be ≤120 days. CISA KEV download contains the whole catalog; EPSS query covers only the retrieved NVD CVEs.

## Databricks

1. Create/select a Unity Catalog volume and upload the generated `data/raw/*.jsonl` files.
2. Set `landing_path` in `notebooks/01_bronze_ingestion.py` to that volume path.
3. Create or select a writable schema, then import and run the notebook.
4. Phase 1 notebook appends data and is **not idempotent**; for a repeatable workflow we will replace it with Delta MERGE in Phase 2.
