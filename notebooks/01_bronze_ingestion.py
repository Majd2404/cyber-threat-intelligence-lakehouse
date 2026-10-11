# Databricks notebook source
# MAGIC %md
# MAGIC # Bronze — Load landing-zone JSONL into Delta
# MAGIC This notebook runs after `python -m src.ingestion.run`; upload `data/raw/*.jsonl` to a Unity Catalog volume.

# COMMAND ----------
# Set your own catalog/schema/volume, then run in Databricks workspace.
landing_path = "/Volumes/main/default/cti_raw"

# COMMAND ----------
for source in ("nvd", "kev", "epss"):
    df = spark.read.json(f"{landing_path}/{source}.jsonl")
    (df.write.format("delta")
       .mode("append")
       .saveAsTable(f"bronze_{source}"))
    print(source, df.count())
# Note: Phase 2 will add idempotent upserts, ingestion run IDs and schema controls.
