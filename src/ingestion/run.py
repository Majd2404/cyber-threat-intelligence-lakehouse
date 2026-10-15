"""Raw JSONL landing area, usable locally or as a Databricks source."""
from __future__ import annotations
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from .clients import (
    fetch_nvd,
    fetch_nvd_by_cve_ids,
    fetch_kev,
    fetch_epss,
)
ROOT = Path(__file__).resolve().parents[2]
SAMPLES = ROOT / "data" / "samples"


def load_sample(name: str) -> list[dict]:
    return json.loads((SAMPLES / f"{name}.json").read_text(encoding="utf-8"))


def write_jsonl(records: list[dict], path: Path, source: str, ingested_at: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as output:
        for record in records:
            output.write(json.dumps({"source": source, "ingested_at": ingested_at, "payload": record}, ensure_ascii=False) + "\n")


def main(argv: list[str] | None = None) -> dict[str, int]:
    parser = argparse.ArgumentParser(description="Land raw threat-intelligence records")
    parser.add_argument("--mode", choices=["sample", "live"], default="sample")
    parser.add_argument("--start", default="2026-09-01", help="NVD publication start YYYY-MM-DD")
    parser.add_argument("--end", default="2026-09-03", help="NVD publication end YYYY-MM-DD")
    parser.add_argument("--limit", type=int, default=100, help="Maximum NVD records for live runs")
    parser.add_argument("--output", type=Path, default=ROOT / "data" / "raw")
    args = parser.parse_args(argv)
    if args.mode == "sample":
        nvd, kev, epss = (load_sample(name) for name in ("nvd", "kev", "epss"))
   
    
    else:
        # Keep the original date-filtered NVD dataset.
        nvd_window = fetch_nvd(
            args.start,
            args.end,
            max_records=args.limit,
        )

        # Retrieve the full current KEV catalog.
        kev = fetch_kev()

        kev_ids = [
            item["cveID"]
            for item in kev
            if item.get("cveID")
        ]

        # Enrich KEV CVEs with NVD details.
        nvd_kev = fetch_nvd_by_cve_ids(kev_ids)

        # Merge both NVD datasets, keeping one record per CVE.
        nvd_by_id = {}

        for item in nvd_window + nvd_kev:
            cve_id = item.get("cve", {}).get("id")
            if cve_id:
                nvd_by_id[cve_id] = item

        nvd = [
            nvd_by_id[cve_id]
            for cve_id in sorted(nvd_by_id)
        ]

        # Query EPSS for all NVD and KEV CVEs.
        nvd_ids = list(nvd_by_id)
        ids = sorted(set(nvd_ids + kev_ids))
        epss = fetch_epss(ids)


    timestamp = datetime.now(timezone.utc).isoformat()
    counts = {}
    for source, items in (("nvd", nvd), ("kev", kev), ("epss", epss)):
        write_jsonl(items, args.output / f"{source}.jsonl", source, timestamp)
        counts[source] = len(items)
    print(json.dumps({"mode": args.mode, "output": str(args.output), "counts": counts}, indent=2))
    return counts


if __name__ == "__main__":
    main()
