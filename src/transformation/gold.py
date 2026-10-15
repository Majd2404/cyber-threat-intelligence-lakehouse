
"""Build a unified Gold vulnerability intelligence dataset."""

from datetime import date
from pathlib import Path
from typing import Any

from src.transformation.silver import read_jsonl, write_jsonl


def parse_score(value: Any) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def build_gold(input_dir: Path, output_dir: Path) -> dict[str, int]:
    nvd_records = read_jsonl(input_dir / "nvd.jsonl")
    kev_records = read_jsonl(input_dir / "kev.jsonl")
    epss_records = read_jsonl(input_dir / "epss.jsonl")

    # One record per CVE in each source.
    nvd_by_cve = {r["cve_id"]: r for r in nvd_records if r.get("cve_id")}
    kev_by_cve = {r["cve_id"]: r for r in kev_records if r.get("cve_id")}

    # Keep the latest EPSS observation for each CVE.
    epss_by_cve = {}
    for record in epss_records:
        cve_id = record.get("cve_id")
        if not cve_id:
            continue

        previous = epss_by_cve.get(cve_id)
        if previous is None or (record.get("score_date") or "") > (
            previous.get("score_date") or ""
        ):
            epss_by_cve[cve_id] = record

    all_cves = (
        set(nvd_by_cve)
        | set(kev_by_cve)
        | set(epss_by_cve)
    )

    gold_records = []

    for cve_id in sorted(all_cves):
        nvd = nvd_by_cve.get(cve_id, {})
        kev = kev_by_cve.get(cve_id, {})
        epss = epss_by_cve.get(cve_id, {})

        cvss = parse_score(nvd.get("cvss_score"))
        epss_score = parse_score(epss.get("epss_score"))

        # A simple, explainable prioritization rule.
        if cve_id in kev_by_cve:
            priority = "CRITICAL"
        elif epss_score is not None and epss_score >= 0.5:
            priority = "HIGH"
        elif cvss is not None and cvss >= 9.0:
            priority = "HIGH"
        elif (
            (epss_score is not None and epss_score >= 0.1)
            or (cvss is not None and cvss >= 7.0)
        ):
            priority = "MEDIUM"
        else:
            priority = "LOW"

        gold_records.append({
            "cve_id": cve_id,
            "description": nvd.get("description"),
            "vendor": kev.get("vendor"),
            "product": kev.get("product"),
            "published_at": nvd.get("published_at"),
            "cvss_score": cvss,
            "severity": nvd.get("severity"),
            "epss_score": epss_score,
            "epss_percentile": parse_score(epss.get("epss_percentile")),
            "epss_score_date": epss.get("score_date"),
            "is_known_exploited": cve_id in kev_by_cve,
            "kev_date_added": kev.get("date_added"),
            "kev_due_date": kev.get("due_date"),
            "known_ransomware_campaign_use": kev.get(
                "known_ransomware_campaign_use"
            ),
            "priority": priority,
            "has_nvd_data": cve_id in nvd_by_cve,
            "has_kev_data": cve_id in kev_by_cve,
            "has_epss_data": cve_id in epss_by_cve,
        })

    write_jsonl(output_dir / "vulnerability_intelligence.jsonl", gold_records)

    return {
        "nvd_records": len(nvd_records),
        "kev_records": len(kev_records),
        "epss_records": len(epss_records),
        "gold_records": len(gold_records),
        "known_exploited": sum(r["is_known_exploited"] for r in gold_records),
    }
