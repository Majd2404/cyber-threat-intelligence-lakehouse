
"""Transform Bronze JSONL vulnerability records into clean Silver datasets."""

import json
from pathlib import Path
from typing import Any


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    """Read JSONL records and skip malformed lines."""
    records = []

    if not path.exists():
        return records

    with path.open(encoding="utf-8") as file:
        for line in file:
            try:
                record = json.loads(line)
                if isinstance(record, dict):
                    records.append(record)
            except json.JSONDecodeError:
                continue

    return records


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    """Write records as UTF-8 JSON Lines."""
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        for record in records:
            file.write(json.dumps(record, ensure_ascii=False) + "\n")


def normalize_cve(value: Any) -> str | None:
    """Normalize and validate a CVE identifier."""
    if not isinstance(value, str):
        return None

    cve = value.strip().upper()

    import re
    if re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
        return cve

    return None


def extract_nvd(record: dict[str, Any]) -> dict[str, Any] | None:
    """Extract a consistent set of fields from an NVD Bronze record."""
    cve = record.get("payload", {}).get("cve", {})
    cve_id = normalize_cve(cve.get("id"))

    if not cve_id:
        return None

    descriptions = cve.get("descriptions") or []
    description = next(
        (
            item.get("value")
            for item in descriptions
            if item.get("lang") == "en" and item.get("value")
        ),
        None,
    )

    metrics = cve.get("metrics") or {}
    cvss_score = None
    severity = None

    # Prefer the newest available CVSS version.
    for metric_key in (
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ):
        entries = metrics.get(metric_key) or []
        if not entries:
            continue

        cvss_data = entries[0].get("cvssData") or {}
        cvss_score = cvss_data.get("baseScore")
        severity = (
            entries[0].get("baseSeverity")
            or cvss_data.get("baseSeverity")
        )
        break

    weaknesses = []
    for weakness in cve.get("weaknesses") or []:
        for item in weakness.get("description") or []:
            if item.get("lang") == "en" and item.get("value"):
                weaknesses.append(item["value"])

    return {
        "cve_id": cve_id,
        "description": description,
        "published_at": cve.get("published"),
        "last_modified_at": cve.get("lastModified"),
        "status": cve.get("vulnStatus"),
        "cvss_score": cvss_score,
        "severity": severity.upper() if severity else None,
        "weaknesses": sorted(set(weaknesses)),
    }


def extract_kev(record: dict[str, Any]) -> dict[str, Any] | None:
    """Extract a consistent set of fields from a CISA KEV record."""
    payload = record.get("payload") or {}
    cve_id = normalize_cve(payload.get("cveID"))

    if not cve_id:
        return None

    return {
        "cve_id": cve_id,
        "vendor": payload.get("vendorProject"),
        "product": payload.get("product"),
        "vulnerability_name": (
            payload.get("vulnerabilityName", "").strip() or None
        ),
        "date_added": payload.get("dateAdded"),
        "due_date": payload.get("dueDate"),
        "known_ransomware_campaign_use": payload.get(
            "knownRansomwareCampaignUse"
        ),
        "required_action": payload.get("requiredAction"),
    }


def extract_epss(record: dict[str, Any]) -> dict[str, Any] | None:
    """Extract EPSS scores and validate their numeric ranges."""
    payload = record.get("payload") or {}
    cve_id = normalize_cve(payload.get("cve"))

    if not cve_id:
        return None

    try:
        score = float(payload["epss"])
        percentile = float(payload["percentile"])
    except (KeyError, TypeError, ValueError):
        return None

    if not (0 <= score <= 1 and 0 <= percentile <= 1):
        return None

    return {
        "cve_id": cve_id,
        "epss_score": score,
        "epss_percentile": percentile,
        "score_date": payload.get("date"),
    }


def deduplicate(
    records: list[dict[str, Any]],
    key_fields: tuple[str, ...],
) -> list[dict[str, Any]]:
    """Keep the last record for each natural key."""
    unique = {}

    for record in records:
        key = tuple(record.get(field) for field in key_fields)
        unique[key] = record

    return list(unique.values())


def transform(input_dir: Path, output_dir: Path) -> dict[str, int]:
    """Build the three Silver datasets from Bronze JSONL files."""
    nvd = [
        result
        for record in read_jsonl(input_dir / "nvd.jsonl")
        if (result := extract_nvd(record)) is not None
    ]
    kev = [
        result
        for record in read_jsonl(input_dir / "kev.jsonl")
        if (result := extract_kev(record)) is not None
    ]
    epss = [
        result
        for record in read_jsonl(input_dir / "epss.jsonl")
        if (result := extract_epss(record)) is not None
    ]

    nvd = deduplicate(nvd, ("cve_id",))
    kev = deduplicate(kev, ("cve_id",))
    epss = deduplicate(epss, ("cve_id", "score_date"))

    write_jsonl(output_dir / "nvd.jsonl", nvd)
    write_jsonl(output_dir / "kev.jsonl", kev)
    write_jsonl(output_dir / "epss.jsonl", epss)

    return {
        "nvd": len(nvd),
        "kev": len(kev),
        "epss": len(epss),
    }
