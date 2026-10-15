"""Public intelligence ingestion clients. Standard library only."""
from __future__ import annotations
import json
import os
import time
import urllib.parse
import urllib.request
from datetime import date

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"


def fetch_json(url: str, params: dict | None = None, retries: int = 3) -> dict:
    if params:
        url += "?" + urllib.parse.urlencode(params)
    headers = {"User-Agent": "CyberThreatLakehouse/0.1 (educational project)"}
    if url.startswith(NVD_URL) and os.getenv("NVD_API_KEY"):
        headers["apiKey"] = os.environ["NVD_API_KEY"]
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=40) as response:
                return json.load(response)
        except (OSError, ValueError) as exc:
            if attempt == retries - 1:
                raise RuntimeError(f"Request failed after {retries} attempts: {url}") from exc
            time.sleep(min(2 ** attempt, 8))
    raise AssertionError("unreachable")


def fetch_nvd(start: str, end: str, page_size: int = 200, max_records: int = 1000) -> list[dict]:
    """Retrieve a bounded published-date interval (max 120 days), with pagination."""
    first, last = date.fromisoformat(start), date.fromisoformat(end)
    if last < first or (last - first).days > 120:
        raise ValueError("NVD date window must be ascending and no longer than 120 days")
    if page_size < 1 or page_size > 2000 or max_records < 1:
        raise ValueError("Invalid pagination arguments")
    records, index = [], 0
    while len(records) < max_records:
        batch = fetch_json(NVD_URL, {
            "pubStartDate": start + "T00:00:00.000",
            "pubEndDate": end + "T23:59:59.999",
            "resultsPerPage": min(page_size, max_records - len(records)),
            "startIndex": index,
        })
        items = batch.get("vulnerabilities", [])
        records.extend(items)
        index += len(items)
        if not items or index >= batch.get("totalResults", 0):
            break
        time.sleep(6 if not os.getenv("NVD_API_KEY") else 0.7)
    return records




def fetch_nvd_by_cve_ids(
    cve_ids: list[str],
    batch_size: int = 100,
) -> list[dict]:
    """Fetch NVD details for specific CVEs in rate-limited batches."""
    if not 1 <= batch_size <= 100:
        raise ValueError("batch_size must be between 1 and 100")

    unique_ids = sorted(set(cve_ids))
    records = []
    delay = 0.7 if os.getenv("NVD_API_KEY") else 6.0

    for offset in range(0, len(unique_ids), batch_size):
        batch = unique_ids[offset:offset + batch_size]

        response = fetch_json(
            NVD_URL,
            {
                "cveIds": ",".join(batch),
                "resultsPerPage": 2000,
            },
        )

        records.extend(response.get("vulnerabilities", []))

        if offset + batch_size < len(unique_ids):
            time.sleep(delay)

    # Deduplicate by CVE ID in case the API returns repeated records.
    by_id = {
        item["cve"]["id"]: item
        for item in records
        if item.get("cve", {}).get("id")
    }

    return [by_id[cve_id] for cve_id in sorted(by_id)]


def fetch_kev() -> list[dict]:
    return fetch_json(KEV_URL)["vulnerabilities"]


def fetch_epss(cve_ids: list[str]) -> list[dict]:
    """Query EPSS in small batches to remain under the 2000-char CVE param limit."""
    unique = sorted(set(cve_ids))
    output = []
    for offset in range(0, len(unique), 50):
        output.extend(fetch_json(EPSS_URL, {"cve": ",".join(unique[offset:offset + 50])}).get("data", []))
    return output
