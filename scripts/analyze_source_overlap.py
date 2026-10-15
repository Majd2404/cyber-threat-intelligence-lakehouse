
import json
from pathlib import Path


def load_cve_ids(path):
    ids = set()

    if not path.exists():
        print(f"Missing file: {path}")
        return ids

    with path.open(encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue

            record = json.loads(line)
            cve_id = record.get("cve_id")

            if cve_id:
                ids.add(cve_id)

    return ids


def main():
    base = Path("data/silver")

    nvd = load_cve_ids(base / "nvd.jsonl")
    kev = load_cve_ids(base / "kev.jsonl")
    epss = load_cve_ids(base / "epss.jsonl")

    print(f"NVD unique CVEs:  {len(nvd)}")
    print(f"KEV unique CVEs:  {len(kev)}")
    print(f"EPSS unique CVEs: {len(epss)}")

    print("\nPairwise overlap:")
    print(f"NVD ∩ KEV:  {len(nvd & kev)}")
    print(f"NVD ∩ EPSS: {len(nvd & epss)}")
    print(f"KEV ∩ EPSS: {len(kev & epss)}")

    print("\nOverlap across all three sources:")
    common = nvd & kev & epss
    print(f"All three: {len(common)}")

    if common:
        print("\nExample CVEs:")
        for cve_id in sorted(common)[:10]:
            print(f"  {cve_id}")


if __name__ == "__main__":
    main()
