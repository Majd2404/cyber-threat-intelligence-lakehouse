
import json
from collections import Counter
from pathlib import Path


def main():
    path = Path("data/gold/vulnerability_intelligence.jsonl")

    if not path.exists():
        print(f"Gold dataset not found: {path}")
        print("Run: python -m src.transformation.gold_run")
        return

    with path.open(encoding="utf-8") as file:
        records = [
            json.loads(line)
            for line in file
            if line.strip()
        ]

    print(f"Total Gold records: {len(records)}")

    source_fields = (
        "has_nvd_data",
        "has_kev_data",
        "has_epss_data",
    )

    for field in source_fields:
        counts = Counter(record.get(field, False) for record in records)
        print(f"\n{field}:")
        for value, count in sorted(counts.items()):
            print(f"  {value}: {count}")

    print("\nPriority distribution:")
    priorities = Counter(
        record.get("priority", "UNKNOWN")
        for record in records
    )
    for priority, count in sorted(priorities.items()):
        print(f"  {priority}: {count}")

    all_sources = sum(
        all(record.get(field, False) for field in source_fields)
        for record in records
    )
    print(f"\nRecords with all three sources: {all_sources}")


if __name__ == "__main__":
    main()
