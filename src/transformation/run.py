
"""Run Bronze-to-Silver transformations."""

import argparse
import json
from pathlib import Path

from src.transformation.silver import transform


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Transform Bronze vulnerability data into Silver."
    )
    parser.add_argument("--input", default="data/raw")
    parser.add_argument("--output", default="data/silver")
    args = parser.parse_args()

    counts = transform(Path(args.input), Path(args.output))
    print(json.dumps({
        "status": "success",
        "output": args.output,
        "counts": counts,
    }, indent=2))


if __name__ == "__main__":
    main()
