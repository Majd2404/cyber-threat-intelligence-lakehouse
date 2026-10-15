
import argparse
import json
from pathlib import Path

from src.transformation.gold import build_gold


def main():
    parser = argparse.ArgumentParser(description="Build Gold analytics.")
    parser.add_argument("--input", default="data/silver")
    parser.add_argument("--output", default="data/gold")
    args = parser.parse_args()

    result = build_gold(Path(args.input), Path(args.output))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
