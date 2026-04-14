#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(ROOT_DIR / "src"))

from varql.schema_extraction import build_seed_schema, save_schema


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract a minimal schema IR for one seed CVE.")
    parser.add_argument("--cve-id", required=True, help="Seed CVE id, for example CVE-2019-10077")
    parser.add_argument(
        "--output-path",
        help="Optional path to write the schema JSON. Defaults to benchmarks/schemas/<CVE>.json",
    )
    args = parser.parse_args()

    schema = build_seed_schema(args.cve_id)
    output_path = Path(args.output_path) if args.output_path else (
        ROOT_DIR / "benchmarks" / "schemas" / f"{args.cve_id}.schema.json"
    )
    save_schema(schema, output_path)

    print(f"Saved schema for {args.cve_id} to {output_path}")
    print(json.dumps(schema.to_dict(), indent=2)[:1200])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
