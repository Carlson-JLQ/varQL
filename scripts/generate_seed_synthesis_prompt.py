#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(ROOT_DIR / "src"))

from varql.config import BENCHMARK_ROOT
from varql.synthesis.prompt_builder import build_prompt_context, save_prompt


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate a schema-guided synthesis prompt for one pilot benchmark seed."
    )
    parser.add_argument("--seed-cve", required=True, help="Seed CVE to build the prompt for.")
    parser.add_argument(
        "--manifest-path",
        default=None,
        help="Optional override for the pilot benchmark manifest path.",
    )
    parser.add_argument(
        "--qlcoder-output-root",
        default=None,
        help="Optional override for the external QLCoder output root used for phase1 evidence.",
    )
    parser.add_argument(
        "--skip-seen-variant-schemas",
        action="store_true",
        help="Only use the seed schema when deriving the family prompt context.",
    )
    parser.add_argument(
        "--output-path",
        default=None,
        help="Where to save the rendered prompt. Defaults under benchmarks/prompts.",
    )
    return parser


def default_output_path(seed_cve: str) -> Path:
    return BENCHMARK_ROOT / "prompts" / f"{seed_cve}.synthesis_prompt.md"


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    context = build_prompt_context(
        args.seed_cve,
        benchmark_manifest_path=args.manifest_path,
        qlcoder_output_root=args.qlcoder_output_root if args.qlcoder_output_root else None,
        include_seen_variant_schemas=not args.skip_seen_variant_schemas,
    )
    prompt = context.build_prompt()
    output_path = Path(args.output_path) if args.output_path else default_output_path(args.seed_cve)
    saved = save_prompt(prompt, output_path)
    print(saved)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
