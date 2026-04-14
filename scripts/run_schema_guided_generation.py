#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(ROOT_DIR / "src"))

from varql.agents.schema_guided_runner import (
    DEFAULT_OUTPUT_ROOT,
    build_run_plan,
    format_run_plan,
    run_schema_guided_generation,
    save_run_plan,
)
from varql.benchmark import DEFAULT_PILOT_MANIFEST_PATH


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run one schema-guided VarQL generation experiment for a pilot benchmark seed."
    )
    parser.add_argument("--seed-cve", required=True, help="Seed CVE to generate a query for.")
    parser.add_argument(
        "--manifest-path",
        default=str(DEFAULT_PILOT_MANIFEST_PATH),
        help="Path to pilot benchmark manifest.",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Optional output directory. Defaults under output/schema_guided_generation.",
    )
    parser.add_argument(
        "--agent",
        default="codex",
        choices=["claude", "gemini", "codex"],
        help="Agent backend to use.",
    )
    parser.add_argument(
        "--model",
        default="gpt-5.4",
        help="Model name to pass to the selected backend.",
    )
    parser.add_argument(
        "--ablation-mode",
        default="full",
        choices=["full", "no_tools", "no_lsp", "no_docs", "no_ast"],
        help="Backend ablation mode.",
    )
    parser.add_argument(
        "--skip-seen-variant-schemas",
        action="store_true",
        help="Build the prompt from the seed schema only.",
    )
    parser.add_argument(
        "--codex-use-local-config",
        action="store_true",
        help="Reuse local Codex CLI config when agent=codex.",
    )
    parser.add_argument(
        "--claude-use-local-config",
        action="store_true",
        help="Reuse local Claude Code CLI config when agent=claude.",
    )
    parser.add_argument(
        "--evaluate",
        action="store_true",
        help="After generation, run the query on the pilot benchmark seed case.",
    )
    parser.add_argument(
        "--no-include-seed",
        dest="include_seed_in_evaluation",
        action="store_false",
        help="When evaluating, exclude the seed itself from the benchmark execution.",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually run generation. Default behavior is dry-run.",
    )
    parser.set_defaults(include_seed_in_evaluation=True)
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    plan = build_run_plan(
        args.seed_cve,
        manifest_path=args.manifest_path,
        output_dir=args.output_dir if args.output_dir else None,
        agent=args.agent,
        model=args.model,
        ablation_mode=args.ablation_mode,
        include_seen_variant_schemas=not args.skip_seen_variant_schemas,
        codex_use_local_config=args.codex_use_local_config,
        claude_use_local_config=args.claude_use_local_config,
        evaluate=args.evaluate,
        include_seed_in_evaluation=args.include_seed_in_evaluation,
    )
    output_dir = Path(plan.output_dir)
    save_run_plan(plan, output_dir)

    if not args.execute:
        print("Execution mode: dry-run")
        print(format_run_plan(plan))
        return 0

    result = asyncio.run(
        run_schema_guided_generation(
            args.seed_cve,
            manifest_path=args.manifest_path,
            output_dir=output_dir,
            agent=args.agent,
            model=args.model,
            ablation_mode=args.ablation_mode,
            include_seen_variant_schemas=not args.skip_seen_variant_schemas,
            codex_use_local_config=args.codex_use_local_config,
            claude_use_local_config=args.claude_use_local_config,
            evaluate=args.evaluate,
            include_seed_in_evaluation=args.include_seed_in_evaluation,
        )
    )
    print(f"Execution mode: execute")
    print(f"Output dir: {result['output_dir']}")
    print(f"Query path: {result.get('query_path')}")
    print(f"Success: {result['success']}")
    if result.get("evaluation"):
        print("Evaluation: generated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
