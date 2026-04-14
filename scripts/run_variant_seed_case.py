#!/usr/bin/env python3

from __future__ import annotations

import argparse
import asyncio
import json
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Dict

ROOT_DIR = Path(__file__).resolve().parent.parent

import sys

sys.path.append(str(ROOT_DIR))

from src.variant_benchmark import DEFAULT_PILOT_MANIFEST_PATH, load_pilot_benchmark


def _to_jsonable(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if is_dataclass(value):
        return {k: _to_jsonable(v) for k, v in asdict(value).items()}
    if isinstance(value, dict):
        return {str(k): _to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_jsonable(v) for v in value]
    return value


def build_seed_case_plan(seed_case, query_path: Path, include_seed: bool = True) -> Dict[str, Any]:
    targets = []
    runnable_target_count = 0
    for target in seed_case.evaluation_targets(include_seed=include_seed):
        sample = target.sample
        vuln_ready = (
            sample.local_paths.vuln_db_path is not None and sample.local_status.vuln_db_exists
        )
        fix_ready = (
            sample.local_paths.fix_db_path is not None and sample.local_status.fix_db_exists
        )
        target_plan = {
            "role": target.role,
            "cve_id": sample.cve_id,
            "family_id": sample.family_id,
            "project": sample.project,
            "variant_type": target.variant_type,
            "negative_type": target.negative_type,
            "construction_note": target.construction_note,
            "expected_vuln_hit": target.expected_vuln_hit,
            "expected_fix_hit": target.expected_fix_hit,
            "ground_truth_files": list(sample.ground_truth_files),
            "ground_truth_methods": list(sample.ground_truth_methods),
            "local_paths": _to_jsonable(sample.local_paths),
            "local_status": _to_jsonable(sample.local_status),
            "runnable_for_execution": vuln_ready and fix_ready,
        }
        if target_plan["runnable_for_execution"]:
            runnable_target_count += 1
        targets.append(target_plan)

    return {
        "execution_mode": "dry-run",
        "query": {
            "path": str(query_path.resolve()),
            "exists": query_path.exists(),
            "name": query_path.name,
        },
        "seed_case": {
            "family_id": seed_case.family_id,
            "family_name": seed_case.family_name,
            "expected_cwe_ids": list(seed_case.expected_cwe_ids),
            "seed_cve_id": seed_case.seed.cve_id,
            "seed_project": seed_case.seed.project,
            "seed_note": seed_case.note,
            "seed_runnable": seed_case.runnable,
        },
        "targets": targets,
        "target_count": len(targets),
        "runnable_target_count": runnable_target_count,
    }


def format_seed_case_plan(plan: Dict[str, Any]) -> str:
    lines = [
        "Variant Seed Case Runner",
        f"Execution mode: {plan['execution_mode']}",
        f"Query: {plan['query']['path']}",
        f"Query exists: {plan['query']['exists']}",
        f"Seed: {plan['seed_case']['seed_cve_id']} ({plan['seed_case']['family_id']})",
        f"Family: {plan['seed_case']['family_name']}",
        f"Runnable seed: {plan['seed_case']['seed_runnable']}",
        (
            "Runnable targets: "
            f"{plan['runnable_target_count']}/{plan['target_count']}"
        ),
        "Targets:",
    ]

    for target in plan["targets"]:
        lines.append(
            "- "
            f"{target['role']}:{target['cve_id']} "
            f"expected(vuln={target['expected_vuln_hit']}, fix={target['expected_fix_hit']}) "
            f"runnable={target['runnable_for_execution']}"
        )

    return "\n".join(lines)


async def _execute_variant_case(
    seed_case,
    query_path: Path,
    output_dir: Path,
    include_seed: bool,
) -> Dict[str, Any]:
    from src.query_subagents_evaluation import run_query_on_variant_seed_case

    evaluation = await run_query_on_variant_seed_case(
        query_path=str(query_path.resolve()),
        seed_case=seed_case,
        output_dir=str(output_dir),
        include_seed=include_seed,
    )

    return {
        "summary": evaluation.summary,
        "seed_success": evaluation.seed_success,
        "positive_variant_hits": evaluation.positive_variant_hits,
        "positive_variant_total": evaluation.positive_variant_total,
        "variant_recall": evaluation.variant_recall,
        "negative_fp_count": evaluation.negative_fp_count,
        "negative_total": evaluation.negative_total,
        "negative_fp_rate": evaluation.negative_fp_rate,
        "skipped_targets": evaluation.skipped_targets,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Dry-run or execute one variant seed case.")
    parser.add_argument("--seed-cve", required=True, help="Seed CVE id, e.g. CVE-2019-10077")
    parser.add_argument("--query-path", required=True, help="Path to the CodeQL query file")
    parser.add_argument(
        "--manifest-path",
        default=str(DEFAULT_PILOT_MANIFEST_PATH),
        help="Path to pilot manifest JSON",
    )
    parser.add_argument(
        "--output-dir",
        default=str(ROOT_DIR / "output" / "variant_seed_runs"),
        help="Directory for dry-run plan files and later execution outputs",
    )
    parser.add_argument(
        "--no-include-seed",
        dest="include_seed",
        action="store_false",
        help="Do not include the seed itself in the target list",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually run query evaluation across the seed case targets",
    )
    parser.set_defaults(include_seed=True)

    args = parser.parse_args()

    query_path = Path(args.query_path)
    if not query_path.exists():
        raise FileNotFoundError(f"Query file does not exist: {query_path}")

    benchmark = load_pilot_benchmark(args.manifest_path)
    seed_case = benchmark.get_seed_case(args.seed_cve, require_runnable=True)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    plan = build_seed_case_plan(seed_case, query_path, include_seed=args.include_seed)
    plan_json_path = output_dir / "variant_seed_case_plan.json"
    plan_text_path = output_dir / "variant_seed_case_plan.txt"

    plan_json_path.write_text(json.dumps(plan, indent=2), encoding="utf-8")
    plan_text_path.write_text(format_seed_case_plan(plan), encoding="utf-8")

    print(format_seed_case_plan(plan))
    print(f"\nWrote dry-run plan to {plan_json_path}")

    if not args.execute:
        return 0

    execution_result = asyncio.run(
        _execute_variant_case(
            seed_case=seed_case,
            query_path=query_path,
            output_dir=output_dir,
            include_seed=args.include_seed,
        )
    )
    execution_json_path = output_dir / "variant_seed_case_execution.json"
    execution_text_path = output_dir / "variant_seed_case_execution.txt"
    execution_json_path.write_text(
        json.dumps(execution_result, indent=2),
        encoding="utf-8",
    )
    execution_text_path.write_text(execution_result["summary"], encoding="utf-8")
    print("\nExecution summary")
    print(execution_result["summary"])
    print(f"\nWrote execution results to {execution_json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
