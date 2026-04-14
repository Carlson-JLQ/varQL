#!/usr/bin/env python3

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(ROOT_DIR))

from src.variant_benchmark import DEFAULT_PILOT_MANIFEST_PATH, load_pilot_benchmark
from scripts.run_variant_seed_case import build_seed_case_plan


def _resolve_query_path(raw_path: Optional[str], base_dir: Path) -> Optional[Path]:
    if not raw_path:
        return None

    candidate = Path(raw_path).expanduser()
    possible_paths = []
    if candidate.is_absolute():
        possible_paths.append(candidate)
    else:
        possible_paths.append((base_dir / candidate).resolve())
        possible_paths.append((base_dir / candidate.name).resolve())

    for path in possible_paths:
        if path.exists():
            return path.resolve()
    return None


def load_query_map(path: Path) -> Dict[str, Path]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    query_map: Dict[str, Path] = {}
    for cve_id, query_path in raw.items():
        resolved = _resolve_query_path(str(query_path), path.parent)
        if resolved is not None:
            query_map[cve_id] = resolved
    return query_map


def discover_queries_from_analysis_root(analysis_root: Path) -> Dict[str, Path]:
    discovered: Dict[str, tuple[float, Path]] = {}

    for metadata_path in analysis_root.rglob("iterative_metadata.json"):
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except Exception:
            continue

        analysis_metadata = metadata.get("analysis_metadata", {})
        cve_id = analysis_metadata.get("cve_id")
        if not cve_id:
            continue

        results_dir = metadata_path.parent
        query_path = None

        for iteration in reversed(analysis_metadata.get("iterations", [])):
            query_path = _resolve_query_path(iteration.get("query_path"), results_dir)
            if query_path is not None:
                break

        if query_path is None:
            for filename in reversed(metadata.get("file_inventory", {}).get("query_files", [])):
                query_path = _resolve_query_path(filename, results_dir)
                if query_path is not None:
                    break

        if query_path is None:
            continue

        mtime = metadata_path.stat().st_mtime
        previous = discovered.get(cve_id)
        if previous is None or mtime >= previous[0]:
            discovered[cve_id] = (mtime, query_path)

    return {cve_id: query_path for cve_id, (_, query_path) in discovered.items()}


def _select_seed_cases(benchmark, seed_cves: Iterable[str], family_id: Optional[str]) -> list:
    selected = []
    requested = {cve_id for cve_id in seed_cves if cve_id}
    if requested:
        for cve_id in sorted(requested):
            case = benchmark.get_seed_case(cve_id, require_runnable=True)
            if family_id and case.family_id != family_id:
                continue
            selected.append(case)
        return selected
    return list(benchmark.list_seed_cases(runnable_only=True, family_id=family_id))


def _aggregate_results(seed_results: list[Dict[str, Any]]) -> Dict[str, Any]:
    planned = len(seed_results)
    with_queries = [result for result in seed_results if result.get("query", {}).get("exists")]
    executed = [result for result in seed_results if result.get("execution") is not None]

    positive_hits = sum(result.get("execution", {}).get("positive_variant_hits", 0) for result in executed)
    positive_total = sum(result.get("execution", {}).get("positive_variant_total", 0) for result in executed)
    negative_fp_count = sum(result.get("execution", {}).get("negative_fp_count", 0) for result in executed)
    negative_total = sum(result.get("execution", {}).get("negative_total", 0) for result in executed)
    seed_success_count = sum(1 for result in executed if result.get("execution", {}).get("seed_success"))
    skipped_targets = sum(result.get("execution", {}).get("skipped_targets", 0) for result in executed)

    family_breakdown: Dict[str, Dict[str, Any]] = {}
    for result in seed_results:
        family_id = result["seed_case"]["family_id"]
        breakdown = family_breakdown.setdefault(
            family_id,
            {
                "planned_seed_cases": 0,
                "query_available_seed_cases": 0,
                "executed_seed_cases": 0,
                "seed_success_count": 0,
                "positive_variant_hits": 0,
                "positive_variant_total": 0,
                "negative_fp_count": 0,
                "negative_total": 0,
            },
        )
        breakdown["planned_seed_cases"] += 1
        if result.get("query", {}).get("exists"):
            breakdown["query_available_seed_cases"] += 1
        if result.get("execution") is not None:
            execution = result["execution"]
            breakdown["executed_seed_cases"] += 1
            breakdown["seed_success_count"] += int(bool(execution.get("seed_success")))
            breakdown["positive_variant_hits"] += execution.get("positive_variant_hits", 0)
            breakdown["positive_variant_total"] += execution.get("positive_variant_total", 0)
            breakdown["negative_fp_count"] += execution.get("negative_fp_count", 0)
            breakdown["negative_total"] += execution.get("negative_total", 0)

    for breakdown in family_breakdown.values():
        total = breakdown["positive_variant_total"]
        neg_total = breakdown["negative_total"]
        breakdown["variant_recall_micro"] = (
            breakdown["positive_variant_hits"] / total if total else 0.0
        )
        breakdown["negative_fp_rate_micro"] = (
            breakdown["negative_fp_count"] / neg_total if neg_total else 0.0
        )

    return {
        "planned_seed_cases": planned,
        "query_available_seed_cases": len(with_queries),
        "query_missing_seed_cases": planned - len(with_queries),
        "executed_seed_cases": len(executed),
        "seed_success_count": seed_success_count,
        "positive_variant_hits": positive_hits,
        "positive_variant_total": positive_total,
        "variant_recall_micro": positive_hits / positive_total if positive_total else 0.0,
        "negative_fp_count": negative_fp_count,
        "negative_total": negative_total,
        "negative_fp_rate_micro": negative_fp_count / negative_total if negative_total else 0.0,
        "skipped_targets": skipped_targets,
        "family_breakdown": family_breakdown,
    }


def _format_summary(summary: Dict[str, Any], mode: str) -> str:
    lines = [
        "Pilot Benchmark Runner",
        f"Execution mode: {mode}",
        f"Planned seed cases: {summary['planned_seed_cases']}",
        f"Query-available seed cases: {summary['query_available_seed_cases']}",
        f"Query-missing seed cases: {summary['query_missing_seed_cases']}",
        f"Executed seed cases: {summary['executed_seed_cases']}",
        f"Seed success count: {summary['seed_success_count']}",
        (
            "Positive variant recall (micro): "
            f"{summary['positive_variant_hits']}/{summary['positive_variant_total']} "
            f"({summary['variant_recall_micro']:.2f})"
        ),
        (
            "Negative FP rate (micro): "
            f"{summary['negative_fp_count']}/{summary['negative_total']} "
            f"({summary['negative_fp_rate_micro']:.2f})"
        ),
        f"Skipped targets: {summary['skipped_targets']}",
    ]

    if summary["family_breakdown"]:
        lines.append("Families:")
        for family_id in sorted(summary["family_breakdown"]):
            breakdown = summary["family_breakdown"][family_id]
            lines.append(
                "- "
                f"{family_id}: seeds={breakdown['planned_seed_cases']} "
                f"queries={breakdown['query_available_seed_cases']} "
                f"executed={breakdown['executed_seed_cases']} "
                f"seed_success={breakdown['seed_success_count']} "
                f"variant_recall={breakdown['variant_recall_micro']:.2f} "
                f"negative_fp_rate={breakdown['negative_fp_rate_micro']:.2f}"
            )

    return "\n".join(lines)


async def _run_seed_case(seed_case, query_path: Path, output_dir: Path, include_seed: bool) -> Dict[str, Any]:
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
    parser = argparse.ArgumentParser(description="Batch dry-run or execute the pilot benchmark.")
    parser.add_argument(
        "--manifest-path",
        default=str(DEFAULT_PILOT_MANIFEST_PATH),
        help="Path to pilot manifest JSON",
    )
    parser.add_argument(
        "--output-dir",
        default=str(ROOT_DIR / "output" / "pilot_benchmark_runs"),
        help="Directory for per-seed plans and aggregated benchmark outputs",
    )
    parser.add_argument(
        "--query-map-json",
        help="JSON mapping of seed CVE id to query path",
    )
    parser.add_argument(
        "--analysis-root",
        help="QLCoder output root to scan for iterative_metadata.json and final queries",
    )
    parser.add_argument(
        "--default-query",
        help="Fallback query path to use for every selected seed",
    )
    parser.add_argument(
        "--family-id",
        help="Restrict execution to one family id, e.g. cwe-079-xss",
    )
    parser.add_argument(
        "--seed-cves",
        help="Comma-separated subset of runnable seed CVEs to include",
    )
    parser.add_argument(
        "--no-include-seed",
        dest="include_seed",
        action="store_false",
        help="Do not include the seed itself in each seed-case evaluation target list",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually run query evaluation across each selected seed case",
    )
    parser.set_defaults(include_seed=True)

    args = parser.parse_args()

    benchmark = load_pilot_benchmark(args.manifest_path)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    query_map: Dict[str, Path] = {}
    if args.query_map_json:
        query_map.update(load_query_map(Path(args.query_map_json)))
    if args.analysis_root:
        query_map.update(discover_queries_from_analysis_root(Path(args.analysis_root)))

    default_query = Path(args.default_query).resolve() if args.default_query else None
    if default_query is not None and not default_query.exists():
        raise FileNotFoundError(f"Default query does not exist: {default_query}")

    seed_cves = [value.strip() for value in (args.seed_cves or "").split(",") if value.strip()]
    seed_cases = _select_seed_cases(benchmark, seed_cves, args.family_id)

    seed_results = []
    for seed_case in seed_cases:
        seed_output_dir = output_dir / seed_case.seed.cve_id
        seed_output_dir.mkdir(parents=True, exist_ok=True)

        query_path = query_map.get(seed_case.seed.cve_id)
        query_source = None
        if query_path is not None:
            query_source = "query_map"
        elif default_query is not None:
            query_path = default_query
            query_source = "default_query"

        plan = build_seed_case_plan(
            seed_case,
            query_path or Path("<missing-query>"),
            include_seed=args.include_seed,
        )
        if query_path is None:
            plan["query"]["path"] = None
            plan["query"]["exists"] = False
            plan["query"]["name"] = None
            plan["query_missing_for_seed"] = True
        else:
            plan["query_source"] = query_source

        (seed_output_dir / "variant_seed_case_plan.json").write_text(
            json.dumps(plan, indent=2),
            encoding="utf-8",
        )

        execution_result = None
        if args.execute and query_path is not None:
            execution_result = asyncio.run(
                _run_seed_case(
                    seed_case=seed_case,
                    query_path=query_path,
                    output_dir=seed_output_dir,
                    include_seed=args.include_seed,
                )
            )
            (seed_output_dir / "variant_seed_case_execution.json").write_text(
                json.dumps(execution_result, indent=2),
                encoding="utf-8",
            )
            (seed_output_dir / "variant_seed_case_execution.txt").write_text(
                execution_result["summary"],
                encoding="utf-8",
            )

        seed_results.append(
            {
                "seed_case": {
                    "seed_cve_id": seed_case.seed.cve_id,
                    "family_id": seed_case.family_id,
                    "family_name": seed_case.family_name,
                },
                "query": {
                    "path": str(query_path) if query_path else None,
                    "exists": bool(query_path and query_path.exists()),
                    "source": query_source,
                },
                "plan": plan,
                "execution": execution_result,
            }
        )

    summary = _aggregate_results(seed_results)
    summary_text = _format_summary(summary, "execute" if args.execute else "dry-run")

    benchmark_report = {
        "manifest_path": str(Path(args.manifest_path).resolve()),
        "execution_mode": "execute" if args.execute else "dry-run",
        "seed_results": seed_results,
        "summary": summary,
    }

    summary_json_path = output_dir / "pilot_benchmark_summary.json"
    summary_text_path = output_dir / "pilot_benchmark_summary.txt"
    summary_json_path.write_text(json.dumps(benchmark_report, indent=2), encoding="utf-8")
    summary_text_path.write_text(summary_text, encoding="utf-8")

    print(summary_text)
    print(f"\nWrote benchmark summary to {summary_json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
