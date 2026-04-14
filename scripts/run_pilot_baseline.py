#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(ROOT_DIR))

from src.variant_benchmark import DEFAULT_PILOT_MANIFEST_PATH, load_pilot_benchmark
from scripts.run_pilot_benchmark import discover_queries_from_analysis_root


def _select_seed_cases(benchmark, seed_cves: Iterable[str], family_id: Optional[str]) -> list:
    requested = {cve_id for cve_id in seed_cves if cve_id}
    if requested:
        selected = []
        for cve_id in sorted(requested):
            case = benchmark.get_seed_case(cve_id, require_runnable=True)
            if family_id and case.family_id != family_id:
                continue
            selected.append(case)
        return selected
    return list(benchmark.list_seed_cases(runnable_only=True, family_id=family_id))


def build_generation_command(
    seed_case,
    *,
    analysis_root: Path,
    max_iteration: int,
    agent: str,
    model: str,
    ablation_mode: str,
    codex_use_local_config: bool,
    claude_use_local_config: bool,
    cache_phase_output: bool,
) -> List[str]:
    sample = seed_case.seed
    if sample.local_paths.vuln_db_path is None or sample.local_paths.fix_db_path is None:
        raise FileNotFoundError(f"Missing DB paths for seed {sample.cve_id}")
    if sample.local_paths.diff_path is None:
        raise FileNotFoundError(f"Missing diff path for seed {sample.cve_id}")

    command = [
        sys.executable,
        str(ROOT_DIR / "src" / "ql_agent.py"),
        "--cve-id",
        sample.cve_id,
        "--vuln-db",
        str(sample.local_paths.vuln_db_path),
        "--fixed-db",
        str(sample.local_paths.fix_db_path),
        "--diff",
        str(sample.local_paths.diff_path),
        "--output-dir",
        str(analysis_root),
        "--max-iteration",
        str(max_iteration),
        "--agent",
        agent,
        "--model",
        model,
        "--ablation-mode",
        ablation_mode,
    ]

    if codex_use_local_config and agent == "codex":
        command.append("--codex-use-local-config")
    if claude_use_local_config and agent == "claude":
        command.append("--claude-use-local-config")
    if not cache_phase_output:
        command.append("--no-cache-phase-output")
    return command


def build_benchmark_command(
    *,
    benchmark_output_dir: Path,
    analysis_root: Path,
    manifest_path: Path,
    family_id: Optional[str],
    seed_cves: Iterable[str],
    include_seed: bool,
    execute_evaluation: bool,
) -> List[str]:
    command = [
        sys.executable,
        str(ROOT_DIR / "scripts" / "run_pilot_benchmark.py"),
        "--manifest-path",
        str(manifest_path),
        "--analysis-root",
        str(analysis_root),
        "--output-dir",
        str(benchmark_output_dir),
    ]

    if family_id:
        command.extend(["--family-id", family_id])
    seed_list = [cve_id for cve_id in seed_cves if cve_id]
    if seed_list:
        command.extend(["--seed-cves", ",".join(seed_list)])
    if not include_seed:
        command.append("--no-include-seed")
    if execute_evaluation:
        command.append("--execute")
    return command


def _run_command(command: List[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=str(cwd),
        text=True,
        capture_output=True,
        check=False,
    )


def _write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def _format_plan(plan: Dict[str, Any]) -> str:
    lines = [
        "Pilot Baseline Runner",
        f"Execution mode: {plan['execution_mode']}",
        f"Manifest: {plan['manifest_path']}",
        f"Analysis root: {plan['analysis_root']}",
        f"Benchmark output dir: {plan['benchmark_output_dir']}",
        f"Selected seed cases: {plan['selected_seed_count']}",
        (
            "Generation requested: "
            f"{plan['generation']['execute']} "
            f"(agent={plan['generation']['agent']}, model={plan['generation']['model']}, "
            f"max_iteration={plan['generation']['max_iteration']})"
        ),
        f"Evaluation requested: {plan['evaluation']['execute']}",
        "Seeds:",
    ]

    for seed in plan["seeds"]:
        lines.append(
            "- "
            f"{seed['cve_id']} "
            f"family={seed['family_id']} "
            f"query_discovered={seed['discovered_query'] is not None}"
        )

    lines.append("Benchmark command:")
    lines.append(" ".join(plan["evaluation"]["command"]))
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Orchestrate QLCoder baseline generation and pilot benchmark evaluation."
    )
    parser.add_argument(
        "--manifest-path",
        default=str(DEFAULT_PILOT_MANIFEST_PATH),
        help="Path to pilot manifest JSON",
    )
    parser.add_argument(
        "--analysis-root",
        default=str(ROOT_DIR / "output" / "pilot_baseline_analysis"),
        help="Base output directory for QLCoder generation runs",
    )
    parser.add_argument(
        "--benchmark-output-dir",
        default=str(ROOT_DIR / "output" / "pilot_baseline_benchmark"),
        help="Output directory for pilot benchmark evaluation results",
    )
    parser.add_argument(
        "--runner-output-dir",
        default=str(ROOT_DIR / "output" / "pilot_baseline_runner"),
        help="Output directory for orchestration plan and command logs",
    )
    parser.add_argument("--family-id", help="Restrict to one family id")
    parser.add_argument("--seed-cves", help="Comma-separated subset of seed CVEs to include")
    parser.add_argument(
        "--max-iteration",
        type=int,
        default=5,
        help="Max iterations for QLCoder generation",
    )
    parser.add_argument(
        "--agent",
        default="codex",
        choices=["claude", "gemini", "codex"],
        help="Agent backend for generation",
    )
    parser.add_argument(
        "--model",
        default="gpt-5.4",
        choices=["sonnet-4", "sonnet-4.5", "gemini-2.5-pro", "gemini-2.5-flash", "gpt-5", "gpt-5.4"],
        help="Model name to pass to QLCoder",
    )
    parser.add_argument(
        "--ablation-mode",
        default="full",
        choices=["full", "no_tools", "no_lsp", "no_docs", "no_ast"],
        help="QLCoder ablation mode",
    )
    parser.add_argument(
        "--codex-use-local-config",
        action="store_true",
        help="For --agent codex, reuse ~/.codex/config.toml",
    )
    parser.add_argument(
        "--claude-use-local-config",
        action="store_true",
        help="For --agent claude, reuse local Claude Code CLI credentials",
    )
    parser.add_argument(
        "--no-cache-phase-output",
        dest="cache_phase_output",
        action="store_false",
        help="Disable QLCoder phase-output caching",
    )
    parser.add_argument(
        "--no-include-seed",
        dest="include_seed",
        action="store_false",
        help="Do not include the seed itself when evaluating each seed case",
    )
    parser.add_argument(
        "--execute-generation",
        action="store_true",
        help="Actually run QLCoder generation for the selected seeds",
    )
    parser.add_argument(
        "--execute-evaluation",
        action="store_true",
        help="Actually run CodeQL evaluation on the discovered/generated queries",
    )
    parser.add_argument(
        "--continue-on-error",
        action="store_true",
        help="Continue generation even if one seed fails",
    )
    parser.set_defaults(cache_phase_output=True, include_seed=True)

    args = parser.parse_args()

    benchmark = load_pilot_benchmark(args.manifest_path)
    seed_cves = [value.strip() for value in (args.seed_cves or "").split(",") if value.strip()]
    seed_cases = _select_seed_cases(benchmark, seed_cves, args.family_id)

    analysis_root = Path(args.analysis_root).resolve()
    benchmark_output_dir = Path(args.benchmark_output_dir).resolve()
    runner_output_dir = Path(args.runner_output_dir).resolve()
    runner_output_dir.mkdir(parents=True, exist_ok=True)
    analysis_root.mkdir(parents=True, exist_ok=True)
    benchmark_output_dir.mkdir(parents=True, exist_ok=True)

    generation_entries = []
    generation_failures = []
    for seed_case in seed_cases:
        command = build_generation_command(
            seed_case,
            analysis_root=analysis_root,
            max_iteration=args.max_iteration,
            agent=args.agent,
            model=args.model,
            ablation_mode=args.ablation_mode,
            codex_use_local_config=args.codex_use_local_config,
            claude_use_local_config=args.claude_use_local_config,
            cache_phase_output=args.cache_phase_output,
        )
        entry: Dict[str, Any] = {
            "cve_id": seed_case.seed.cve_id,
            "family_id": seed_case.family_id,
            "family_name": seed_case.family_name,
            "command": command,
            "stdout_log": None,
            "stderr_log": None,
            "returncode": None,
            "status": "planned",
        }

        if args.execute_generation:
            result = _run_command(command, ROOT_DIR)
            stdout_log = runner_output_dir / seed_case.seed.cve_id / "generation.stdout.log"
            stderr_log = runner_output_dir / seed_case.seed.cve_id / "generation.stderr.log"
            _write_text(stdout_log, result.stdout)
            _write_text(stderr_log, result.stderr)
            entry["stdout_log"] = str(stdout_log)
            entry["stderr_log"] = str(stderr_log)
            entry["returncode"] = result.returncode
            entry["status"] = "success" if result.returncode == 0 else "failed"
            if result.returncode != 0:
                generation_failures.append(seed_case.seed.cve_id)
                if not args.continue_on_error:
                    generation_entries.append(entry)
                    break

        generation_entries.append(entry)

    discovered_queries = discover_queries_from_analysis_root(analysis_root)
    seed_records = []
    for seed_case in seed_cases:
        seed_records.append(
            {
                "cve_id": seed_case.seed.cve_id,
                "family_id": seed_case.family_id,
                "family_name": seed_case.family_name,
                "discovered_query": str(discovered_queries.get(seed_case.seed.cve_id))
                if seed_case.seed.cve_id in discovered_queries
                else None,
            }
        )

    benchmark_command = build_benchmark_command(
        benchmark_output_dir=benchmark_output_dir,
        analysis_root=analysis_root,
        manifest_path=Path(args.manifest_path).resolve(),
        family_id=args.family_id,
        seed_cves=seed_cves,
        include_seed=args.include_seed,
        execute_evaluation=args.execute_evaluation,
    )

    benchmark_result = None
    if args.execute_evaluation:
        benchmark_result = _run_command(benchmark_command, ROOT_DIR)
        _write_text(runner_output_dir / "benchmark.stdout.log", benchmark_result.stdout)
        _write_text(runner_output_dir / "benchmark.stderr.log", benchmark_result.stderr)

    payload = {
        "execution_mode": (
            "generate+evaluate"
            if args.execute_generation and args.execute_evaluation
            else "generate"
            if args.execute_generation
            else "evaluate"
            if args.execute_evaluation
            else "dry-run"
        ),
        "manifest_path": str(Path(args.manifest_path).resolve()),
        "analysis_root": str(analysis_root),
        "benchmark_output_dir": str(benchmark_output_dir),
        "selected_seed_count": len(seed_cases),
        "generation": {
            "execute": args.execute_generation,
            "agent": args.agent,
            "model": args.model,
            "ablation_mode": args.ablation_mode,
            "max_iteration": args.max_iteration,
            "codex_use_local_config": args.codex_use_local_config,
            "claude_use_local_config": args.claude_use_local_config,
            "cache_phase_output": args.cache_phase_output,
            "continue_on_error": args.continue_on_error,
            "entries": generation_entries,
            "failed_cves": generation_failures,
        },
        "evaluation": {
            "execute": args.execute_evaluation,
            "include_seed": args.include_seed,
            "command": benchmark_command,
            "returncode": None if benchmark_result is None else benchmark_result.returncode,
            "stdout_log": str(runner_output_dir / "benchmark.stdout.log")
            if benchmark_result is not None
            else None,
            "stderr_log": str(runner_output_dir / "benchmark.stderr.log")
            if benchmark_result is not None
            else None,
        },
        "seeds": seed_records,
    }

    plan_json_path = runner_output_dir / "pilot_baseline_plan.json"
    plan_text_path = runner_output_dir / "pilot_baseline_plan.txt"
    _write_text(plan_json_path, json.dumps(payload, indent=2))
    _write_text(plan_text_path, _format_plan(payload))

    print(_format_plan(payload))
    print(f"\nWrote baseline runner plan to {plan_json_path}")

    if benchmark_result is not None and benchmark_result.returncode != 0:
        return benchmark_result.returncode
    if generation_failures and not args.continue_on_error:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
