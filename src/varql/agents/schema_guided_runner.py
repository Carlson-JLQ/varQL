from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from agent_backends import create_backend
from query_subagents_evaluation import run_query_on_variant_seed_case
from varql.benchmark import DEFAULT_PILOT_MANIFEST_PATH, VariantSeedCase, load_pilot_benchmark
from varql.config import REPO_ROOT
from varql.synthesis.prompt_builder import build_prompt_context


DEFAULT_OUTPUT_ROOT = REPO_ROOT / "output" / "schema_guided_generation"


@dataclass(frozen=True)
class BackendTaskStub:
    cve_id: str
    vuln_db_path: str
    fixed_db_path: str
    working_dir: Optional[str] = None


@dataclass(frozen=True)
class SchemaGuidedRunPlan:
    seed_cve: str
    family_id: str
    agent: str
    model: str
    ablation_mode: str
    output_dir: str
    query_filename: str
    manifest_path: str
    include_seen_variant_schemas: bool
    evaluate: bool
    include_seed_in_evaluation: bool
    codex_use_local_config: bool
    claude_use_local_config: bool


def create_logger(output_dir: Path) -> logging.Logger:
    output_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger(f"varql.schema_guided_runner.{output_dir.name}")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if not logger.handlers:
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        file_handler = logging.FileHandler(output_dir / "schema_guided_runner.log")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    return logger


def resolve_output_dir(
    seed_cve: str,
    agent: str,
    model: str,
    output_root: Path | str = DEFAULT_OUTPUT_ROOT,
) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Path(output_root) / f"schema_guided_{seed_cve}_{timestamp}_{agent}_{model}" / "results"


def build_backend_task(seed_case: VariantSeedCase) -> BackendTaskStub:
    sample = seed_case.seed
    if sample.local_paths.vuln_db_path is None or sample.local_paths.fix_db_path is None:
        raise FileNotFoundError(f"Seed {sample.cve_id} is missing runnable DB paths")
    return BackendTaskStub(
        cve_id=sample.cve_id,
        vuln_db_path=str(sample.local_paths.vuln_db_path),
        fixed_db_path=str(sample.local_paths.fix_db_path),
    )


def build_schema_guided_prompt(
    seed_cve: str,
    *,
    query_filename: str,
    benchmark_manifest_path: Path | str = DEFAULT_PILOT_MANIFEST_PATH,
    include_seen_variant_schemas: bool = True,
) -> str:
    context = build_prompt_context(
        seed_cve,
        benchmark_manifest_path=benchmark_manifest_path,
        include_seen_variant_schemas=include_seen_variant_schemas,
    )
    base_prompt = context.build_prompt().rstrip()
    instructions = f"""

Workspace Instructions
- You are running inside a writable results directory that already contains `qlpack.yml`.
- Write exactly one CodeQL query file named `{query_filename}` in the current working directory.
- Do not place the query in a subdirectory.
- Use the benchmark protocol above instead of asking for the raw diff again.
- You may use available MCP/file tools if the backend exposes them.

Completion Contract
- When you finish writing the query, print exactly one line in this format:
QUERY_FILE_PATH: {query_filename}
- Then briefly explain why the query should generalize beyond the seed.
"""
    return base_prompt + "\n" + instructions.strip() + "\n"


def extract_query_path_from_output(output_text: str, output_dir: Path) -> Optional[Path]:
    match = re.search(r"QUERY_FILE_PATH:\s*([^\s\"}*\n\r]+)", output_text)
    candidate_names: list[str] = []
    if match:
        candidate_names.append(match.group(1).strip("*"))

    for path in output_dir.glob("*.ql"):
        candidate_names.append(path.name)

    seen: set[str] = set()
    for candidate in candidate_names:
        if candidate in seen:
            continue
        seen.add(candidate)
        candidate_path = Path(candidate)
        if candidate_path.is_absolute() and candidate_path.exists():
            return candidate_path
        resolved = output_dir / candidate_path.name
        if resolved.exists():
            return resolved
    return None


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _prepare_workspace(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    qlpack_src = REPO_ROOT / "qlpack.yml"
    qlpack_dest = output_dir / "qlpack.yml"
    if qlpack_src.exists():
        shutil.copy2(qlpack_src, qlpack_dest)


async def run_schema_guided_generation(
    seed_cve: str,
    *,
    manifest_path: Path | str = DEFAULT_PILOT_MANIFEST_PATH,
    output_dir: Path | str | None = None,
    agent: str = "codex",
    model: str = "gpt-5.4",
    ablation_mode: str = "full",
    include_seen_variant_schemas: bool = True,
    codex_use_local_config: bool = False,
    claude_use_local_config: bool = False,
    evaluate: bool = False,
    include_seed_in_evaluation: bool = True,
) -> dict[str, Any]:
    benchmark = load_pilot_benchmark(manifest_path)
    seed_case = benchmark.get_seed_case(seed_cve, require_runnable=True)
    run_output_dir = Path(output_dir) if output_dir else resolve_output_dir(seed_cve, agent, model)
    _prepare_workspace(run_output_dir)
    logger = create_logger(run_output_dir)

    query_filename = f"{seed_cve}-schema-guided-query.ql"
    prompt = build_schema_guided_prompt(
        seed_cve,
        query_filename=query_filename,
        benchmark_manifest_path=manifest_path,
        include_seen_variant_schemas=include_seen_variant_schemas,
    )
    prompt_path = run_output_dir / "schema_guided_prompt.txt"
    prompt_path.write_text(prompt, encoding="utf-8")

    task = build_backend_task(seed_case)
    backend_kwargs: dict[str, Any] = {}
    if agent == "codex":
        backend_kwargs["use_local_config"] = codex_use_local_config
    if agent == "claude":
        backend_kwargs["use_local_config"] = claude_use_local_config
    backend = create_backend(
        agent,
        model,
        logger,
        ablation_mode=ablation_mode,
        **backend_kwargs,
    )
    backend.setup_workspace(str(run_output_dir), task)

    env = os.environ.copy()
    env["VULN_CODEQL_DB"] = task.vuln_db_path
    env["FIXED_CODEQL_DB"] = task.fixed_db_path

    result = await backend.execute_prompt(
        prompt,
        env,
        str(run_output_dir),
        "schema_guided_generation",
    )

    stdout_path = run_output_dir / "schema_guided_generation_output.txt"
    stderr_path = run_output_dir / "schema_guided_generation_stderr.txt"
    stdout_path.write_text(result["stdout"], encoding="utf-8")
    stderr_path.write_text(result["stderr"], encoding="utf-8")

    query_path = extract_query_path_from_output(result["stdout"], run_output_dir)

    evaluation_payload: Optional[dict[str, Any]] = None
    if evaluate and query_path is not None:
        evaluation = await run_query_on_variant_seed_case(
            query_path=str(query_path),
            seed_case=seed_case,
            iteration_number=1,
            output_dir=str(run_output_dir / "benchmark_evaluation"),
            logger=logger,
            include_seed=include_seed_in_evaluation,
        )
        evaluation_payload = evaluation.to_dict()
        _write_json(run_output_dir / "variant_benchmark_evaluation.json", evaluation_payload)
        (run_output_dir / "variant_benchmark_evaluation.txt").write_text(
            evaluation.summary,
            encoding="utf-8",
        )

    metrics = {
        "success": result["returncode"] == 0,
        "return_code": result["returncode"],
        "query_path": str(query_path) if query_path else None,
        "prompt_path": str(prompt_path),
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "api_usage": result.get("api_usage", {}),
        "evaluation_generated": evaluation_payload is not None,
    }
    _write_json(run_output_dir / "schema_guided_generation_metrics.json", metrics)

    return {
        "seed_cve": seed_cve,
        "family_id": seed_case.family_id,
        "output_dir": str(run_output_dir),
        "query_path": str(query_path) if query_path else None,
        "prompt_path": str(prompt_path),
        "success": result["returncode"] == 0,
        "api_usage": result.get("api_usage", {}),
        "evaluation": evaluation_payload,
    }


def build_run_plan(
    seed_cve: str,
    *,
    manifest_path: Path | str = DEFAULT_PILOT_MANIFEST_PATH,
    output_dir: Path | str | None = None,
    agent: str = "codex",
    model: str = "gpt-5.4",
    ablation_mode: str = "full",
    include_seen_variant_schemas: bool = True,
    codex_use_local_config: bool = False,
    claude_use_local_config: bool = False,
    evaluate: bool = False,
    include_seed_in_evaluation: bool = True,
) -> SchemaGuidedRunPlan:
    benchmark = load_pilot_benchmark(manifest_path)
    seed_case = benchmark.get_seed_case(seed_cve, require_runnable=True)
    resolved_output_dir = Path(output_dir) if output_dir else resolve_output_dir(seed_cve, agent, model)
    return SchemaGuidedRunPlan(
        seed_cve=seed_cve,
        family_id=seed_case.family_id,
        agent=agent,
        model=model,
        ablation_mode=ablation_mode,
        output_dir=str(resolved_output_dir),
        query_filename=f"{seed_cve}-schema-guided-query.ql",
        manifest_path=str(Path(manifest_path)),
        include_seen_variant_schemas=include_seen_variant_schemas,
        evaluate=evaluate,
        include_seed_in_evaluation=include_seed_in_evaluation,
        codex_use_local_config=codex_use_local_config,
        claude_use_local_config=claude_use_local_config,
    )


def format_run_plan(plan: SchemaGuidedRunPlan) -> str:
    lines = [
        "Schema-Guided Generation Runner",
        f"Seed CVE: {plan.seed_cve}",
        f"Family: {plan.family_id}",
        f"Agent: {plan.agent}",
        f"Model: {plan.model}",
        f"Ablation mode: {plan.ablation_mode}",
        f"Output dir: {plan.output_dir}",
        f"Query filename: {plan.query_filename}",
        f"Manifest: {plan.manifest_path}",
        f"Include seen variant schemas: {plan.include_seen_variant_schemas}",
        f"Evaluate after generation: {plan.evaluate}",
        f"Include seed in evaluation: {plan.include_seed_in_evaluation}",
    ]
    return "\n".join(lines)


def save_run_plan(plan: SchemaGuidedRunPlan, output_dir: Path | str) -> None:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    _write_json(output_dir / "schema_guided_plan.json", asdict(plan))
    (output_dir / "schema_guided_plan.txt").write_text(format_run_plan(plan), encoding="utf-8")
