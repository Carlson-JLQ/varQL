from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from varql.benchmark import VariantSeedCase, VariantTarget


@dataclass(frozen=True)
class EvaluationResult:
    recall_method: bool = False
    num_tp_methods: int = 0
    total_fixed_methods: int = 0
    num_results: int = 0
    num_paths: int = 0
    fixed_methods: list[str] = field(default_factory=list)
    hit_methods: list[str] = field(default_factory=list)
    missed_methods: list[str] = field(default_factory=list)
    recall_file: bool = False
    num_tp_files: int = 0
    total_fixed_files: int = 0
    fixed_files: list[str] = field(default_factory=list)
    hit_files: list[str] = field(default_factory=list)
    missed_files: list[str] = field(default_factory=list)
    full_result: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class VariantTargetEvaluation:
    target: VariantTarget
    summary: str
    vuln_eval: EvaluationResult
    fixed_eval: EvaluationResult
    execution_successful: bool
    vuln_hit: bool
    fix_hit: bool
    matches_expectation: bool
    skipped: bool = False
    skip_reason: str | None = None


@dataclass(frozen=True)
class VariantBenchmarkEvaluation:
    seed_case: VariantSeedCase
    target_evaluations: list[VariantTargetEvaluation]
    seed_success: bool
    positive_variant_hits: int
    positive_variant_total: int
    variant_recall: float
    negative_fp_count: int
    negative_total: int
    negative_fp_rate: float
    skipped_targets: int
    summary: str


def empty_evaluation_result() -> EvaluationResult:
    return EvaluationResult()


def summarize_variant_seed_case(
    seed_case: VariantSeedCase,
    target_evaluations: list[VariantTargetEvaluation],
) -> VariantBenchmarkEvaluation:
    runnable_evals = [evaluation for evaluation in target_evaluations if not evaluation.skipped]
    seed_eval = next(
        (evaluation for evaluation in runnable_evals if evaluation.target.role == "seed"),
        None,
    )
    positive_evals = [
        evaluation
        for evaluation in runnable_evals
        if evaluation.target.role == "positive_variant"
    ]
    negative_evals = [
        evaluation
        for evaluation in runnable_evals
        if evaluation.target.role == "hard_negative"
    ]

    positive_variant_hits = sum(
        1 for evaluation in positive_evals if evaluation.matches_expectation
    )
    positive_variant_total = len(positive_evals)
    negative_fp_count = sum(
        1 for evaluation in negative_evals if not evaluation.matches_expectation
    )
    negative_total = len(negative_evals)
    skipped_targets = sum(1 for evaluation in target_evaluations if evaluation.skipped)

    variant_recall = (
        positive_variant_hits / positive_variant_total if positive_variant_total else 0.0
    )
    negative_fp_rate = negative_fp_count / negative_total if negative_total else 0.0
    seed_success = seed_eval.matches_expectation if seed_eval else False

    lines = [
        f"Variant benchmark summary for seed {seed_case.seed.cve_id}",
        f"Family: {seed_case.family_id}",
        f"Seed success: {seed_success}",
        f"Positive variant recall: {positive_variant_hits}/{positive_variant_total} ({variant_recall:.2f})",
        f"Negative FP rate: {negative_fp_count}/{negative_total} ({negative_fp_rate:.2f})",
    ]
    if skipped_targets:
        lines.append(f"Skipped targets: {skipped_targets}")

    for evaluation in target_evaluations:
        status = "SKIPPED" if evaluation.skipped else (
            "PASS" if evaluation.matches_expectation else "FAIL"
        )
        lines.append(
            f"- {evaluation.target.role}:{evaluation.target.sample.cve_id} "
            f"[{status}] vuln_hit={evaluation.vuln_hit} fix_hit={evaluation.fix_hit}"
        )

    return VariantBenchmarkEvaluation(
        seed_case=seed_case,
        target_evaluations=target_evaluations,
        seed_success=seed_success,
        positive_variant_hits=positive_variant_hits,
        positive_variant_total=positive_variant_total,
        variant_recall=variant_recall,
        negative_fp_count=negative_fp_count,
        negative_total=negative_total,
        negative_fp_rate=negative_fp_rate,
        skipped_targets=skipped_targets,
        summary="\n".join(lines),
    )


def make_target_evaluation(
    *,
    target: VariantTarget,
    vuln_hit: bool,
    fix_hit: bool,
    execution_successful: bool = True,
    summary: str = "",
    vuln_eval: EvaluationResult | None = None,
    fixed_eval: EvaluationResult | None = None,
) -> VariantTargetEvaluation:
    return VariantTargetEvaluation(
        target=target,
        summary=summary,
        vuln_eval=vuln_eval or empty_evaluation_result(),
        fixed_eval=fixed_eval or empty_evaluation_result(),
        execution_successful=execution_successful,
        vuln_hit=vuln_hit,
        fix_hit=fix_hit,
        matches_expectation=(
            execution_successful
            and vuln_hit == target.expected_vuln_hit
            and fix_hit == target.expected_fix_hit
        ),
    )


def make_skipped_target_evaluation(
    *,
    target: VariantTarget,
    reason: str,
) -> VariantTargetEvaluation:
    return VariantTargetEvaluation(
        target=target,
        summary=f"SKIPPED: {reason}",
        vuln_eval=empty_evaluation_result(),
        fixed_eval=empty_evaluation_result(),
        execution_successful=False,
        vuln_hit=False,
        fix_hit=False,
        matches_expectation=False,
        skipped=True,
        skip_reason=reason,
    )
