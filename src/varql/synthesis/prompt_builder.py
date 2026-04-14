from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from varql.benchmark import VariantSeedCase, load_pilot_benchmark
from varql.family_schema import FamilySchema, build_family_schema
from varql.schema_extraction import (
    DEFAULT_EXTERNAL_QLCODER_OUTPUT_ROOT,
    build_sample_schema,
    build_seed_schema,
)
from varql.schema_ir import SchemaElement, SchemaIR


def _format_element(element: SchemaElement) -> str:
    title = str(element.concrete.get("title", "")).strip() or element.role
    parts = [title]

    semantic_type = str(element.abstract.get("semantic_type", "")).strip()
    if semantic_type:
        parts.append(f"semantic={semantic_type}")

    api_category = str(element.abstract.get("api_category", "")).strip()
    if api_category and api_category != "generic":
        parts.append(f"category={api_category}")

    file_path = str(element.concrete.get("file", "")).strip()
    if file_path:
        parts.append(f"file={file_path}")

    pattern = str(element.concrete.get("pattern", "")).strip()
    if pattern:
        parts.append(f"pattern={pattern}")

    return "; ".join(parts)


def _format_elements(title: str, elements: list[SchemaElement], limit: int = 4) -> list[str]:
    if not elements:
        return [f"{title}: none extracted"]

    lines = [f"{title}:"]
    for element in elements[:limit]:
        lines.append(f"- {_format_element(element)}")

    remaining = len(elements) - min(len(elements), limit)
    if remaining > 0:
        lines.append(f"- ... plus {remaining} more")
    return lines


def _format_list(title: str, values: list[str] | tuple[str, ...]) -> str:
    normalized = [value for value in values if str(value).strip()]
    return f"{title}: {', '.join(normalized) if normalized else 'none'}"


@dataclass(frozen=True)
class SynthesisPromptContext:
    seed_case: VariantSeedCase
    seed_schema: SchemaIR
    family_schema: FamilySchema
    seen_schema_ids: tuple[str, ...] = ()
    skipped_seen_schema_ids: tuple[str, ...] = ()
    qlcoder_output_root: Path = DEFAULT_EXTERNAL_QLCODER_OUTPUT_ROOT
    notes: tuple[str, ...] = field(default_factory=tuple)

    def build_prompt(self) -> str:
        split = self.seed_case.split_summary()
        lines: list[str] = [
            "You are designing a CodeQL query that should generalize beyond a single seed CVE.",
            "",
            "Task",
            f"- Seed CVE: {self.seed_case.seed.cve_id}",
            f"- Family: {self.seed_case.family_id} ({self.seed_case.family_name})",
            f"- Goal: synthesize one query that detects the seed and should transfer to related variants.",
            "",
            "Evaluation Protocol",
            f"- Seed: {split['seed']}",
            _format_list("- Seen refinement variants", split["seen_variants"]),
            _format_list("- Held-out test variants", split["held_out_variants"]),
            _format_list("- Hard negatives", split["hard_negatives"]),
            "- During synthesis, optimize for the seed and seen variants only.",
            "- The held-out variants are the real generalization target and should not be overfit explicitly.",
            "",
            "Seed Schema",
            f"- Summary: {self.seed_schema.summary or self.seed_case.note or 'none'}",
            f"- Patch action: {self.seed_schema.patch_semantics.action or 'unknown'}",
            f"- Before: {self.seed_schema.patch_semantics.before or 'not extracted'}",
            f"- After: {self.seed_schema.patch_semantics.after or 'not extracted'}",
        ]

        lines.extend(_format_elements("Sources", self.seed_schema.sources))
        lines.extend(_format_elements("Sinks", self.seed_schema.sinks))
        lines.extend(_format_elements("Sanitizers", self.seed_schema.sanitizers))
        lines.extend(_format_elements("Propagations", self.seed_schema.propagations))

        lines.extend(
            [
                "",
                "Family Abstraction",
                f"- Summary: {self.family_schema.summary or 'none'}",
                _format_list("- Shared source categories", self.family_schema.shared_source_categories),
                _format_list("- Shared sink categories", self.family_schema.shared_sink_categories),
                _format_list(
                    "- Shared sanitizer categories",
                    self.family_schema.shared_sanitizer_categories,
                ),
                _format_list("- Shared fix actions", self.family_schema.shared_fix_actions),
                _format_list("- Forbidden overfits", self.family_schema.forbidden_overfits),
                _format_list("- Seen schemas used to derive family abstraction", self.seen_schema_ids),
            ]
        )

        if self.skipped_seen_schema_ids:
            lines.append(
                _format_list(
                    "- Seen variants without available schema evidence",
                    self.skipped_seen_schema_ids,
                )
            )

        if self.notes:
            lines.append(_format_list("- Additional notes", self.notes))

        lines.extend(
            [
                "",
                "Query Design Requirements",
                _format_list("- Required constraints", self.seed_schema.query_constraints.required),
                _format_list("- Preferred abstractions", self.seed_schema.query_constraints.preferred),
                _format_list("- Forbidden seed-specific symbols", self.seed_schema.query_constraints.forbidden),
                "- Prefer semantic source/sink/sanitizer modeling over concrete class names.",
                "- Avoid relying on project-private helper names unless they encode the vulnerability mechanism.",
                "- The query must distinguish vulnerable from fixed versions.",
                "- Favor a reusable family-level pattern instead of a seed-only signature.",
                "",
                "Output",
                "- Produce one CodeQL query.",
                "- Include concise metadata suitable for a real vulnerability query.",
                "- Briefly explain how the query avoids overfitting to the seed project.",
            ]
        )
        return "\n".join(lines).strip() + "\n"


def build_prompt_context(
    seed_cve: str,
    *,
    benchmark_manifest_path: Path | str | None = None,
    qlcoder_output_root: Path | str | None = DEFAULT_EXTERNAL_QLCODER_OUTPUT_ROOT,
    include_seen_variant_schemas: bool = True,
) -> SynthesisPromptContext:
    resolved_output_root = (
        Path(qlcoder_output_root)
        if qlcoder_output_root is not None
        else DEFAULT_EXTERNAL_QLCODER_OUTPUT_ROOT
    )
    benchmark = load_pilot_benchmark(benchmark_manifest_path) if benchmark_manifest_path else load_pilot_benchmark()
    seed_case = benchmark.get_seed_case(seed_cve, require_runnable=True)
    seed_schema = build_seed_schema(
        seed_cve,
        benchmark_manifest_path=benchmark_manifest_path,
        qlcoder_output_root=resolved_output_root,
    )

    schema_members = [seed_schema]
    seen_schema_ids: list[str] = []
    skipped_seen_schema_ids: list[str] = []

    seen_variants, _held_out_variants = seed_case.split_variants()
    if include_seen_variant_schemas:
        for target in seen_variants:
            try:
                seen_schema = build_sample_schema(
                    target.sample.cve_id,
                    benchmark_manifest_path=benchmark_manifest_path,
                    qlcoder_output_root=resolved_output_root,
                )
            except FileNotFoundError:
                skipped_seen_schema_ids.append(target.sample.cve_id)
                continue
            schema_members.append(seen_schema)
            seen_schema_ids.append(seen_schema.schema_id)

    family_schema = build_family_schema(schema_members)
    return SynthesisPromptContext(
        seed_case=seed_case,
        seed_schema=seed_schema,
        family_schema=family_schema,
        seen_schema_ids=tuple(seen_schema_ids),
        skipped_seen_schema_ids=tuple(skipped_seen_schema_ids),
        qlcoder_output_root=resolved_output_root,
    )


def save_prompt(prompt: str, output_path: Path | str) -> Path:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(prompt, encoding="utf-8")
    return output_path
