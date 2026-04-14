from pathlib import Path

from varql.benchmark import load_pilot_benchmark
from varql.family_schema import build_family_schema
from varql.schema_extraction import build_seed_schema
from varql.schema_ir import PatchSemantics, QueryConstraints, SchemaIR
from varql.synthesis.prompt_builder import SynthesisPromptContext, build_prompt_context


def test_prompt_builder_includes_split_and_constraints():
    benchmark = load_pilot_benchmark()
    case = benchmark.get_seed_case("CVE-2019-10077", require_runnable=True)
    schema = build_seed_schema("CVE-2019-10077")
    family_schema = build_family_schema([schema])

    context = SynthesisPromptContext(
        seed_case=case,
        seed_schema=schema,
        family_schema=family_schema,
        seen_schema_ids=(),
        skipped_seen_schema_ids=("CVE-2019-10078",),
    )

    prompt = context.build_prompt()

    assert "Seed CVE: CVE-2019-10077" in prompt
    assert "Held-out test variants: CVE-2019-10076" in prompt
    assert "Hard negatives: CVE-2019-0225" in prompt
    assert "Required constraints:" in prompt
    assert "Forbidden seed-specific symbols:" in prompt
    assert "Seen variants without available schema evidence: CVE-2019-10078" in prompt


def test_prompt_context_builds_for_seed():
    context = build_prompt_context("CVE-2019-10077")
    assert context.seed_case.seed.cve_id == "CVE-2019-10077"
    assert context.seed_schema.schema_id == "CVE-2019-10077"
    assert context.family_schema.family_id == "cwe-079-xss"
    assert "CVE-2019-10078" in context.seen_schema_ids
    assert not context.skipped_seen_schema_ids


def test_prompt_builder_handles_minimal_schema():
    benchmark = load_pilot_benchmark()
    case = benchmark.get_seed_case("CVE-2019-10077", require_runnable=True)
    minimal_schema = SchemaIR(
        schema_id="CVE-2019-10077",
        family_id="cwe-079-xss",
        summary="Minimal schema",
        patch_semantics=PatchSemantics(action="other"),
        query_constraints=QueryConstraints(required=["must_distinguish_fixed"]),
    )
    family_schema = build_family_schema([minimal_schema])
    prompt = SynthesisPromptContext(
        seed_case=case,
        seed_schema=minimal_schema,
        family_schema=family_schema,
    ).build_prompt()
    assert "Sources: none extracted" in prompt
    assert "Sinks: none extracted" in prompt
    assert "Sanitizers: none extracted" in prompt
