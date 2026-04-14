from pathlib import Path

from varql.schema_extraction import (
    DEFAULT_EXTERNAL_QLCODER_OUTPUT_ROOT,
    build_sample_schema,
    build_seed_schema,
    find_latest_phase1_sections,
)
from varql.schema_ir import SchemaIR


def test_find_latest_phase1_sections_for_jspwiki_seed():
    path = find_latest_phase1_sections(
        "CVE-2019-10077",
        output_root=DEFAULT_EXTERNAL_QLCODER_OUTPUT_ROOT,
    )
    assert path.exists()
    assert path.name == "phase1_extracted_sections_CVE-2019-10077.json"


def test_build_seed_schema_for_jspwiki_seed():
    schema = build_seed_schema("CVE-2019-10077")
    assert isinstance(schema, SchemaIR)
    assert schema.schema_id == "CVE-2019-10077"
    assert schema.family_id == "cwe-079-xss"
    assert len(schema.sources) >= 1
    assert len(schema.sinks) >= 1
    assert len(schema.sanitizers) >= 1
    assert len(schema.propagations) >= 1
    assert schema.patch_semantics.action == "add_sanitizer"
    assert "must_model_dataflow" in schema.query_constraints.required
    assert not schema.summary.startswith("\n")
    assert schema.sources[0].abstract["api_category"] in {"remote_input", "parser_output"}
    assert schema.sinks[0].abstract["api_category"] in {"html_output", "error_rendering"}


def test_build_seed_schema_deduplicates_propagations():
    schema = build_seed_schema("CVE-2019-10077")
    dedup_keys = {element.dedup_key() for element in schema.propagations}
    assert len(dedup_keys) == len(schema.propagations)


def test_schema_roundtrip_dict():
    schema = build_seed_schema("CVE-2019-10077")
    reloaded = SchemaIR.from_dict(schema.to_dict())
    assert reloaded.schema_id == schema.schema_id
    assert reloaded.family_id == schema.family_id
    assert len(reloaded.sources) == len(schema.sources)


def test_build_sample_schema_for_seen_variant_with_diff_fallback():
    schema = build_sample_schema("CVE-2019-10078")
    assert isinstance(schema, SchemaIR)
    assert schema.schema_id == "CVE-2019-10078"
    assert schema.family_id == "cwe-079-xss"
    assert len(schema.sources) >= 1
    assert len(schema.sinks) >= 1
    assert schema.patch_semantics.action in {"add_sanitizer", "add_guard", "other"}
    assert "jspwiki" in schema.query_constraints.forbidden


def test_build_sample_schema_for_seen_variant_without_phase1_evidence():
    schema = build_sample_schema("CVE-2019-10076")
    evidence_types = {item["type"] for item in schema.evidence}
    assert "patch_diff" in evidence_types
    assert schema.abstractions[0]["support"] == ["family_fallback"]
