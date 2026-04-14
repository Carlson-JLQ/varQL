from varql.family_schema import build_family_schema
from varql.schema_extraction import build_seed_schema


def test_build_family_schema_for_xss_seed_pair():
    schema_a = build_seed_schema("CVE-2019-10077")
    schema_b = build_seed_schema("CVE-2017-14735")

    family_schema = build_family_schema([schema_a, schema_b])

    assert family_schema.family_id == "cwe-079-xss"
    assert len(family_schema.member_schema_ids) == 2
    assert "add_sanitizer" in family_schema.shared_fix_actions or "other" in family_schema.shared_fix_actions
    assert "jspwiki" in family_schema.forbidden_overfits
    assert "antisamy" in family_schema.forbidden_overfits
    assert family_schema.summary.startswith("Family schema for cwe-079-xss")
