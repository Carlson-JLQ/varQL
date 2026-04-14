from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from varql.schema_ir import SchemaIR


@dataclass(frozen=True)
class FamilySchema:
    family_id: str
    member_schema_ids: tuple[str, ...]
    shared_source_categories: tuple[str, ...] = field(default_factory=tuple)
    shared_sink_categories: tuple[str, ...] = field(default_factory=tuple)
    shared_sanitizer_categories: tuple[str, ...] = field(default_factory=tuple)
    shared_fix_actions: tuple[str, ...] = field(default_factory=tuple)
    forbidden_overfits: tuple[str, ...] = field(default_factory=tuple)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "family_id": self.family_id,
            "member_schema_ids": list(self.member_schema_ids),
            "shared_source_categories": list(self.shared_source_categories),
            "shared_sink_categories": list(self.shared_sink_categories),
            "shared_sanitizer_categories": list(self.shared_sanitizer_categories),
            "shared_fix_actions": list(self.shared_fix_actions),
            "forbidden_overfits": list(self.forbidden_overfits),
            "summary": self.summary,
        }


def _shared_categories(schemas: list[SchemaIR], field_name: str) -> tuple[str, ...]:
    if not schemas:
        return ()
    category_sets = []
    for schema in schemas:
        elements = getattr(schema, field_name)
        categories = {
            str(element.abstract.get("api_category", "")).strip()
            for element in elements
            if str(element.abstract.get("api_category", "")).strip()
        }
        category_sets.append(categories)
    if not category_sets:
        return ()
    shared = set.intersection(*category_sets) if category_sets else set()
    return tuple(sorted(shared))


def build_family_schema(schemas: list[SchemaIR]) -> FamilySchema:
    if not schemas:
        raise ValueError("At least one schema is required to build a family schema")

    family_id = schemas[0].family_id
    if any(schema.family_id != family_id for schema in schemas):
        raise ValueError("All schemas must belong to the same family")

    member_schema_ids = tuple(schema.schema_id for schema in schemas)
    shared_fix_actions = tuple(
        sorted({schema.patch_semantics.action for schema in schemas if schema.patch_semantics.action})
    )

    forbidden_symbols = []
    for schema in schemas:
        forbidden_symbols.extend(schema.query_constraints.forbidden)
    forbidden_overfits = tuple(sorted(set(symbol for symbol in forbidden_symbols if symbol)))

    summary = (
        f"Family schema for {family_id}: "
        f"{len(member_schema_ids)} member schemas, "
        f"shared sources={','.join(_shared_categories(schemas, 'sources')) or 'none'}, "
        f"shared sinks={','.join(_shared_categories(schemas, 'sinks')) or 'none'}"
    )

    return FamilySchema(
        family_id=family_id,
        member_schema_ids=member_schema_ids,
        shared_source_categories=_shared_categories(schemas, "sources"),
        shared_sink_categories=_shared_categories(schemas, "sinks"),
        shared_sanitizer_categories=_shared_categories(schemas, "sanitizers"),
        shared_fix_actions=shared_fix_actions,
        forbidden_overfits=forbidden_overfits,
        summary=summary,
    )
