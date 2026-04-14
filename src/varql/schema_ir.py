from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class SchemaElement:
    role: str
    concrete: dict[str, Any] = field(default_factory=dict)
    abstract: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    evidence_refs: list[str] = field(default_factory=list)

    def dedup_key(self) -> tuple[str, str, str, str]:
        return (
            self.role,
            str(self.concrete.get("title", "")).strip().lower(),
            str(self.concrete.get("file", "")).strip().lower(),
            str(self.concrete.get("pattern", "")).strip().lower(),
        )


@dataclass
class PatchSemantics:
    action: str = ""
    before: str = ""
    after: str = ""
    changed_elements: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class QueryConstraints:
    required: list[str] = field(default_factory=list)
    preferred: list[str] = field(default_factory=list)
    forbidden: list[str] = field(default_factory=list)


@dataclass
class SchemaIR:
    schema_id: str
    family_id: str
    summary: str = ""
    language: str = "java"
    sources: list[SchemaElement] = field(default_factory=list)
    sinks: list[SchemaElement] = field(default_factory=list)
    sanitizers: list[SchemaElement] = field(default_factory=list)
    guards: list[SchemaElement] = field(default_factory=list)
    propagations: list[SchemaElement] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    abstractions: list[dict[str, Any]] = field(default_factory=list)
    patch_semantics: PatchSemantics = field(default_factory=PatchSemantics)
    query_constraints: QueryConstraints = field(default_factory=QueryConstraints)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "SchemaIR":
        def _elements(values: list[dict[str, Any]]) -> list[SchemaElement]:
            return [SchemaElement(**value) for value in values]

        return cls(
            schema_id=raw["schema_id"],
            family_id=raw["family_id"],
            summary=raw.get("summary", ""),
            language=raw.get("language", "java"),
            sources=_elements(raw.get("sources", [])),
            sinks=_elements(raw.get("sinks", [])),
            sanitizers=_elements(raw.get("sanitizers", [])),
            guards=_elements(raw.get("guards", [])),
            propagations=_elements(raw.get("propagations", [])),
            evidence=list(raw.get("evidence", [])),
            abstractions=list(raw.get("abstractions", [])),
            patch_semantics=PatchSemantics(**raw.get("patch_semantics", {})),
            query_constraints=QueryConstraints(**raw.get("query_constraints", {})),
        )
