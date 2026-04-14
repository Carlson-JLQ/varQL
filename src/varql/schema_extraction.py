from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from varql.benchmark import BenchmarkSample, VariantSeedCase, load_pilot_benchmark
from varql.schema_ir import PatchSemantics, QueryConstraints, SchemaElement, SchemaIR


VARQL_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_EXTERNAL_QLCODER_OUTPUT_ROOT = VARQL_ROOT.parent / "qlcoder" / "output" / "pilot_baseline_analysis"


@dataclass(frozen=True)
class Phase1Sections:
    path: Path
    raw: dict[str, Any]

    @property
    def sources(self) -> str:
        return str(self.raw.get("sources", ""))

    @property
    def sinks(self) -> str:
        return str(self.raw.get("sinks", ""))

    @property
    def sanitizers(self) -> str:
        return str(self.raw.get("sanitizers", ""))

    @property
    def additional_taint_steps(self) -> str:
        return str(self.raw.get("additional_taint_steps", ""))

    @property
    def vulnerability_summary(self) -> str:
        summary = str(self.raw.get("vulnerability_analysis_summary", ""))
        if "## Vulnerability Summary" in summary:
            return summary.split("## Vulnerability Summary", 1)[1].strip()
        return summary.strip()


@dataclass(frozen=True)
class SampleContext:
    sample: BenchmarkSample
    family_id: str
    family_name: str
    note: str = ""


def find_latest_phase1_sections(
    cve_id: str,
    output_root: Path | str = DEFAULT_EXTERNAL_QLCODER_OUTPUT_ROOT,
) -> Path:
    output_root = Path(output_root)
    pattern = f"ql_agent_{cve_id}_*/results/phase1_extracted_sections_{cve_id}.json"
    matches = sorted(output_root.glob(pattern), key=lambda p: p.stat().st_mtime)
    if not matches:
        raise FileNotFoundError(f"No phase1 extracted sections found for {cve_id} under {output_root}")
    return matches[-1]


def load_phase1_sections(
    cve_id: str,
    output_root: Path | str = DEFAULT_EXTERNAL_QLCODER_OUTPUT_ROOT,
) -> Phase1Sections:
    path = find_latest_phase1_sections(cve_id, output_root=output_root)
    raw = json.loads(path.read_text(encoding="utf-8"))
    return Phase1Sections(path=path, raw=raw)


def _split_numbered_entries(section_text: str) -> list[str]:
    if not section_text:
        return []
    normalized = (
        section_text.replace("\\r\\n", "\n")
        .replace("\\n", "\n")
        .replace("\\t", "\t")
        .replace('\\"', '"')
    )
    lines = normalized.replace("\r\n", "\n").split("\n")
    entries: list[list[str]] = []
    current: list[str] = []
    for line in lines:
        if re.match(r"^\d+\.\s+\*\*", line.strip()) or re.match(r"^\d+\.\s+`", line.strip()) or re.match(r"^\d+\.\s+\S", line.strip()):
            if current:
                entries.append(current)
            current = [line]
        else:
            if current:
                current.append(line)
    if current:
        entries.append(current)
    return ["\n".join(chunk).strip() for chunk in entries if any(part.strip() for part in chunk)]


def _extract_first_match(pattern: str, text: str) -> str:
    match = re.search(pattern, text, re.MULTILINE)
    return match.group(1).strip() if match else ""


def _clean_title(raw_title: str) -> str:
    title = re.sub(r"^\d+\.\s*", "", raw_title.strip())
    title = title.strip("* ").strip()
    return title


def _normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _infer_api_category(role: str, title: str, pattern: str, semantic_type: str) -> str:
    blob = f"{title} {pattern} {semantic_type}".lower()
    if role == "source":
        if "request" in blob or "remote" in blob or "user" in blob:
            return "remote_input"
        if "parser" in blob:
            return "parser_output"
    if role == "sink":
        if "html" in blob or "render" in blob or "output" in blob:
            return "html_output"
        if "error" in blob:
            return "error_rendering"
    if role == "sanitizer":
        if "escape" in blob or "entity" in blob:
            return "html_escaping"
    if role == "propagation":
        if "format" in blob:
            return "string_formatting"
        if "array" in blob:
            return "container_wrapping"
        if "parser" in blob:
            return "parser_flow"
    return "generic"


def _parse_schema_elements(section_text: str, role: str) -> list[SchemaElement]:
    elements: list[SchemaElement] = []
    for idx, entry in enumerate(_split_numbered_entries(section_text), start=1):
        lines = [line for line in entry.splitlines() if line.strip()]
        if not lines:
            continue
        title = _clean_title(lines[0])
        file_path = _extract_first_match(r"- File:\s*`([^`]+)`", entry)
        location = _extract_first_match(r"- Location:\s*(.+)", entry)
        pattern = _extract_first_match(r"- Pattern:\s*(.+)", entry)
        conceptual = _extract_first_match(r"\*\*Conceptual [^:]+:\*\*\s*(.+)", entry)
        vulnerable_pattern = _extract_first_match(r"\*\*Vulnerable pattern \(ABSENT sanitizer\):\*\*\s*(.+)", entry)

        concrete: dict[str, Any] = {}
        if file_path:
            concrete["file"] = _normalize_text(file_path)
        if location:
            concrete["location"] = _normalize_text(location)
        if pattern:
            concrete["pattern"] = _normalize_text(pattern)
        concrete["title"] = _normalize_text(title)

        abstract: dict[str, Any] = {}
        if conceptual:
            abstract["semantic_type"] = _normalize_text(conceptual)
        if vulnerable_pattern:
            abstract["missing_protection"] = _normalize_text(vulnerable_pattern)
        abstract["api_category"] = _infer_api_category(
            role,
            concrete.get("title", ""),
            concrete.get("pattern", ""),
            abstract.get("semantic_type", ""),
        )

        elements.append(
            SchemaElement(
                role=role,
                concrete=concrete,
                abstract=abstract,
                confidence=0.7,
                evidence_refs=[f"{role}_{idx}"],
            )
        )
    return elements


def _deduplicate_elements(elements: list[SchemaElement]) -> list[SchemaElement]:
    deduped: dict[tuple[str, str, str, str], SchemaElement] = {}
    for element in elements:
        key = element.dedup_key()
        current = deduped.get(key)
        if current is None or element.confidence > current.confidence:
            deduped[key] = element
    return list(deduped.values())


def _clean_summary(summary_text: str, fallback: str) -> str:
    if not summary_text:
        return fallback
    text = summary_text.replace("\\n", "\n").strip()
    text = re.sub(r"^\*+\s*", "", text)
    text = _normalize_text(text)
    return text or fallback


def _family_defaults_for_sample(sample_context: SampleContext) -> dict[str, Any]:
    family_id = sample_context.family_id
    if family_id == "cwe-079-xss":
        return {
            "summary": "User-controlled text reaches HTML rendering without contextual escaping.",
            "sources": [
                SchemaElement(
                    role="source",
                    concrete={"title": "User-controlled web or parser-derived text"},
                    abstract={
                        "semantic_type": "untrusted text input that can influence rendered output",
                        "api_category": "remote_input",
                    },
                    confidence=0.45,
                    evidence_refs=["family_fallback"],
                )
            ],
            "sinks": [
                SchemaElement(
                    role="sink",
                    concrete={"title": "HTML rendering or error output sink"},
                    abstract={
                        "semantic_type": "text is emitted into an HTML response or error message",
                        "api_category": "html_output",
                    },
                    confidence=0.45,
                    evidence_refs=["family_fallback"],
                )
            ],
            "sanitizers": [
                SchemaElement(
                    role="sanitizer",
                    concrete={"title": "HTML escaping or encoding"},
                    abstract={
                        "semantic_type": "HTML special characters are escaped before output",
                        "api_category": "html_escaping",
                    },
                    confidence=0.4,
                    evidence_refs=["family_fallback"],
                )
            ],
        }
    if family_id == "cwe-022-path-traversal":
        return {
            "summary": "User-controlled path reaches filesystem access without sufficient path validation.",
            "sources": [
                SchemaElement(
                    role="source",
                    concrete={"title": "User-controlled path input"},
                    abstract={
                        "semantic_type": "untrusted path string from external input",
                        "api_category": "remote_input",
                    },
                    confidence=0.45,
                    evidence_refs=["family_fallback"],
                )
            ],
            "sinks": [
                SchemaElement(
                    role="sink",
                    concrete={"title": "Filesystem access sink"},
                    abstract={
                        "semantic_type": "path is consumed by file read/write or resource resolution",
                        "api_category": "filesystem_access",
                    },
                    confidence=0.45,
                    evidence_refs=["family_fallback"],
                )
            ],
            "sanitizers": [],
        }
    if family_id == "cwe-078-command-injection":
        return {
            "summary": "User-controlled input reaches command execution without command validation.",
            "sources": [
                SchemaElement(
                    role="source",
                    concrete={"title": "User-controlled command fragment"},
                    abstract={
                        "semantic_type": "external input influences a command string",
                        "api_category": "remote_input",
                    },
                    confidence=0.45,
                    evidence_refs=["family_fallback"],
                )
            ],
            "sinks": [
                SchemaElement(
                    role="sink",
                    concrete={"title": "Command execution sink"},
                    abstract={
                        "semantic_type": "input reaches a process or shell execution API",
                        "api_category": "command_execution",
                    },
                    confidence=0.45,
                    evidence_refs=["family_fallback"],
                )
            ],
            "sanitizers": [],
        }
    if family_id == "cwe-094-code-injection":
        return {
            "summary": "User-controlled input reaches code evaluation or dynamic execution without restriction.",
            "sources": [
                SchemaElement(
                    role="source",
                    concrete={"title": "User-controlled code fragment"},
                    abstract={
                        "semantic_type": "external input influences dynamically executed code",
                        "api_category": "remote_input",
                    },
                    confidence=0.45,
                    evidence_refs=["family_fallback"],
                )
            ],
            "sinks": [
                SchemaElement(
                    role="sink",
                    concrete={"title": "Dynamic code execution sink"},
                    abstract={
                        "semantic_type": "input reaches code evaluation or reflection-based execution",
                        "api_category": "code_execution",
                    },
                    confidence=0.45,
                    evidence_refs=["family_fallback"],
                )
            ],
            "sanitizers": [],
        }
    if family_id == "cwe-502-deserialization":
        return {
            "summary": "Untrusted serialized data reaches deserialization without sufficient type or source restrictions.",
            "sources": [
                SchemaElement(
                    role="source",
                    concrete={"title": "Untrusted serialized input"},
                    abstract={
                        "semantic_type": "external serialized bytes or object stream",
                        "api_category": "remote_input",
                    },
                    confidence=0.45,
                    evidence_refs=["family_fallback"],
                )
            ],
            "sinks": [
                SchemaElement(
                    role="sink",
                    concrete={"title": "Deserialization sink"},
                    abstract={
                        "semantic_type": "input reaches object deserialization",
                        "api_category": "deserialization",
                    },
                    confidence=0.45,
                    evidence_refs=["family_fallback"],
                )
            ],
            "sanitizers": [],
        }
    return {
        "summary": sample_context.note or f"Schema for {sample_context.sample.cve_id}",
        "sources": [],
        "sinks": [],
        "sanitizers": [],
    }


def _infer_patch_semantics_from_diff(sample: BenchmarkSample, family_id: str) -> PatchSemantics:
    diff_text = ""
    if sample.local_paths.diff_path and sample.local_paths.diff_path.exists():
        diff_text = sample.local_paths.diff_path.read_text(encoding="utf-8", errors="replace")
    lowered = diff_text.lower()
    changed_elements: list[dict[str, Any]] = []
    action = "other"
    before = ""
    after = ""

    if "escape" in lowered or "encode" in lowered or "entities" in lowered:
        action = "add_sanitizer"
        changed_elements.append({"type": "sanitizer_added"})
        before = "raw user-controlled value reaches sink without output encoding"
        after = "patched version encodes or escapes the value before the sink"
    elif any(token in lowered for token in ["check", "validate", "guard", "permission", "allow"]):
        action = "add_guard"
        changed_elements.append({"type": "guard_added"})
        before = "dangerous behavior is reachable without a sufficient check"
        after = "patched version adds validation or access control before the sink"
    elif family_id == "cwe-022-path-traversal":
        before = "user-controlled path reaches filesystem access without normalization or restriction"
        after = "patched version restricts or validates the path before filesystem access"
    elif family_id == "cwe-078-command-injection":
        before = "user-controlled command input reaches process execution"
        after = "patched version validates or constrains command execution"
    elif family_id == "cwe-094-code-injection":
        before = "user-controlled input reaches dynamic code execution"
        after = "patched version constrains or validates dynamic execution"
    elif family_id == "cwe-502-deserialization":
        before = "untrusted serialized input reaches deserialization"
        after = "patched version validates or restricts deserialization"

    return PatchSemantics(
        action=action,
        before=before,
        after=after,
        changed_elements=changed_elements,
    )


def _infer_query_constraints_for_context(sample_context: SampleContext) -> QueryConstraints:
    forbidden = [sample_context.sample.project]
    if sample_context.family_id == "cwe-079-xss":
        preferred = [
            "generic html output sink",
            "generic html escaping sanitizer",
            "dataflow-oriented path query",
        ]
        required = ["must_model_dataflow", "must_distinguish_fixed"]
    else:
        preferred = ["generic family-level source/sink abstraction"]
        required = ["must_distinguish_fixed"]
    return QueryConstraints(required=required, preferred=preferred, forbidden=forbidden)


def _collect_sample_context(
    cve_id: str,
    *,
    benchmark_manifest_path: Path | str | None = None,
) -> SampleContext:
    benchmark = (
        load_pilot_benchmark(benchmark_manifest_path)
        if benchmark_manifest_path
        else load_pilot_benchmark()
    )
    sample = benchmark.get_sample(cve_id)

    family_name = sample.cwe_name or sample.family_id
    note = ""
    for case in benchmark.list_seed_cases(runnable_only=False):
        if case.family_id == sample.family_id:
            family_name = case.family_name
            if case.seed.cve_id == cve_id:
                note = case.note
                break
            for target in case.positive_variants + case.hard_negatives:
                if target.sample.cve_id == cve_id:
                    note = target.construction_note or ""
                    break
    return SampleContext(sample=sample, family_id=sample.family_id, family_name=family_name, note=note)


def _build_schema_from_phase1(sample_context: SampleContext, sections: Phase1Sections) -> SchemaIR:
    evidence = [
        {
            "id": "phase1_sections",
            "type": "phase1_extracted_sections",
            "origin": str(sections.path),
        }
    ]
    if sample_context.sample.local_paths.diff_path:
        evidence.append(
            {
                "id": "sample_diff",
                "type": "patch_diff",
                "origin": str(sample_context.sample.local_paths.diff_path),
            }
        )

    return SchemaIR(
        schema_id=sample_context.sample.cve_id,
        family_id=sample_context.family_id,
        summary=_clean_summary(
            sections.vulnerability_summary.split("\n", 1)[0] if sections.vulnerability_summary else "",
            sample_context.note or _family_defaults_for_sample(sample_context)["summary"],
        ),
        language="java",
        sources=_deduplicate_elements(_parse_schema_elements(sections.sources, "source")),
        sinks=_deduplicate_elements(_parse_schema_elements(sections.sinks, "sink")),
        sanitizers=_deduplicate_elements(_parse_schema_elements(sections.sanitizers, "sanitizer")),
        guards=[],
        propagations=_deduplicate_elements(
            _parse_schema_elements(sections.additional_taint_steps, "propagation")
        ),
        evidence=evidence,
        abstractions=[
            {
                "type": "family_pattern",
                "predicate": sample_context.family_name,
                "support": ["phase1_sections"],
            }
        ],
        patch_semantics=_infer_patch_semantics(sample_context.sample, sections),
        query_constraints=_infer_query_constraints_for_context(sample_context),
    )


def _build_schema_from_diff_fallback(sample_context: SampleContext) -> SchemaIR:
    defaults = _family_defaults_for_sample(sample_context)
    evidence = []
    if sample_context.sample.local_paths.diff_path:
        evidence.append(
            {
                "id": "sample_diff",
                "type": "patch_diff",
                "origin": str(sample_context.sample.local_paths.diff_path),
            }
        )

    return SchemaIR(
        schema_id=sample_context.sample.cve_id,
        family_id=sample_context.family_id,
        summary=sample_context.note or defaults["summary"],
        language="java",
        sources=_deduplicate_elements(list(defaults["sources"])),
        sinks=_deduplicate_elements(list(defaults["sinks"])),
        sanitizers=_deduplicate_elements(list(defaults["sanitizers"])),
        guards=[],
        propagations=[],
        evidence=evidence,
        abstractions=[
            {
                "type": "family_pattern",
                "predicate": sample_context.family_name,
                "support": ["family_fallback"],
            }
        ],
        patch_semantics=_infer_patch_semantics_from_diff(
            sample_context.sample,
            sample_context.family_id,
        ),
        query_constraints=_infer_query_constraints_for_context(sample_context),
    )


def _infer_patch_semantics(sample: BenchmarkSample, sections: Phase1Sections) -> PatchSemantics:
    diff_text = ""
    if sample.local_paths.diff_path and sample.local_paths.diff_path.exists():
        diff_text = sample.local_paths.diff_path.read_text(encoding="utf-8", errors="replace")

    sanitizers_text = sections.sanitizers.lower()
    summary_text = sections.vulnerability_summary.lower()
    action = "other"
    changed_elements: list[dict[str, Any]] = []

    if "escapehtmlentities" in sanitizers_text or "+     Object[] args = { escapeHTMLEntities(extWiki) };" in diff_text:
        action = "add_sanitizer"
        changed_elements.append(
            {"type": "sanitizer_added", "symbol": "escapeHTMLEntities"}
        )
    elif "guard" in summary_text:
        action = "add_guard"
        changed_elements.append({"type": "guard_added"})

    before = ""
    after = ""
    if "The fix" in sections.vulnerability_summary:
        before_after = sections.vulnerability_summary
        before = "raw user-controlled value reaches sink without protection"
        after = "patched version adds protection before sink"
        if "escapeHTMLEntities" in before_after:
            after = "HTML entity escaping is added before rendering"

    return PatchSemantics(
        action=action,
        before=before,
        after=after,
        changed_elements=changed_elements,
    )


def _infer_query_constraints(seed_case: VariantSeedCase) -> QueryConstraints:
    forbidden = [seed_case.seed.project]
    if seed_case.family_id == "cwe-079-xss":
        preferred = [
            "generic html output sink",
            "generic html escaping sanitizer",
            "dataflow-oriented path query",
        ]
        required = ["must_model_dataflow", "must_distinguish_fixed"]
    else:
        preferred = ["generic family-level source/sink abstraction"]
        required = ["must_distinguish_fixed"]

    return QueryConstraints(
        required=required,
        preferred=preferred,
        forbidden=forbidden,
    )


def build_sample_schema(
    cve_id: str,
    *,
    benchmark_manifest_path: Path | str | None = None,
    qlcoder_output_root: Path | str = DEFAULT_EXTERNAL_QLCODER_OUTPUT_ROOT,
) -> SchemaIR:
    sample_context = _collect_sample_context(
        cve_id,
        benchmark_manifest_path=benchmark_manifest_path,
    )
    try:
        sections = load_phase1_sections(cve_id, output_root=qlcoder_output_root)
    except FileNotFoundError:
        return _build_schema_from_diff_fallback(sample_context)
    return _build_schema_from_phase1(sample_context, sections)


def build_seed_schema(
    cve_id: str,
    *,
    benchmark_manifest_path: Path | str | None = None,
    qlcoder_output_root: Path | str = DEFAULT_EXTERNAL_QLCODER_OUTPUT_ROOT,
) -> SchemaIR:
    benchmark = load_pilot_benchmark(benchmark_manifest_path) if benchmark_manifest_path else load_pilot_benchmark()
    benchmark.get_seed_case(cve_id, require_runnable=True)
    return build_sample_schema(
        cve_id,
        benchmark_manifest_path=benchmark_manifest_path,
        qlcoder_output_root=qlcoder_output_root,
    )


def save_schema(schema: SchemaIR, output_path: Path | str) -> Path:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(schema.to_dict(), indent=2), encoding="utf-8")
    return output_path
