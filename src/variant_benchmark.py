#!/usr/bin/env python3

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple

try:
    from .data_types import VulnAnalysisTask
except ImportError:
    from data_types import VulnAnalysisTask


ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_PILOT_MANIFEST_PATH = ROOT_DIR / "benchmarks" / "pilot" / "pilot_manifest.json"


class VariantBenchmarkError(ValueError):
    """Raised when the benchmark manifest is malformed or inconsistent."""


def _optional_path(raw_value: Optional[str]) -> Optional[Path]:
    if raw_value is None:
        return None
    return Path(raw_value)


@dataclass(frozen=True)
class SampleLocalPaths:
    cve_dir: Optional[Path]
    repo_dir: Optional[Path]
    diff_path: Optional[Path]
    vuln_db_path: Optional[Path]
    fix_db_path: Optional[Path]

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "SampleLocalPaths":
        return cls(
            cve_dir=_optional_path(raw.get("cve_dir")),
            repo_dir=_optional_path(raw.get("repo_dir")),
            diff_path=_optional_path(raw.get("diff_path")),
            vuln_db_path=_optional_path(raw.get("vuln_db_path")),
            fix_db_path=_optional_path(raw.get("fix_db_path")),
        )


@dataclass(frozen=True)
class SampleLocalStatus:
    cve_dir_exists: bool
    repo_exists: bool
    diff_exists: bool
    vuln_db_exists: bool
    fix_db_exists: bool
    runnable_seed: bool

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "SampleLocalStatus":
        return cls(
            cve_dir_exists=bool(raw.get("cve_dir_exists", False)),
            repo_exists=bool(raw.get("repo_exists", False)),
            diff_exists=bool(raw.get("diff_exists", False)),
            vuln_db_exists=bool(raw.get("vuln_db_exists", False)),
            fix_db_exists=bool(raw.get("fix_db_exists", False)),
            runnable_seed=bool(raw.get("runnable_seed", False)),
        )


@dataclass(frozen=True)
class BenchmarkSample:
    cve_id: str
    family_id: str
    project: str
    project_slug: str
    github_username: str
    github_repository_name: str
    github_url: str
    cwe_id: str
    normalized_cwe_id: str
    cwe_name: str
    local_paths: SampleLocalPaths
    ground_truth_files: Tuple[str, ...]
    ground_truth_methods: Tuple[str, ...]
    ground_truth_summary: Dict[str, Any]
    local_status: SampleLocalStatus

    @classmethod
    def from_manifest_dict(cls, raw: Dict[str, Any]) -> "BenchmarkSample":
        return cls(
            cve_id=raw["cve_id"],
            family_id=raw["family_id"],
            project=raw["project"],
            project_slug=raw["project_slug"],
            github_username=raw["github_username"],
            github_repository_name=raw["github_repository_name"],
            github_url=raw["github_url"],
            cwe_id=raw["cwe_id"],
            normalized_cwe_id=raw["normalized_cwe_id"],
            cwe_name=raw["cwe_name"],
            local_paths=SampleLocalPaths.from_dict(raw["local_paths"]),
            ground_truth_files=tuple(raw.get("ground_truth_files", [])),
            ground_truth_methods=tuple(raw.get("ground_truth_methods", [])),
            ground_truth_summary=dict(raw.get("ground_truth_summary", {})),
            local_status=SampleLocalStatus.from_dict(raw["local_status"]),
        )

    def read_diff_text(self) -> str:
        if self.local_paths.diff_path is None:
            raise FileNotFoundError(f"Diff path is missing for {self.cve_id}")
        return self.local_paths.diff_path.read_text(encoding="utf-8", errors="replace")

    def require_seed_assets(self) -> None:
        if (
            self.local_paths.vuln_db_path is None
            or self.local_paths.fix_db_path is None
            or self.local_paths.diff_path is None
        ):
            raise FileNotFoundError(
                f"Seed paths are incomplete for {self.cve_id}: {self.local_paths}"
            )
        if not self.local_status.runnable_seed:
            raise FileNotFoundError(
                f"Seed assets are incomplete for {self.cve_id}: {self.local_status}"
            )

    def to_vuln_analysis_task(
        self,
        *,
        output_dir: str = "benchmark_runs",
        working_dir: Optional[str] = None,
        max_iteration: int = 1,
        model: str = "sonnet",
        ast_cache: Optional[str] = None,
        nvd_cache: Optional[str] = None,
    ) -> VulnAnalysisTask:
        self.require_seed_assets()
        vuln_db_path = self.local_paths.vuln_db_path
        fix_db_path = self.local_paths.fix_db_path
        if vuln_db_path is None or fix_db_path is None:
            raise FileNotFoundError(f"Database paths are missing for {self.cve_id}")
        return VulnAnalysisTask(
            vuln_db_path=str(vuln_db_path),
            fixed_db_path=str(fix_db_path),
            fix_commit_diff=self.read_diff_text(),
            vulnerability_type=self.cwe_name,
            cve_id=self.cve_id,
            output_dir=output_dir,
            working_dir=working_dir,
            max_iteration=max_iteration,
            model=model,
            ast_cache=ast_cache,
            nvd_cache=nvd_cache,
        )


@dataclass(frozen=True)
class VariantTarget:
    role: str
    sample: BenchmarkSample
    expected_vuln_hit: bool
    expected_fix_hit: bool
    variant_type: Optional[str] = None
    negative_type: Optional[str] = None
    construction_note: Optional[str] = None


@dataclass(frozen=True)
class VariantSeedCase:
    family_id: str
    family_name: str
    expected_cwe_ids: Tuple[str, ...]
    seed: BenchmarkSample
    note: str
    positive_variants: Tuple[VariantTarget, ...]
    hard_negatives: Tuple[VariantTarget, ...]

    @property
    def runnable(self) -> bool:
        return self.seed.local_status.runnable_seed

    def evaluation_targets(self, include_seed: bool = True) -> Tuple[VariantTarget, ...]:
        targets = []
        if include_seed:
            targets.append(
                VariantTarget(
                    role="seed",
                    sample=self.seed,
                    expected_vuln_hit=True,
                    expected_fix_hit=False,
                    construction_note=self.note,
                )
            )
        targets.extend(self.positive_variants)
        targets.extend(self.hard_negatives)
        return tuple(targets)

    def to_vuln_analysis_task(self, **kwargs: Any) -> VulnAnalysisTask:
        return self.seed.to_vuln_analysis_task(**kwargs)


class VariantBenchmark:
    """Bridge layer from the pilot manifest to code-consumable benchmark objects."""

    def __init__(
        self,
        *,
        manifest_path: Path,
        metadata: Dict[str, Any],
        asset_summary: Dict[str, Any],
        samples: Dict[str, BenchmarkSample],
        seed_cases: Tuple[VariantSeedCase, ...],
    ):
        self.manifest_path = manifest_path
        self.metadata = metadata
        self.asset_summary = asset_summary
        self.samples = samples
        self._seed_cases = seed_cases
        self._seed_case_by_cve = {case.seed.cve_id: case for case in seed_cases}

    @classmethod
    def from_manifest(
        cls, manifest_path: Path | str = DEFAULT_PILOT_MANIFEST_PATH
    ) -> "VariantBenchmark":
        manifest_path = Path(manifest_path)
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))

        samples = {
            cve_id: BenchmarkSample.from_manifest_dict(sample)
            for cve_id, sample in raw["samples"].items()
        }

        seed_cases = []
        for family in raw["families"]:
            family_id = family["family_id"]
            family_name = family["family_name"]
            expected_cwe_ids = tuple(family.get("expected_cwe_ids", []))

            for seed_entry in family["seeds"]:
                seed_cve_id = seed_entry["cve_id"]
                if seed_cve_id not in samples:
                    raise VariantBenchmarkError(
                        f"Seed {seed_cve_id} is missing from manifest samples"
                    )

                seed_sample = samples[seed_cve_id]
                if seed_sample.family_id != family_id:
                    raise VariantBenchmarkError(
                        f"Seed {seed_cve_id} belongs to {seed_sample.family_id}, "
                        f"expected {family_id}"
                    )

                positive_variants = tuple(
                    cls._build_positive_target(samples, family_id, entry)
                    for entry in seed_entry.get("positive_variants", [])
                )
                hard_negatives = tuple(
                    cls._build_negative_target(samples, entry)
                    for entry in seed_entry.get("hard_negatives", [])
                )

                seed_cases.append(
                    VariantSeedCase(
                        family_id=family_id,
                        family_name=family_name,
                        expected_cwe_ids=expected_cwe_ids,
                        seed=seed_sample,
                        note=seed_entry.get("note", ""),
                        positive_variants=positive_variants,
                        hard_negatives=hard_negatives,
                    )
                )

        return cls(
            manifest_path=manifest_path,
            metadata=dict(raw.get("metadata", {})),
            asset_summary=dict(raw.get("asset_summary", {})),
            samples=samples,
            seed_cases=tuple(seed_cases),
        )

    @staticmethod
    def _build_positive_target(
        samples: Dict[str, BenchmarkSample], family_id: str, entry: Dict[str, Any]
    ) -> VariantTarget:
        cve_id = entry["cve_id"]
        sample = VariantBenchmark._require_sample(samples, cve_id)
        if sample.family_id != family_id:
            raise VariantBenchmarkError(
                f"Positive variant {cve_id} belongs to {sample.family_id}, expected {family_id}"
            )
        return VariantTarget(
            role="positive_variant",
            sample=sample,
            expected_vuln_hit=True,
            expected_fix_hit=False,
            variant_type=entry.get("variant_type"),
            construction_note=entry.get("construction_note"),
        )

    @staticmethod
    def _build_negative_target(
        samples: Dict[str, BenchmarkSample], entry: Dict[str, Any]
    ) -> VariantTarget:
        cve_id = entry["cve_id"]
        sample = VariantBenchmark._require_sample(samples, cve_id)
        return VariantTarget(
            role="hard_negative",
            sample=sample,
            expected_vuln_hit=False,
            expected_fix_hit=False,
            negative_type=entry.get("negative_type"),
            construction_note=entry.get("construction_note"),
        )

    @staticmethod
    def _require_sample(
        samples: Dict[str, BenchmarkSample], cve_id: str
    ) -> BenchmarkSample:
        if cve_id not in samples:
            raise VariantBenchmarkError(
                f"Referenced CVE {cve_id} is missing from manifest samples"
            )
        return samples[cve_id]

    def list_seed_cases(
        self, *, runnable_only: bool = True, family_id: Optional[str] = None
    ) -> Tuple[VariantSeedCase, ...]:
        cases: Iterable[VariantSeedCase] = self._seed_cases
        if family_id is not None:
            cases = (case for case in cases if case.family_id == family_id)
        if runnable_only:
            cases = (case for case in cases if case.runnable)
        return tuple(cases)

    def get_seed_case(
        self, cve_id: str, *, require_runnable: bool = False
    ) -> VariantSeedCase:
        if cve_id not in self._seed_case_by_cve:
            raise KeyError(f"Unknown seed CVE: {cve_id}")
        case = self._seed_case_by_cve[cve_id]
        if require_runnable and not case.runnable:
            raise FileNotFoundError(f"Seed case is not runnable: {cve_id}")
        return case

    def get_sample(self, cve_id: str) -> BenchmarkSample:
        return self._require_sample(self.samples, cve_id)

    def summary(self) -> Dict[str, Any]:
        return {
            "manifest_path": str(self.manifest_path),
            "family_count": len({case.family_id for case in self._seed_cases}),
            "seed_count": len(self._seed_cases),
            "runnable_seed_count": len(self.list_seed_cases(runnable_only=True)),
            "referenced_sample_count": len(self.samples),
        }


def load_pilot_benchmark(
    manifest_path: Path | str = DEFAULT_PILOT_MANIFEST_PATH,
) -> VariantBenchmark:
    return VariantBenchmark.from_manifest(manifest_path)
