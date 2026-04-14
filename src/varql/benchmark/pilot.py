from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


VARQL_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_EXTERNAL_QLCODER_ROOT = VARQL_ROOT.parent / "qlcoder"
DEFAULT_PILOT_MANIFEST_PATH = (
    DEFAULT_EXTERNAL_QLCODER_ROOT / "benchmarks" / "pilot" / "pilot_manifest.json"
)


class BenchmarkError(ValueError):
    """Raised when a benchmark manifest is malformed or inconsistent."""


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
    def from_dict(cls, raw: dict[str, Any]) -> "SampleLocalPaths":
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
    def from_dict(cls, raw: dict[str, Any]) -> "SampleLocalStatus":
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
    cwe_id: str
    cwe_name: str
    local_paths: SampleLocalPaths
    ground_truth_files: tuple[str, ...]
    ground_truth_methods: tuple[str, ...]
    local_status: SampleLocalStatus

    @classmethod
    def from_manifest_dict(cls, raw: dict[str, Any]) -> "BenchmarkSample":
        return cls(
            cve_id=raw["cve_id"],
            family_id=raw["family_id"],
            project=raw["project"],
            cwe_id=raw["cwe_id"],
            cwe_name=raw["cwe_name"],
            local_paths=SampleLocalPaths.from_dict(raw["local_paths"]),
            ground_truth_files=tuple(raw.get("ground_truth_files", [])),
            ground_truth_methods=tuple(raw.get("ground_truth_methods", [])),
            local_status=SampleLocalStatus.from_dict(raw["local_status"]),
        )

    @property
    def runnable(self) -> bool:
        return self.local_status.runnable_seed


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
    expected_cwe_ids: tuple[str, ...]
    seed: BenchmarkSample
    note: str
    positive_variants: tuple[VariantTarget, ...]
    hard_negatives: tuple[VariantTarget, ...]

    @property
    def runnable(self) -> bool:
        return self.seed.runnable

    def evaluation_targets(self, include_seed: bool = True) -> tuple[VariantTarget, ...]:
        targets: list[VariantTarget] = []
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

    def split_variants(self) -> tuple[tuple[VariantTarget, ...], tuple[VariantTarget, ...]]:
        """Return (seen_variants, held_out_variants) using a deterministic default strategy.

        Strategy:
        - prefer one `same_repo` positive variant as the seen refinement variant
        - otherwise use the first positive variant as seen
        - all remaining positives are held out
        """
        positives = list(self.positive_variants)
        if not positives:
            return (), ()

        seen_index = 0
        for idx, target in enumerate(positives):
            if target.variant_type == "same_repo":
                seen_index = idx
                break

        seen = (positives.pop(seen_index),)
        held_out = tuple(positives)
        return seen, held_out

    def split_summary(self) -> dict[str, Any]:
        seen, held_out = self.split_variants()
        return {
            "seed": self.seed.cve_id,
            "seen_variants": [target.sample.cve_id for target in seen],
            "held_out_variants": [target.sample.cve_id for target in held_out],
            "hard_negatives": [target.sample.cve_id for target in self.hard_negatives],
        }


class PilotBenchmark:
    def __init__(
        self,
        *,
        manifest_path: Path,
        metadata: dict[str, Any],
        asset_summary: dict[str, Any],
        samples: dict[str, BenchmarkSample],
        seed_cases: tuple[VariantSeedCase, ...],
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
    ) -> "PilotBenchmark":
        manifest_path = Path(manifest_path)
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))

        samples = {
            cve_id: BenchmarkSample.from_manifest_dict(sample)
            for cve_id, sample in raw["samples"].items()
        }

        seed_cases: list[VariantSeedCase] = []
        for family in raw["families"]:
            family_id = family["family_id"]
            family_name = family["family_name"]
            expected_cwe_ids = tuple(family.get("expected_cwe_ids", []))

            for seed_entry in family["seeds"]:
                seed_cve_id = seed_entry["cve_id"]
                if seed_cve_id not in samples:
                    raise BenchmarkError(
                        f"Seed {seed_cve_id} is missing from manifest samples"
                    )

                seed_sample = samples[seed_cve_id]
                if seed_sample.family_id != family_id:
                    raise BenchmarkError(
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
        samples: dict[str, BenchmarkSample], family_id: str, entry: dict[str, Any]
    ) -> VariantTarget:
        cve_id = entry["cve_id"]
        sample = PilotBenchmark._require_sample(samples, cve_id)
        if sample.family_id != family_id:
            raise BenchmarkError(
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
        samples: dict[str, BenchmarkSample], entry: dict[str, Any]
    ) -> VariantTarget:
        cve_id = entry["cve_id"]
        sample = PilotBenchmark._require_sample(samples, cve_id)
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
        samples: dict[str, BenchmarkSample], cve_id: str
    ) -> BenchmarkSample:
        if cve_id not in samples:
            raise BenchmarkError(
                f"Referenced CVE {cve_id} is missing from manifest samples"
            )
        return samples[cve_id]

    def list_seed_cases(
        self, *, runnable_only: bool = True, family_id: Optional[str] = None
    ) -> tuple[VariantSeedCase, ...]:
        cases = self._seed_cases
        if family_id is not None:
            cases = tuple(case for case in cases if case.family_id == family_id)
        if runnable_only:
            cases = tuple(case for case in cases if case.runnable)
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

    def summary(self) -> dict[str, Any]:
        return {
            "manifest_path": str(self.manifest_path),
            "family_count": len({case.family_id for case in self._seed_cases}),
            "seed_count": len(self._seed_cases),
            "runnable_seed_count": len(self.list_seed_cases(runnable_only=True)),
            "referenced_sample_count": len(self.samples),
        }


def load_pilot_benchmark(
    manifest_path: Path | str = DEFAULT_PILOT_MANIFEST_PATH,
) -> PilotBenchmark:
    return PilotBenchmark.from_manifest(manifest_path)
