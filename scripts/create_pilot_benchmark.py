#!/usr/bin/env python3
"""
Create and optionally prepare the curated pilot benchmark.

The script reads a curated pilot benchmark spec, enriches it with metadata from
project_info.csv and fix_info.csv, inspects local assets under cves/, and writes
an executable manifest that later benchmark/evaluation code can consume.

It can also reuse the existing repository/bootstrap scripts to fetch missing
repositories/diffs and build missing CodeQL databases.
"""

import argparse
import csv
import json
import os
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Set


ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_SPEC = ROOT_DIR / "benchmarks" / "pilot" / "pilot_spec.json"
DEFAULT_OUTPUT = ROOT_DIR / "benchmarks" / "pilot" / "pilot_manifest.json"
PROJECT_INFO = ROOT_DIR / "data" / "project_info.csv"
FIX_INFO = ROOT_DIR / "data" / "fix_info.csv"
CVES_PATH = ROOT_DIR / "cves"


def normalize_cwe_id(cwe_id: str) -> str:
    if not cwe_id:
        return ""
    digits = cwe_id.upper().replace("CWE-", "").strip()
    if digits.isdigit() and len(digits) < 3:
        digits = digits.zfill(3)
    return f"CWE-{digits}"


def is_test_file(file_path: str) -> bool:
    file_path_lower = file_path.lower()
    basename = os.path.basename(file_path_lower)

    if "/test/" in file_path_lower or "/tests/" in file_path_lower:
        return True

    if (
        basename.endswith("test.java")
        or basename.endswith("tests.java")
        or basename.startswith("test")
        or basename.endswith("testcase.java")
        or "unittest" in basename
        or "integrationtest" in basename
    ):
        return True

    if any(
        pattern in basename
        for pattern in [
            "testutil",
            "testhelper",
            "testbase",
            "abstracttest",
            "mocktest",
            "dummytest",
        ]
    ):
        return True

    return False


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_project_info() -> Dict[str, Dict[str, str]]:
    with PROJECT_INFO.open("r", encoding="utf-8") as handle:
        return {row["cve_id"]: row for row in csv.DictReader(handle)}


def load_fix_info() -> Dict[str, List[Dict[str, str]]]:
    grouped: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    with FIX_INFO.open("r", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            grouped[row["cve_id"]].append(row)
    return grouped


def find_local_repo_dir(cve_id: str, repo_name: str) -> Path | None:
    cve_dir = Path(CVES_PATH) / cve_id
    preferred = cve_dir / repo_name
    if preferred.exists():
        return preferred

    if not cve_dir.exists():
        return None

    for child in cve_dir.iterdir():
        if child.is_dir() and (child / ".git").exists() and child.name != f"{cve_id}-vul" and child.name != f"{cve_id}-fix":
            return child
    return None


def build_ground_truth(rows: List[Dict[str, str]]) -> Dict[str, List[str]]:
    filtered = [
        row
        for row in rows
        if row["file"].endswith(".java") and not is_test_file(row["file"])
    ]

    files = sorted({row["file"] for row in filtered})
    methods = sorted(
        {
            f"{row['file']}:{row['class']}:{row['method']}"
            for row in filtered
            if row.get("class") and row.get("method")
        }
    )

    return {"files": files, "methods": methods, "non_test_rows": len(filtered)}


def build_sample_record(
    cve_id: str,
    family_id: str,
    project_info: Dict[str, Dict[str, str]],
    fix_info: Dict[str, List[Dict[str, str]]],
) -> Dict[str, Any]:
    if cve_id not in project_info:
        raise ValueError(f"{cve_id} not found in {PROJECT_INFO}")
    if cve_id not in fix_info:
        raise ValueError(f"{cve_id} not found in {FIX_INFO}")

    project_row = project_info[cve_id]
    gt = build_ground_truth(fix_info[cve_id])
    if not gt["files"] or not gt["methods"]:
        raise ValueError(
            f"{cve_id} has no non-test ground truth after filtering fix_info rows"
        )

    cve_dir = Path(CVES_PATH) / cve_id
    repo_dir = find_local_repo_dir(cve_id, project_row["github_repository_name"])
    diff_path = cve_dir / f"{cve_id}.diff"
    vuln_db_path = cve_dir / f"{cve_id}-vul"
    fix_db_path = cve_dir / f"{cve_id}-fix"

    local_status = {
        "cve_dir_exists": cve_dir.exists(),
        "repo_exists": bool(repo_dir and repo_dir.exists()),
        "diff_exists": diff_path.exists(),
        "vuln_db_exists": (vuln_db_path / "db-java").exists(),
        "fix_db_exists": (fix_db_path / "db-java").exists(),
    }
    local_status["runnable_seed"] = bool(
        local_status["diff_exists"]
        and local_status["vuln_db_exists"]
        and local_status["fix_db_exists"]
    )

    return {
        "cve_id": cve_id,
        "family_id": family_id,
        "project": project_row["github_repository_name"],
        "project_slug": project_row["project_slug"],
        "github_username": project_row["github_username"],
        "github_repository_name": project_row["github_repository_name"],
        "github_url": project_row["github_url"],
        "cwe_id": project_row["cwe_id"],
        "normalized_cwe_id": normalize_cwe_id(project_row["cwe_id"]),
        "cwe_name": project_row["cwe_name"],
        "local_paths": {
            "cve_dir": str(cve_dir),
            "repo_dir": str(repo_dir) if repo_dir else None,
            "diff_path": str(diff_path),
            "vuln_db_path": str(vuln_db_path),
            "fix_db_path": str(fix_db_path),
        },
        "ground_truth_files": gt["files"],
        "ground_truth_methods": gt["methods"],
        "ground_truth_summary": {
            "num_files": len(gt["files"]),
            "num_methods": len(gt["methods"]),
            "non_test_rows": gt["non_test_rows"],
        },
        "local_status": local_status,
    }


def collect_cve_ids(spec: Dict[str, Any]) -> List[str]:
    cve_ids: Set[str] = set()
    for family in spec["families"]:
        for seed in family["seeds"]:
            cve_ids.add(seed["cve_id"])
            for variant in seed.get("positive_variants", []):
                cve_ids.add(variant["cve_id"])
            for negative in seed.get("hard_negatives", []):
                cve_ids.add(negative["cve_id"])
    return sorted(cve_ids)


def validate_family_membership(
    family: Dict[str, Any], sample_record: Dict[str, Any], relation_label: str
) -> None:
    expected = {normalize_cwe_id(value) for value in family["expected_cwe_ids"]}
    sample_cwe = sample_record["normalized_cwe_id"]
    if sample_cwe not in expected:
        raise ValueError(
            f"{relation_label} {sample_record['cve_id']} has {sample_cwe}, expected one of {sorted(expected)}"
        )


def generate_manifest(spec: Dict[str, Any]) -> Dict[str, Any]:
    project_info = load_project_info()
    fix_info = load_fix_info()

    samples: Dict[str, Dict[str, Any]] = {}
    families_out: List[Dict[str, Any]] = []
    total_variant_links = 0
    total_hard_negative_links = 0

    for family in spec["families"]:
        family_out = {
            "family_id": family["family_id"],
            "family_name": family["family_name"],
            "expected_cwe_ids": family["expected_cwe_ids"],
            "seeds": [],
        }

        for seed in family["seeds"]:
            seed_record = samples.get(seed["cve_id"])
            if seed_record is None:
                seed_record = build_sample_record(
                    seed["cve_id"], family["family_id"], project_info, fix_info
                )
                samples[seed["cve_id"]] = seed_record
            validate_family_membership(family, seed_record, "seed")

            seed_out = {
                "cve_id": seed["cve_id"],
                "note": seed.get("note", ""),
                "positive_variants": [],
                "hard_negatives": [],
            }

            for variant in seed.get("positive_variants", []):
                variant_record = samples.get(variant["cve_id"])
                if variant_record is None:
                    variant_record = build_sample_record(
                        variant["cve_id"],
                        family["family_id"],
                        project_info,
                        fix_info,
                    )
                    samples[variant["cve_id"]] = variant_record
                validate_family_membership(family, variant_record, "positive variant")
                total_variant_links += 1
                seed_out["positive_variants"].append(
                    {
                        "cve_id": variant["cve_id"],
                        "variant_type": variant["variant_type"],
                        "construction_note": variant["construction_note"],
                    }
                )

            for negative in seed.get("hard_negatives", []):
                negative_record = samples.get(negative["cve_id"])
                if negative_record is None:
                    negative_record = build_sample_record(
                        negative["cve_id"],
                        family["family_id"],
                        project_info,
                        fix_info,
                    )
                    samples[negative["cve_id"]] = negative_record
                total_hard_negative_links += 1
                seed_out["hard_negatives"].append(
                    {
                        "cve_id": negative["cve_id"],
                        "negative_type": negative["negative_type"],
                        "construction_note": negative["construction_note"],
                        "negative_cwe_id": negative_record["normalized_cwe_id"],
                    }
                )

            family_out["seeds"].append(seed_out)

        families_out.append(family_out)

    referenced = collect_cve_ids(spec)
    runnable_seeds = 0
    missing_repo_or_diff_all = []
    missing_dbs_all = []
    missing_repo_or_diff_seeds = []
    missing_dbs_seeds = []

    for cve_id, sample in samples.items():
        status = sample["local_status"]
        if not status["repo_exists"] or not status["diff_exists"]:
            missing_repo_or_diff_all.append(cve_id)
        if not status["vuln_db_exists"] or not status["fix_db_exists"]:
            missing_dbs_all.append(cve_id)

    for family in families_out:
        for seed in family["seeds"]:
            status = samples[seed["cve_id"]]["local_status"]
            if status["runnable_seed"]:
                runnable_seeds += 1
            if not status["repo_exists"] or not status["diff_exists"]:
                missing_repo_or_diff_seeds.append(seed["cve_id"])
            if not status["vuln_db_exists"] or not status["fix_db_exists"]:
                missing_dbs_seeds.append(seed["cve_id"])

    manifest = {
        "metadata": {
            "name": spec["name"],
            "version": spec["version"],
            "description": spec["description"],
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "seed_count": sum(len(family["seeds"]) for family in families_out),
            "family_count": len(families_out),
            "referenced_cve_count": len(referenced),
            "positive_variant_links": total_variant_links,
            "hard_negative_links": total_hard_negative_links,
            "runnable_seed_count": runnable_seeds,
        },
        "asset_summary": {
            "missing_repo_or_diff_all": sorted(set(missing_repo_or_diff_all)),
            "missing_dbs_all": sorted(set(missing_dbs_all)),
            "missing_repo_or_diff_seeds": sorted(set(missing_repo_or_diff_seeds)),
            "missing_dbs_seeds": sorted(set(missing_dbs_seeds)),
        },
        "families": families_out,
        "samples": {cve_id: samples[cve_id] for cve_id in sorted(samples)},
    }
    return manifest


def run_command(command: List[str], cwd: Path | None = None) -> None:
    print(f"Running: {' '.join(command)}")
    subprocess.run(command, cwd=str(cwd) if cwd else None, check=True)


def prepare_assets(manifest: Dict[str, Any], build_dbs: bool, asset_scope: str) -> None:
    all_seed_cves = []
    repo_or_diff_missing = []
    db_missing = []

    for family in manifest["families"]:
        for seed in family["seeds"]:
            cve_id = seed["cve_id"]
            all_seed_cves.append(cve_id)
            status = manifest["samples"][cve_id]["local_status"]
            if not status["repo_exists"] or not status["diff_exists"]:
                repo_or_diff_missing.append(cve_id)
            if build_dbs and (not status["vuln_db_exists"] or not status["fix_db_exists"]):
                db_missing.append(cve_id)

    if asset_scope == "all":
        referenced = sorted(manifest["samples"].keys())
        for cve_id in referenced:
            status = manifest["samples"][cve_id]["local_status"]
            if not status["repo_exists"] or not status["diff_exists"]:
                if cve_id not in repo_or_diff_missing:
                    repo_or_diff_missing.append(cve_id)
            if build_dbs and (not status["vuln_db_exists"] or not status["fix_db_exists"]):
                if cve_id not in db_missing:
                    db_missing.append(cve_id)

    if repo_or_diff_missing:
        run_command(
            [
                sys.executable,
                str(ROOT_DIR / "scripts" / "get_cve_repos.py"),
                "--cves",
                ",".join(sorted(set(repo_or_diff_missing))),
            ],
            cwd=ROOT_DIR,
        )
    else:
        print("No missing repositories or diffs detected for the pilot benchmark.")

    if build_dbs:
        if db_missing:
            for cve_id in sorted(set(db_missing)):
                run_command(
                    [
                        sys.executable,
                        str(ROOT_DIR / "scripts" / "build_codeql_dbs.py"),
                        "--cve-id",
                        cve_id,
                    ],
                    cwd=ROOT_DIR,
                )
        else:
            print("No missing CodeQL databases detected for the pilot benchmark.")


def print_summary(manifest: Dict[str, Any]) -> None:
    metadata = manifest["metadata"]
    print("")
    print("Pilot benchmark summary")
    print("-----------------------")
    print(f"Families: {metadata['family_count']}")
    print(f"Seed CVEs: {metadata['seed_count']}")
    print(f"Referenced CVEs: {metadata['referenced_cve_count']}")
    print(f"Positive variant links: {metadata['positive_variant_links']}")
    print(f"Hard negative links: {metadata['hard_negative_links']}")
    print(f"Runnable seed count: {metadata['runnable_seed_count']}")
    print(
        f"Missing repo/diff (all referenced CVEs): "
        f"{manifest['asset_summary']['missing_repo_or_diff_all']}"
    )
    print(
        f"Missing DBs (all referenced CVEs): "
        f"{manifest['asset_summary']['missing_dbs_all']}"
    )
    print(
        f"Missing repo/diff (seed CVEs only): "
        f"{manifest['asset_summary']['missing_repo_or_diff_seeds']}"
    )
    print(
        f"Missing DBs (seed CVEs only): "
        f"{manifest['asset_summary']['missing_dbs_seeds']}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Create the pilot benchmark manifest")
    parser.add_argument("--spec", default=str(DEFAULT_SPEC), help="Path to pilot spec JSON")
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        help="Path to the generated pilot manifest JSON",
    )
    parser.add_argument(
        "--prepare-assets",
        action="store_true",
        help="Use existing scripts to fetch missing repos/diffs for referenced CVEs",
    )
    parser.add_argument(
        "--build-dbs",
        action="store_true",
        help="Also build missing CodeQL databases after fetching repos",
    )
    parser.add_argument(
        "--asset-scope",
        choices=["seeds", "all"],
        default="seeds",
        help="Prepare assets for seed CVEs only or for all referenced CVEs",
    )
    args = parser.parse_args()

    spec_path = Path(args.spec)
    output_path = Path(args.output)

    spec = load_json(spec_path)
    manifest = generate_manifest(spec)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Wrote manifest to {output_path}")
    print_summary(manifest)

    if args.prepare_assets:
        prepare_assets(
            manifest,
            build_dbs=args.build_dbs,
            asset_scope=args.asset_scope,
        )
        refreshed = generate_manifest(spec)
        output_path.write_text(json.dumps(refreshed, indent=2), encoding="utf-8")
        print(f"Refreshed manifest written to {output_path}")
        print_summary(refreshed)


if __name__ == "__main__":
    main()
