# Pilot Benchmark

This directory contains a curated pilot benchmark for the research plan in
[`PAPER_EXECUTION_PLAN.md`](/root/qlcoder/PAPER_EXECUTION_PLAN.md).

The pilot benchmark is intentionally small enough to iterate on quickly, but
structured enough to exercise the future `variant benchmark + variant-level
objective + schema IR` pipeline:

- multiple vulnerability families
- seed CVEs with original `vuln/fix` evaluation pairs
- positive variants for same-repo and cross-repo generalization
- a small number of contrastive negatives where same-repo alternatives exist

## Files

- [`pilot_spec.json`](/root/qlcoder/benchmarks/pilot/pilot_spec.json)
  Curated benchmark design: families, seeds, positive variants, and optional
  hard negatives.
- [`pilot_manifest.json`](/root/qlcoder/benchmarks/pilot/pilot_manifest.json)
  Generated manifest enriched with metadata, local paths, ground truth, and
  asset status.

## Generate The Manifest

From the project root:

```sh
python3 scripts/create_pilot_benchmark.py
```

This reads `pilot_spec.json`, enriches it from `data/project_info.csv` and
`data/fix_info.csv`, inspects local assets under `cves/`, and writes
`pilot_manifest.json`.

## Prepare Missing Assets

To fetch missing repositories and diffs for every referenced CVE:

```sh
python3 scripts/create_pilot_benchmark.py --prepare-assets --asset-scope all
```

To also build missing CodeQL databases:

```sh
python3 scripts/create_pilot_benchmark.py --prepare-assets --build-dbs --asset-scope all
```

To prepare only the seed CVEs first, which is usually the right first step:

```sh
python3 scripts/create_pilot_benchmark.py --prepare-assets --build-dbs
```

The script reuses the existing project bootstrap scripts:

- [`get_cve_repos.py`](/root/qlcoder/scripts/get_cve_repos.py)
- [`build_codeql_dbs.py`](/root/qlcoder/scripts/build_codeql_dbs.py)

## Known Asset Notes

- `CVE-2017-14735` currently uses a locally validated substitute fix endpoint
  `e76f02a77afb4e43b897f13d17b5bc1260b8afde` for pilot asset preparation,
  because the fix SHA recorded in `data/project_info.csv`
  (`82da009e733a989a57190cd6aa1b6824724f6d36`) is not reachable from the
  upstream `nahsra/antisamy` repository snapshot available during preparation.
  The substitute endpoint still changes the benchmark ground-truth files
  `Policy.java`, `AntiSamyDOMScanner.java`, and `AntiSamySAXScanner.java`, so
  it is suitable for local pilot evaluation. Keep this deviation in mind if
  you later regenerate assets or publish the benchmark.
- `CVE-2025-27531` currently uses the module-level source root
  `inlong/inlong-manager` for local pilot database creation. The full repository
  buildless extraction pulled in unrelated monorepo modules and was
  disproportionately expensive, while all recorded ground-truth files for this
  CVE live under `inlong-manager/`. This keeps the seed runnable for pilot
  evaluation, but it is another local preparation deviation worth revisiting
  before artifact release.

## Current Pilot Scope

The curated spec currently covers:

- CWE-022 Path Traversal
- CWE-079 XSS
- CWE-078 Command Injection
- CWE-094 Code Injection
- CWE-502 Deserialization of Untrusted Data

This first pilot is designed for fast iteration, not final publication scale.
The next step after stabilizing this manifest is to wire it into
`variant_benchmark.py` and the evaluation pipeline.
