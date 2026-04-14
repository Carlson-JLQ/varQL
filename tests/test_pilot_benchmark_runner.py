#!/usr/bin/env python3

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent.parent
RUNNER_PATH = ROOT_DIR / "scripts" / "run_pilot_benchmark.py"
QUERY_PATH = ROOT_DIR / "src" / "queries" / "fetch_func_locs.ql"


class PilotBenchmarkRunnerDryRunTest(unittest.TestCase):
    def test_runner_writes_benchmark_summary_for_all_runnable_seeds(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_dir = Path(tmp_dir)
            result = subprocess.run(
                [
                    "python3",
                    str(RUNNER_PATH),
                    "--default-query",
                    str(QUERY_PATH),
                    "--output-dir",
                    str(output_dir),
                ],
                cwd=ROOT_DIR,
                capture_output=True,
                text=True,
                check=True,
            )

            self.assertIn("Execution mode: dry-run", result.stdout)
            self.assertIn("Planned seed cases: 8", result.stdout)
            self.assertIn("Query-available seed cases: 8", result.stdout)
            self.assertIn("Executed seed cases: 0", result.stdout)

            summary_path = output_dir / "pilot_benchmark_summary.json"
            self.assertTrue(summary_path.exists())

            summary_payload = json.loads(summary_path.read_text(encoding="utf-8"))
            summary = summary_payload["summary"]
            self.assertEqual("dry-run", summary_payload["execution_mode"])
            self.assertEqual(8, summary["planned_seed_cases"])
            self.assertEqual(8, summary["query_available_seed_cases"])
            self.assertEqual(0, summary["query_missing_seed_cases"])
            self.assertEqual(0, summary["executed_seed_cases"])
            self.assertEqual(0, summary["seed_success_count"])

            seed_results = summary_payload["seed_results"]
            self.assertEqual(8, len(seed_results))

            jspwiki_result = next(
                result
                for result in seed_results
                if result["seed_case"]["seed_cve_id"] == "CVE-2019-10077"
            )
            self.assertEqual("default_query", jspwiki_result["query"]["source"])
            self.assertTrue(jspwiki_result["query"]["exists"])
            self.assertEqual(4, jspwiki_result["plan"]["target_count"])
            self.assertEqual(4, jspwiki_result["plan"]["runnable_target_count"])


class PilotBenchmarkDiscoveryTest(unittest.TestCase):
    def test_runner_discovers_latest_query_from_analysis_root(self):
        from scripts.run_pilot_benchmark import discover_queries_from_analysis_root

        with tempfile.TemporaryDirectory() as tmp_dir:
            analysis_root = Path(tmp_dir)

            run_dir = analysis_root / "run_a"
            run_dir.mkdir(parents=True)
            query_path = run_dir / "CVE-2019-10077-query-iter-2.ql"
            query_path.write_text("/** @kind problem */\nselect 1\n", encoding="utf-8")
            metadata_path = run_dir / "iterative_metadata.json"
            metadata_path.write_text(
                json.dumps(
                    {
                        "analysis_metadata": {
                            "cve_id": "CVE-2019-10077",
                            "iterations": [
                                {
                                    "query_path": str(query_path),
                                }
                            ],
                        },
                        "file_inventory": {
                            "query_files": [query_path.name],
                        },
                    }
                ),
                encoding="utf-8",
            )

            discovered = discover_queries_from_analysis_root(analysis_root)
            self.assertIn("CVE-2019-10077", discovered)
            self.assertEqual(query_path.resolve(), discovered["CVE-2019-10077"])


if __name__ == "__main__":
    unittest.main()
