#!/usr/bin/env python3

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent.parent
RUNNER_PATH = ROOT_DIR / "scripts" / "run_pilot_baseline.py"


class PilotBaselineRunnerDryRunTest(unittest.TestCase):
    def test_runner_plans_codex_generation_and_benchmark_evaluation(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            analysis_root = tmp_path / "analysis"
            benchmark_output_dir = tmp_path / "benchmark"
            runner_output_dir = tmp_path / "runner"

            result = subprocess.run(
                [
                    "python3",
                    str(RUNNER_PATH),
                    "--family-id",
                    "cwe-079-xss",
                    "--agent",
                    "codex",
                    "--model",
                    "gpt-5.4",
                    "--codex-use-local-config",
                    "--analysis-root",
                    str(analysis_root),
                    "--benchmark-output-dir",
                    str(benchmark_output_dir),
                    "--runner-output-dir",
                    str(runner_output_dir),
                ],
                cwd=ROOT_DIR,
                capture_output=True,
                text=True,
                check=True,
            )

            self.assertIn("Execution mode: dry-run", result.stdout)
            self.assertIn("Selected seed cases: 2", result.stdout)
            self.assertIn("Generation requested: False (agent=codex, model=gpt-5.4", result.stdout)
            self.assertIn("Evaluation requested: False", result.stdout)

            plan_path = runner_output_dir / "pilot_baseline_plan.json"
            self.assertTrue(plan_path.exists())

            payload = json.loads(plan_path.read_text(encoding="utf-8"))
            self.assertEqual("dry-run", payload["execution_mode"])
            self.assertEqual(2, payload["selected_seed_count"])
            self.assertFalse(payload["generation"]["execute"])
            self.assertFalse(payload["evaluation"]["execute"])
            self.assertEqual("codex", payload["generation"]["agent"])
            self.assertEqual("gpt-5.4", payload["generation"]["model"])
            self.assertTrue(payload["generation"]["codex_use_local_config"])
            self.assertEqual(2, len(payload["generation"]["entries"]))

            seed_ids = {entry["cve_id"] for entry in payload["generation"]["entries"]}
            self.assertEqual({"CVE-2019-10077", "CVE-2017-14735"}, seed_ids)

            jspwiki_entry = next(
                entry
                for entry in payload["generation"]["entries"]
                if entry["cve_id"] == "CVE-2019-10077"
            )
            command = jspwiki_entry["command"]
            self.assertIn("--codex-use-local-config", command)
            self.assertIn("--vuln-db", command)
            self.assertIn("--fixed-db", command)
            self.assertIn("--diff", command)

            benchmark_command = payload["evaluation"]["command"]
            self.assertIn(str(ROOT_DIR / "scripts" / "run_pilot_benchmark.py"), benchmark_command)
            self.assertIn("--analysis-root", benchmark_command)
            self.assertIn(str(analysis_root.resolve()), benchmark_command)


if __name__ == "__main__":
    unittest.main()
