#!/usr/bin/env python3

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent.parent
RUNNER_PATH = ROOT_DIR / "scripts" / "run_variant_seed_case.py"
QUERY_PATH = ROOT_DIR / "src" / "queries" / "fetch_func_locs.ql"


class VariantRunnerDryRunTest(unittest.TestCase):
    def test_runner_writes_dry_run_plan(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_dir = Path(tmp_dir)
            result = subprocess.run(
                [
                    "python3",
                    str(RUNNER_PATH),
                    "--seed-cve",
                    "CVE-2019-10077",
                    "--query-path",
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
            self.assertIn("Seed: CVE-2019-10077", result.stdout)
            self.assertIn("Runnable targets: 4/4", result.stdout)

            plan_path = output_dir / "variant_seed_case_plan.json"
            self.assertTrue(plan_path.exists())

            plan = json.loads(plan_path.read_text())
            self.assertEqual("dry-run", plan["execution_mode"])
            self.assertEqual("CVE-2019-10077", plan["seed_case"]["seed_cve_id"])
            self.assertEqual(4, plan["target_count"])
            self.assertEqual(4, plan["runnable_target_count"])

            targets = {target["cve_id"]: target for target in plan["targets"]}
            self.assertEqual(True, targets["CVE-2019-10077"]["expected_vuln_hit"])
            self.assertEqual(False, targets["CVE-2019-10077"]["expected_fix_hit"])
            self.assertEqual(False, targets["CVE-2019-0225"]["expected_vuln_hit"])
            self.assertEqual(False, targets["CVE-2019-0225"]["expected_fix_hit"])


if __name__ == "__main__":
    unittest.main()
