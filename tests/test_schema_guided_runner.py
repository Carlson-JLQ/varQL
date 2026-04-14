import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent.parent
SCRIPT_PATH = ROOT_DIR / "scripts" / "run_schema_guided_generation.py"

sys.path.append(str(ROOT_DIR / "src"))

from varql.agents.schema_guided_runner import (
    build_run_plan,
    build_schema_guided_prompt,
    extract_query_path_from_output,
)


class SchemaGuidedRunnerTest(unittest.TestCase):
    def test_build_schema_guided_prompt_contains_protocol_and_contract(self):
        prompt = build_schema_guided_prompt(
            "CVE-2019-10077",
            query_filename="CVE-2019-10077-schema-guided-query.ql",
        )
        self.assertIn("Held-out test variants: CVE-2019-10076", prompt)
        self.assertIn("QUERY_FILE_PATH: CVE-2019-10077-schema-guided-query.ql", prompt)
        self.assertIn("Write exactly one CodeQL query file", prompt)

    def test_extract_query_path_from_output_prefers_marker(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            query_path = tmp_path / "CVE-2019-10077-schema-guided-query.ql"
            query_path.write_text("import java", encoding="utf-8")
            resolved = extract_query_path_from_output(
                "Done\nQUERY_FILE_PATH: CVE-2019-10077-schema-guided-query.ql\n",
                tmp_path,
            )
            self.assertEqual(query_path, resolved)

    def test_build_run_plan_for_jspwiki_seed(self):
        plan = build_run_plan(
            "CVE-2019-10077",
            agent="codex",
            model="gpt-5.4",
            ablation_mode="full",
            codex_use_local_config=True,
        )
        self.assertEqual("CVE-2019-10077", plan.seed_cve)
        self.assertEqual("cwe-079-xss", plan.family_id)
        self.assertEqual("CVE-2019-10077-schema-guided-query.ql", plan.query_filename)
        self.assertTrue(plan.codex_use_local_config)

    def test_runner_dry_run_writes_plan(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_dir = Path(tmp_dir) / "runner"
            result = subprocess.run(
                [
                    "python3",
                    str(SCRIPT_PATH),
                    "--seed-cve",
                    "CVE-2019-10077",
                    "--agent",
                    "codex",
                    "--model",
                    "gpt-5.4",
                    "--codex-use-local-config",
                    "--output-dir",
                    str(output_dir),
                ],
                cwd=ROOT_DIR,
                capture_output=True,
                text=True,
                check=True,
            )

            self.assertIn("Execution mode: dry-run", result.stdout)
            self.assertIn("Seed CVE: CVE-2019-10077", result.stdout)
            plan_json = output_dir / "schema_guided_plan.json"
            self.assertTrue(plan_json.exists())
            payload = json.loads(plan_json.read_text(encoding="utf-8"))
            self.assertEqual("CVE-2019-10077", payload["seed_cve"])
            self.assertEqual("codex", payload["agent"])
            self.assertEqual("gpt-5.4", payload["model"])


if __name__ == "__main__":
    unittest.main()
