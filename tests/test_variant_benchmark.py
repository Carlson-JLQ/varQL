#!/usr/bin/env python3

import unittest

from src.variant_benchmark import DEFAULT_PILOT_MANIFEST_PATH, load_pilot_benchmark
from src.query_subagents_evaluation import (
    EvaluationResult,
    VariantTargetEvaluation,
    summarize_variant_seed_case,
)


def make_empty_eval() -> EvaluationResult:
    return EvaluationResult(
        recall_method=False,
        num_tp_methods=0,
        total_fixed_methods=0,
        num_results=0,
        num_paths=0,
        fixed_methods=[],
        hit_methods=[],
        missed_methods=[],
        recall_file=False,
        num_tp_files=0,
        total_fixed_files=0,
        fixed_files=[],
        hit_files=[],
        missed_files=[],
        full_result={},
    )


class VariantBenchmarkSmokeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.benchmark = load_pilot_benchmark()

    def test_loads_pilot_manifest_summary(self):
        summary = self.benchmark.summary()
        self.assertEqual(str(DEFAULT_PILOT_MANIFEST_PATH), summary["manifest_path"])
        self.assertEqual(5, summary["family_count"])
        self.assertEqual(8, summary["seed_count"])
        self.assertEqual(8, summary["runnable_seed_count"])
        self.assertEqual(24, summary["referenced_sample_count"])

    def test_jspwiki_seed_case_structure(self):
        case = self.benchmark.get_seed_case("CVE-2019-10077", require_runnable=True)
        self.assertEqual("cwe-079-xss", case.family_id)
        self.assertEqual("Cross-Site Scripting", case.family_name)

        positive_ids = {target.sample.cve_id for target in case.positive_variants}
        negative_ids = {target.sample.cve_id for target in case.hard_negatives}

        self.assertEqual({"CVE-2019-10078", "CVE-2019-10076"}, positive_ids)
        self.assertEqual({"CVE-2019-0225"}, negative_ids)

        targets = case.evaluation_targets()
        target_expectations = {
            target.sample.cve_id: (target.expected_vuln_hit, target.expected_fix_hit)
            for target in targets
        }
        self.assertEqual((True, False), target_expectations["CVE-2019-10077"])
        self.assertEqual((True, False), target_expectations["CVE-2019-10078"])
        self.assertEqual((True, False), target_expectations["CVE-2019-10076"])
        self.assertEqual((False, False), target_expectations["CVE-2019-0225"])

    def test_seed_can_be_converted_to_analysis_task(self):
        case = self.benchmark.get_seed_case("CVE-2019-10077", require_runnable=True)
        task = case.to_vuln_analysis_task(output_dir="tmp_variant_benchmark_test")

        self.assertTrue(task.vuln_db_path.endswith("CVE-2019-10077-vul"))
        self.assertTrue(task.fixed_db_path.endswith("CVE-2019-10077-fix"))
        self.assertEqual("CVE-2019-10077", task.cve_id)
        self.assertEqual("tmp_variant_benchmark_test", task.output_dir)
        self.assertIn("JSPWikiMarkupParser", task.fix_commit_diff)

    def test_variant_summary_aggregation(self):
        case = self.benchmark.get_seed_case("CVE-2019-10077", require_runnable=True)
        target_evaluations = []
        for target in case.evaluation_targets():
            target_evaluations.append(
                VariantTargetEvaluation(
                    target=target,
                    summary="synthetic",
                    vuln_eval=make_empty_eval(),
                    fixed_eval=make_empty_eval(),
                    execution_successful=True,
                    vuln_hit=target.expected_vuln_hit,
                    fix_hit=target.expected_fix_hit,
                    matches_expectation=True,
                )
            )

        aggregate = summarize_variant_seed_case(case, target_evaluations)
        self.assertTrue(aggregate.seed_success)
        self.assertEqual(2, aggregate.positive_variant_hits)
        self.assertEqual(2, aggregate.positive_variant_total)
        self.assertEqual(0, aggregate.negative_fp_count)
        self.assertEqual(1, aggregate.negative_total)
        self.assertEqual(1.0, aggregate.variant_recall)
        self.assertEqual(0.0, aggregate.negative_fp_rate)
        self.assertIn("Variant benchmark summary for seed CVE-2019-10077", aggregate.summary)


if __name__ == "__main__":
    unittest.main()
