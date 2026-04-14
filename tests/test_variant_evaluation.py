from varql.benchmark import load_pilot_benchmark
from varql.evaluation import (
    make_skipped_target_evaluation,
    make_target_evaluation,
    summarize_variant_seed_case,
)


def test_summarize_variant_seed_case_success_pattern():
    benchmark = load_pilot_benchmark()
    case = benchmark.get_seed_case("CVE-2019-10077", require_runnable=True)
    targets = case.evaluation_targets(include_seed=True)

    evaluations = [
        make_target_evaluation(target=targets[0], vuln_hit=True, fix_hit=False),
        make_target_evaluation(target=targets[1], vuln_hit=True, fix_hit=False),
        make_target_evaluation(target=targets[2], vuln_hit=False, fix_hit=False),
        make_target_evaluation(target=targets[3], vuln_hit=False, fix_hit=False),
    ]

    result = summarize_variant_seed_case(case, evaluations)

    assert result.seed_success is True
    assert result.positive_variant_hits == 1
    assert result.positive_variant_total == 2
    assert result.variant_recall == 0.5
    assert result.negative_fp_count == 0
    assert result.negative_total == 1
    assert result.negative_fp_rate == 0.0


def test_summarize_variant_seed_case_with_skip():
    benchmark = load_pilot_benchmark()
    case = benchmark.get_seed_case("CVE-2019-10077", require_runnable=True)
    targets = case.evaluation_targets(include_seed=True)

    evaluations = [
        make_target_evaluation(target=targets[0], vuln_hit=True, fix_hit=False),
        make_skipped_target_evaluation(target=targets[1], reason="missing db"),
        make_target_evaluation(target=targets[2], vuln_hit=False, fix_hit=False),
        make_target_evaluation(target=targets[3], vuln_hit=False, fix_hit=False),
    ]

    result = summarize_variant_seed_case(case, evaluations)

    assert result.seed_success is True
    assert result.positive_variant_hits == 0
    assert result.positive_variant_total == 1
    assert result.skipped_targets == 1
    assert "Skipped targets: 1" in result.summary
