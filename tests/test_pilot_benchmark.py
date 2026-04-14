from varql.benchmark.pilot import DEFAULT_PILOT_MANIFEST_PATH, load_pilot_benchmark


def test_default_manifest_exists():
    assert DEFAULT_PILOT_MANIFEST_PATH.exists()


def test_load_pilot_benchmark_summary():
    benchmark = load_pilot_benchmark()
    summary = benchmark.summary()
    assert summary["family_count"] == 5
    assert summary["seed_count"] == 8
    assert summary["runnable_seed_count"] == 8


def test_jspwiki_seed_case_targets():
    benchmark = load_pilot_benchmark()
    case = benchmark.get_seed_case("CVE-2019-10077", require_runnable=True)

    assert case.family_id == "cwe-079-xss"
    assert case.seed.cve_id == "CVE-2019-10077"
    assert len(case.positive_variants) == 2
    assert len(case.hard_negatives) == 1

    targets = case.evaluation_targets(include_seed=True)
    assert len(targets) == 4
    assert targets[0].role == "seed"
    assert targets[1].sample.cve_id == "CVE-2019-10078"
    assert targets[2].sample.cve_id == "CVE-2019-10076"
    assert targets[3].role == "hard_negative"


def test_jspwiki_seed_case_default_split():
    benchmark = load_pilot_benchmark()
    case = benchmark.get_seed_case("CVE-2019-10077", require_runnable=True)

    seen, held_out = case.split_variants()

    assert [target.sample.cve_id for target in seen] == ["CVE-2019-10078"]
    assert [target.sample.cve_id for target in held_out] == ["CVE-2019-10076"]
