from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src" / "varql"
TEST_ROOT = REPO_ROOT / "tests"
BENCHMARK_ROOT = REPO_ROOT / "benchmarks"
CONFIG_ROOT = REPO_ROOT / "configs"
SCRIPT_ROOT = REPO_ROOT / "scripts"
PAPER_ROOT = REPO_ROOT / "paper"


def get_repo_root() -> Path:
    return REPO_ROOT
