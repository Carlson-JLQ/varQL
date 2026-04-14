import os
import subprocess
import sys
from pathlib import Path


def test_generate_seed_synthesis_prompt_script(tmp_path: Path):
    output_path = tmp_path / "CVE-2019-10077.prompt.md"
    repo_root = Path(__file__).resolve().parents[1]

    result = subprocess.run(
        [
            sys.executable,
            "scripts/generate_seed_synthesis_prompt.py",
            "--seed-cve",
            "CVE-2019-10077",
            "--output-path",
            str(output_path),
        ],
        cwd=repo_root,
        env={**os.environ, "PYTHONPATH": str(repo_root / "src")},
        capture_output=True,
        text=True,
        check=True,
    )

    assert output_path.exists()
    content = output_path.read_text(encoding="utf-8")
    assert "Seed CVE: CVE-2019-10077" in content
    assert "Family Abstraction" in content
    assert str(output_path) in result.stdout
