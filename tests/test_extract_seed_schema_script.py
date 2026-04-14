import subprocess
from pathlib import Path


def test_extract_seed_schema_script(tmp_path: Path):
    output_path = tmp_path / "CVE-2019-10077.schema.json"
    result = subprocess.run(
        [
            "python3",
            "/root/varQL/scripts/extract_seed_schema.py",
            "--cve-id",
            "CVE-2019-10077",
            "--output-path",
            str(output_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert output_path.exists()
    assert "Saved schema for CVE-2019-10077" in result.stdout
