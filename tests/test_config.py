from varql.config import get_repo_root


def test_repo_root_exists():
    assert get_repo_root().exists()
