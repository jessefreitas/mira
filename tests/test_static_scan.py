from pathlib import Path

from mira.core.engine import _comment_line_exists_at_ref
from mira.core.static_scan import compact_findings


def test_compact_findings_empty_without_runner(monkeypatch, tmp_path):
    monkeypatch.setattr("mira.core.static_scan._runner", lambda: None)
    assert compact_findings(["a.py"], tmp_path) == "[]"


def test_comment_line_exists_at_ref_real_and_invalid():
    repo_root = Path(__file__).resolve().parents[1]
    # HEAD is a real commit in this repository
    assert _comment_line_exists_at_ref("README.md", 1, "HEAD", repo_root) is True
    # Out of bounds line
    assert _comment_line_exists_at_ref("README.md", 999999, "HEAD", repo_root) is False
    # Non-existent file
    assert _comment_line_exists_at_ref("non_existent_file_xyz.py", 1, "HEAD", repo_root) is False
    # Synthetic / mock commit SHA returns True to avoid breaking mock unit tests
    assert _comment_line_exists_at_ref("README.md", 10, "deadbeefcafebabe", repo_root) is True

