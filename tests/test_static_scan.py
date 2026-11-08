import subprocess
from types import SimpleNamespace

import pytest

from mira.core.engine import _comment_line_exists_at_ref
from mira.core.static_scan import compact_findings, compact_findings_at_ref


def test_compact_findings_empty_without_runner(monkeypatch, tmp_path):
    monkeypatch.setattr("mira.core.static_scan._runner", lambda: None)
    assert compact_findings(["a.py"], tmp_path) == "[]"


@pytest.fixture
def repo_root(tmp_path):
    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    (tmp_path / "README.md").write_bytes(b"first\nsecond\ninvalid: \xff\n")
    subprocess.run(["git", "add", "README.md"], cwd=tmp_path, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.com",
            "commit",
            "-m",
            "fixture",
        ],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    return tmp_path


def test_comment_line_exists_at_ref_real_and_invalid(repo_root):
    assert _comment_line_exists_at_ref("README.md", 1, "HEAD", repo_root) is True
    # Out of bounds line
    assert _comment_line_exists_at_ref("README.md", 999999, "HEAD", repo_root) is False
    # Non-existent file
    assert _comment_line_exists_at_ref("non_existent_file_xyz.py", 1, "HEAD", repo_root) is False
    # Synthetic / mock commit SHA returns True to avoid breaking mock unit tests
    assert _comment_line_exists_at_ref("README.md", 10, "deadbeefcafebabe", repo_root) is True


@pytest.mark.parametrize("ref", ["", "--help", "-x"])
def test_unusable_ref_fails_open(ref, repo_root, monkeypatch):
    def unexpected(*args, **kwargs):
        pytest.fail("Git must not run for unusable refs")

    monkeypatch.setattr("mira.core.engine.subprocess.run", unexpected)
    assert _comment_line_exists_at_ref("README.md", 1, ref, repo_root)


def test_scan_uses_commit_snapshot(repo_root, monkeypatch):
    (repo_root / "README.md").write_text("dirty tree")
    monkeypatch.setattr("mira.core.static_scan._runner", lambda: ["semgrep"])

    def scan(paths, snapshot):
        assert paths == ["README.md"]
        assert (snapshot / "README.md").read_bytes() == b"first\nsecond\ninvalid: \xff\n"
        assert not (snapshot / ".git").exists()
        return "[]"

    monkeypatch.setattr("mira.core.static_scan.compact_findings", scan)
    assert compact_findings_at_ref(["README.md", "../outside"], repo_root, "HEAD") == "[]"


def test_scanner_explicit_config_and_absolute_targets(tmp_path, monkeypatch):
    (tmp_path / "-target.py").write_text("pass")
    monkeypatch.setattr("mira.core.static_scan._runner", lambda: ["semgrep"])

    def run(command, **kwargs):
        assert command[2:4] == ["--config", "auto"]
        assert command[-2] == "--"
        assert command[-1] == str(tmp_path / "-target.py")
        return SimpleNamespace(returncode=0, stdout='{"results": []}', stderr="")

    monkeypatch.setattr("mira.core.static_scan.subprocess.run", run)
    assert compact_findings(["-target.py"], tmp_path) == "[]"
