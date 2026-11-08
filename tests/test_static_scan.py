from mira.core.static_scan import compact_findings


def test_compact_findings_empty_without_runner(monkeypatch, tmp_path):
    monkeypatch.setattr("mira.core.static_scan._runner", lambda: None)
    assert compact_findings(["a.py"], tmp_path) == "[]"
