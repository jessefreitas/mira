"""Compact Semgrep/Opengrep findings for review prompts."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path


def _runner() -> list[str] | None:
    for cmd in ("opengrep", "semgrep"):
        if shutil.which(cmd):
            return [cmd]
    return None


def compact_findings(paths: list[str], repo_root: Path) -> str:
    cmd = _runner()
    if not cmd:
        return "[]"
    target = [str(repo_root / p) for p in paths if (repo_root / p).exists()]
    if not target:
        return "[]"
    try:
        proc = subprocess.run(
            [*cmd, "scan", "--json", "--quiet", *target],
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "[]"
    if proc.returncode not in (0, 1) or not proc.stdout.strip():
        return "[]"
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return "[]"
    rows = []
    for hit in payload.get("results", [])[:40]:
        rows.append(
            {
                "rule": hit.get("check_id") or hit.get("rule_id"),
                "file": hit.get("path"),
                "line": (hit.get("start") or {}).get("line"),
                "message": (hit.get("extra") or {}).get("message") or hit.get("message"),
            }
        )
    return json.dumps(rows, ensure_ascii=False)
