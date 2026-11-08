"""Compact Semgrep/Opengrep findings for review prompts."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)


def _runner() -> list[str] | None:
    """Find available static analysis scanner executable."""
    for cmd in ("opengrep", "semgrep"):
        if shutil.which(cmd):
            return [cmd]
    return None


def compact_findings(paths: list[str], repo_root: Path) -> str:
    """Run semgrep/opengrep on the given paths and return compact JSON findings."""
    cmd = _runner()
    if not cmd:
        return "[]"
    target = [str((repo_root / p).resolve()) for p in paths if (repo_root / p).exists()]
    if not target:
        return "[]"
    try:
        proc = subprocess.run(
            [*cmd, "scan", "--config", "auto", "--json", "--quiet", "--", *target],
            cwd=repo_root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.debug("Static scan execution failed: %s", exc)
        return "[]"
    if proc.returncode not in (0, 1) or not proc.stdout.strip():
        logger.debug("Static scan returned code %d, stderr: %s", proc.returncode, proc.stderr[:200])
        return "[]"
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        logger.debug("Static scan returned invalid JSON: %s", exc)
        return "[]"
    rows = []
    for hit in payload.get("results", [])[:40]:
        hit_path = hit.get("path")
        if hit_path:
            try:
                hit_path = str((repo_root / hit_path).resolve().relative_to(repo_root.resolve()))
            except ValueError:
                continue
        rows.append(
            {
                "rule": hit.get("check_id") or hit.get("rule_id"),
                "file": hit_path,
                "line": (hit.get("start") or {}).get("line"),
                "message": (hit.get("extra") or {}).get("message") or hit.get("message"),
            }
        )
    return json.dumps(rows, ensure_ascii=False)


def compact_findings_at_ref(paths: list[str], repo_root: Path, ref: str) -> str:
    """Scan isolated file contents from a resolved commit, never the working tree."""
    if not ref or ref.startswith("-") or _runner() is None:
        return "[]"
    try:
        commit = (
            subprocess.run(
                ["git", "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}"],
                cwd=repo_root,
                capture_output=True,
                check=True,
                timeout=5,
            )
            .stdout.decode("ascii")
            .strip()
        )
        with tempfile.TemporaryDirectory(prefix="mira-scan-") as directory:
            snapshot = Path(directory)
            targets = []
            for path in paths:
                relative = Path(path)
                if relative.is_absolute() or ".." in relative.parts or not relative.parts:
                    logger.debug("Skipping unsafe static scan path: %s", path)
                    continue
                blob = subprocess.run(
                    ["git", "show", f"{commit}:{path}"],
                    cwd=repo_root,
                    capture_output=True,
                    check=False,
                    timeout=30,
                )
                if blob.returncode:
                    logger.debug("Static scan file unavailable at revision: %s", path)
                    continue
                destination = snapshot / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(blob.stdout)
                targets.append(path)
            return compact_findings(targets, snapshot)
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        logger.debug("Static scan snapshot failed: %s", exc)
        return "[]"
