"""Provenance primitives shared by every artifact this project publishes.

Single-sourced here rather than duplicated in `eval/run.py` and
`eval/redteam/runner.py` because the two artifacts have to agree on what a run
IS: `eval/harness.py` refuses a red-team rate whose `eval_sha` differs from the
run being scored, and that comparison is meaningless if the two files compute
the string differently.
"""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

from eval.schema import REPO_ROOT

UNCOMMITTED = "uncommitted"


def file_sha256(path: Path) -> str:
    """Return the sha256 of a file's bytes, or 'missing' when absent."""
    if not path.is_file():
        return "missing"
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_eval_sha(repo_root: Path = REPO_ROOT) -> str:
    """Return HEAD's sha, or 'uncommitted' if the tree is dirty or empty.

    Any failure resolves to "uncommitted" rather than to a guess: a card is
    allowed to say it has no provenance, but never allowed to claim provenance
    it does not have.
    """
    try:
        status = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
        )
        if status.stdout.strip():
            return UNCOMMITTED
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, OSError):
        return UNCOMMITTED
    sha = head.stdout.strip()
    return sha if sha else UNCOMMITTED
