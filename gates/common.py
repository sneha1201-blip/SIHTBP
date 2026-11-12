"""Common utilities for Gate Verification Scripts.

SIH Problem Statement ID: 26106 (AICTE Cyber Security Cell)
Standard: Section 63 Bharatiya Sakshya Adhiniyam (BSA), 2023
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_GATES_DIR = PROJECT_ROOT / "evidence" / "gates"
EVIDENCE_GATES_DIR.mkdir(parents=True, exist_ok=True)


def get_git_commit() -> str:
    """Retrieve current HEAD commit hash."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        return res.stdout.strip() or "UNKNOWN_COMMIT"
    except Exception:
        return "UNKNOWN_COMMIT"


def get_python_exec() -> str:
    """Find appropriate virtualenv python executable."""
    venv_py = PROJECT_ROOT / ".venv" / "Scripts" / "python.exe"
    if venv_py.exists():
        return str(venv_py)
    # Unix fallback
    venv_py_unix = PROJECT_ROOT / ".venv" / "bin" / "python"
    if venv_py_unix.exists():
        return str(venv_py_unix)
    return sys.executable


def record_gate_result(
    gate_id: str,
    status: str,  # "PASS", "FAIL", "BLOCKED"
    command: str,
    raw_output: str,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """Write gate execution artifact to evidence/gates/<gate_id>.json."""
    artifact = {
        "gate_id": gate_id,
        "status": status,
        "commit": get_git_commit(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "command": command,
        "details": details or {},
        "raw_output": raw_output[-4000:],  # Tail of output for readability
    }
    target_path = EVIDENCE_GATES_DIR / f"{gate_id.lower()}.json"
    with open(target_path, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)
    print(f"[{gate_id.upper()}] Status: {status} -> Artifact saved: {target_path.name}")
