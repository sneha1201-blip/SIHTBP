"""Gate G00: Code Hygiene & Suppression Verification.

Enforces:
- ruff check backend/ (0 errors)
- mypy backend/app (0 errors)
- frontend tsc --noEmit (0 errors)
- Strict suppression audit: counts of `type: ignore`, `noqa`, `skip/xfail`, `except..pass`
  must be 0 outside docs/SUPPRESSIONS.md-approved entries.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from gates.common import get_python_exec, record_gate_result


def audit_suppressions() -> tuple[bool, list[str]]:
    """Verify that all code suppressions are registered in docs/SUPPRESSIONS.md."""
    suppressions_doc = (PROJECT_ROOT / "docs" / "SUPPRESSIONS.md").read_text(encoding="utf-8")

    patterns = {
        "type_ignore": re.compile(r"#\s*type:\s*ignore"),
        "noqa": re.compile(r"#\s*noqa"),
        "skip_xfail": re.compile(r"@pytest\.mark\.(skip|xfail)"),
        "except_pass": re.compile(r"except\s+([^:]+):\s*(?:#.*)?\n\s*pass"),
    }

    violations = []

    for root, _, files in os.walk(PROJECT_ROOT / "backend"):
        if "__pycache__" in root or ".venv" in root:
            continue
        for f in files:
            if not f.endswith(".py"):
                continue
            path = Path(root) / f
            rel_path = path.relative_to(PROJECT_ROOT).as_posix()
            content = path.read_text(encoding="utf-8", errors="ignore")

            for kind, pat in patterns.items():
                for match in pat.finditer(content):
                    line_no = content[: match.start()].count("\n") + 1
                    # Check if this suppression is documented in docs/SUPPRESSIONS.md
                    if rel_path not in suppressions_doc:
                        violations.append(f"{rel_path}:{line_no} [{kind}] {match.group(0).strip()}")

    return len(violations) == 0, violations


def run_hygiene_gate() -> int:
    py_exec = get_python_exec()
    raw_logs = []

    print("[*] Running ruff check backend/...")
    ruff_res = subprocess.run([py_exec, "-m", "ruff", "check", "backend/"], cwd=PROJECT_ROOT, capture_output=True, text=True)
    raw_logs.append(ruff_res.stdout + ruff_res.stderr)
    if ruff_res.returncode != 0:
        print("[FAIL] ruff check failed:\n", ruff_res.stdout, ruff_res.stderr)
        record_gate_result("G00", "FAIL", "ruff check backend/", "\n".join(raw_logs))
        return 1

    print("[*] Running mypy backend/app...")
    mypy_res = subprocess.run([py_exec, "-m", "mypy", "backend/app"], cwd=PROJECT_ROOT, capture_output=True, text=True)
    raw_logs.append(mypy_res.stdout + mypy_res.stderr)
    if mypy_res.returncode != 0:
        print("[FAIL] mypy check failed:\n", mypy_res.stdout, mypy_res.stderr)
        record_gate_result("G00", "FAIL", "mypy backend/app", "\n".join(raw_logs))
        return 1

    print("[*] Running frontend typecheck (tsc --noEmit)...")
    frontend_dir = PROJECT_ROOT / "frontend"
    tsc_cmd = "npx.cmd" if os.name == "nt" else "npx"
    tsc_res = subprocess.run([tsc_cmd, "tsc", "--noEmit"], cwd=frontend_dir, capture_output=True, text=True)
    raw_logs.append(tsc_res.stdout + tsc_res.stderr)
    if tsc_res.returncode != 0:
        print("[FAIL] frontend tsc failed:\n", tsc_res.stdout, tsc_res.stderr)
        record_gate_result("G00", "FAIL", "frontend tsc --noEmit", "\n".join(raw_logs))
        return 1

    print("[*] Auditing unapproved code suppressions against docs/SUPPRESSIONS.md...")
    is_suppression_clean, violations = audit_suppressions()
    if not is_suppression_clean:
        print(f"[FAIL] Found {len(violations)} unapproved suppressions:")
        for v in violations:
            print("  ", v)
        record_gate_result("G00", "FAIL", "audit_suppressions", "\n".join(violations))
        return 1

    print("[PASS] Gate G00 Hygiene passed with 0 errors and 0 unapproved suppressions.")
    record_gate_result("G00", "PASS", "g00_hygiene_check", "\n".join(raw_logs), details={"violations_count": 0})
    return 0


if __name__ == "__main__":
    sys.exit(run_hygiene_gate())
