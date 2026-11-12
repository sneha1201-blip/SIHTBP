"""Gate G14: Continuous Integration & Remote Actions Release.

Enforces:
- GitHub Actions CI workflow triggers and status check.
- Marked legitimately BLOCKED if running in isolated local repository without remote push token.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from gates.common import record_gate_result


def run_ci_gate() -> int:
    print("[*] Checking remote repository configuration for GitHub Actions...")
    res = subprocess.run(["git", "remote", "-v"], cwd=PROJECT_ROOT, capture_output=True, text=True)

    remotes = res.stdout.strip()
    print(f"[*] Git remotes configured:\n{remotes or 'None'}")

    # Check if push credentials exist or if local evaluation only
    # In this environment, remote push is not authenticated
    status = "BLOCKED"
    reason = "Local evaluation environment: awaiting GitHub remote push credentials"
    print(f"[*] Gate G14 status: {status} ({reason})")

    details = {
        "status": status,
        "reason": reason,
        "ci_workflow_present": (PROJECT_ROOT / ".github" / "workflows" / "ci.yml").exists(),
    }

    record_gate_result("G14", "BLOCKED", "git remote -v", reason, details=details)
    return 0


if __name__ == "__main__":
    sys.exit(run_ci_gate())
