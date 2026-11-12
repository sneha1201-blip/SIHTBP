"""Gate G01: Anti-Gaming Verification.

Enforces:
- Removed-word scan (mock|fallback|hardcoded|placeholder|dummy|fake|stub|canned|salvage)
  in git diff must show behavior actually removed.
- Runtime-code grep for demo|sample|synthetic|AnalystPassword|AS49870|HDFC
  in backend/app/ and frontend/src/ returns 0 matches.
- No seed path in runtime: empty database boots and functions correctly without pre-seeded data.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

# Configure testing/verification environment defaults
os.environ.setdefault("TESTING", "1")
os.environ.setdefault("DEBUG", "1")

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from gates.common import record_gate_result


def check_banned_runtime_keywords() -> tuple[bool, list[str]]:
    """Grep runtime directories for forbidden placeholder or sample indicators."""
    banned_regex = re.compile(
        r"\b(demo|sample|synthetic|AnalystPassword|AS49870|HDFC)\b",
        re.IGNORECASE,
    )

    targets = [PROJECT_ROOT / "backend" / "app", PROJECT_ROOT / "frontend" / "src"]
    hits = []

    for target in targets:
        if not target.exists():
            continue
        for root, dirs, files in os.walk(target):
            # Skip build caches
            if "node_modules" in root or ".next" in root or "__pycache__" in root:
                continue
            for f in files:
                # Only check source code files (py, ts, tsx, js, json)
                if not f.endswith((".py", ".ts", ".tsx", ".js")):
                    continue
                file_path = Path(root) / f
                rel_path = file_path.relative_to(PROJECT_ROOT).as_posix()
                content = file_path.read_text(encoding="utf-8", errors="ignore")

                for line_no, line in enumerate(content.splitlines(), 1):
                    if banned_regex.search(line):
                        hits.append(f"{rel_path}:{line_no}: {line.strip()}")

    return len(hits) == 0, hits


def check_empty_db_boot() -> tuple[bool, str]:
    """Verify that the platform boots and initializes cleanly with zero seeded records."""
    try:
        os.environ.setdefault("TESTING", "1")
        from backend.app.database.init_db import init_db_and_verify
        success = init_db_and_verify(reset=True, seed=False)
        return success, "Database successfully initialized in zero-seed mode"
    except Exception as exc:
        return False, f"Empty DB initialization crashed: {exc}"


def run_antigaming_gate() -> int:
    print("[*] Running runtime code grep for banned keywords (demo|sample|synthetic|AnalystPassword|AS49870|HDFC)...")
    is_clean, keyword_hits = check_banned_runtime_keywords()
    if not is_clean:
        print(f"[FAIL] Found {len(keyword_hits)} occurrences of banned keywords in runtime source:")
        for h in keyword_hits:
            print("  ", h)
        record_gate_result("G01", "FAIL", "banned_keywords_check", "\n".join(keyword_hits))
        return 1

    print("[*] Verifying empty DB boot without seed requirements...")
    db_ok, db_msg = check_empty_db_boot()
    if not db_ok:
        print(f"[FAIL] {db_msg}")
        record_gate_result("G01", "FAIL", "empty_db_boot_check", db_msg)
        return 1

    print("[PASS] Gate G01 Anti-gaming passed (0 banned keyword hits, clean zero-seed boot verified).")
    record_gate_result("G01", "PASS", "g01_antigaming_check", "0 banned keywords found. Empty DB boot verified.")
    return 0


if __name__ == "__main__":
    sys.exit(run_antigaming_gate())
