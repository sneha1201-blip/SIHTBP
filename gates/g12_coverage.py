"""Gate G12: Test Suite Pass & Coverage Gate Verification.

Enforces:
- 100% of automated test suites passing.
- Overall codebase test coverage >= 70% in CI environment, >=80% on core parsers/auth/scoring.
- Property-based tests for vault integrity and audit ledger hash chaining.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from gates.common import get_python_exec, record_gate_result


def run_coverage_gate() -> int:
    py_exec = get_python_exec()
    logs: list[str] = []
    cov_json_path = PROJECT_ROOT / "evidence" / "coverage.json"

    print("[*] Running master pytest test suite across all backend test modules with coverage...")
    res = subprocess.run(
        [
            py_exec,
            "-m",
            "pytest",
            "backend/tests/",
            "-v",
            "--cov=backend/app",
            f"--cov-report=json:{cov_json_path}",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=180,
    )
    logs.append(res.stdout + res.stderr)
    if res.returncode != 0:
        print("[FAIL] Master test suite failed:\n", res.stdout, res.stderr)
        record_gate_result("G12", "FAIL", "pytest backend/tests/ --cov", "\n".join(logs))
        return 1

    if not cov_json_path.exists():
        print("[FAIL] evidence/coverage.json was not generated.")
        record_gate_result("G12", "FAIL", "check_coverage_json", "\n".join(logs))
        return 1

    cov_data = json.loads(cov_json_path.read_text(encoding="utf-8"))
    totals = cov_data.get("totals", {})
    overall_pct = round(totals.get("percent_covered", 0.0), 2)

    files_cov = cov_data.get("files", {})
    core_coverage = {}
    for filepath, data in files_cov.items():
        norm_path = filepath.replace("\\", "/")
        pct = data.get("summary", {}).get("percent_covered", 0.0)
        for target in [
            "threat_scorer.py",
            "auth_validator.py",
            "hop_traversal.py",
            "eml_parser.py",
            "msg_parser.py",
            "mime_normalizer.py",
            "vault.py",
            "audit_service.py",
            "campaign_clusterer.py",
            "spoof_detector.py",
            "pdf_generator.py",
        ]:
            if target in norm_path:
                core_coverage[target] = f"{pct:.1f}%"

    REQUIRED_MODULE_THRESHOLDS = {
        "eml_parser.py": 90.0,
        "msg_parser.py": 90.0,
        "mime_normalizer.py": 90.0,
        "auth_validator.py": 90.0,
        "threat_scorer.py": 90.0,
        "spoof_detector.py": 90.0,
        "campaign_clusterer.py": 90.0,
    }

    print(f"[*] Overall Test Coverage: {overall_pct}% (Empirically measured)")
    print(f"[*] Core module coverage: {json.dumps(core_coverage, indent=2)}")

    module_failures = []
    for mod_name, threshold in REQUIRED_MODULE_THRESHOLDS.items():
        val_str = core_coverage.get(mod_name, "0.0%").rstrip("%")
        try:
            val = float(val_str)
        except ValueError:
            val = 0.0
        if val < threshold:
            module_failures.append(f"{mod_name}: {val}% < required {threshold}%")

    if overall_pct < 80.0:
        print(f"[FAIL] Overall coverage {overall_pct}% is below 80.0% threshold.")
        record_gate_result(
            "G12",
            "FAIL",
            "verify_overall_coverage_threshold",
            f"Overall coverage {overall_pct}% is below 80.0% threshold. Module failures: {module_failures}",
        )
        return 1

    if module_failures:
        print(f"[FAIL] Core module coverage below required >=90%:\n" + "\n".join(module_failures))
        record_gate_result(
            "G12",
            "FAIL",
            "verify_per_module_coverage_threshold",
            f"Module failures below 90%: {module_failures}",
        )
        return 1

    details = {
        "overall_coverage_pct": overall_pct,
        "covered_lines": totals.get("covered_lines", 0),
        "total_statements": totals.get("num_statements", 0),
        "core_coverage": core_coverage,
        "overall_status": "ALL_TESTS_GREEN",
    }

    print(f"[PASS] Gate G12 Tests/coverage passed ({overall_pct}% overall coverage, all test suites green).")
    record_gate_result("G12", "PASS", "g12_coverage_runner", "\n".join(logs), details=details)
    return 0


if __name__ == "__main__":
    sys.exit(run_coverage_gate())

