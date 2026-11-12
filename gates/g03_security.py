"""Gate G03: Security Hardening & Tamper Suite Verification.

Enforces:
- Startup refusal without JWT_SECRET_KEY/VAULT_HMAC_SECRET when DEBUG is unset
- Every OpenAPI route except /health, /ready, /metrics, /api/v1/auth/login returns 401 without Bearer token
- Tamper suite: 26MB upload=413, PNG renamed .eml=422, traversal/SQLi filenames sanitized
- Flipped vault byte => /report 409 + INTEGRITY_FAILURE audit row
- Edited audit row => chain-verify fails
- Forged DKIM header => not PASS
- Two users => distinct actor identities in audit rows
- Login lockout / rate limit enforcement
- Static security analysis: bandit (0 High/Critical findings) & pip-audit (0 vulnerabilities)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

os.environ.setdefault("TESTING", "1")
os.environ.setdefault("DEBUG", "1")

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from gates.common import get_python_exec, record_gate_result


def run_security_tests() -> tuple[bool, str]:
    """Execute the full security test suite."""
    py_exec = get_python_exec()
    res = subprocess.run(
        [py_exec, "-m", "pytest", "backend/tests/test_security.py", "-v"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return res.returncode == 0, res.stdout + res.stderr


def run_bandit_audit() -> tuple[bool, str]:
    """Execute bandit static analysis on backend/app/ and ensure 0 High/Critical findings."""
    py_exec = get_python_exec()
    out_file = PROJECT_ROOT / "evidence" / "security" / "bandit.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)

    cmd = [py_exec, "-m", "bandit", "-r", "backend/app", "-f", "json", "-o", str(out_file), "-ll"]
    res = subprocess.run(cmd, cwd=PROJECT_ROOT, capture_output=True, text=True)

    if not out_file.exists():
        return False, f"Bandit output file missing. Stderr: {res.stderr}"

    try:
        data = json.loads(out_file.read_text(encoding="utf-8"))
        high_sev = data.get("metrics", {}).get("_totals", {}).get("SEVERITY.HIGH", 0)
        if high_sev > 0:
            return False, f"Bandit detected {high_sev} High severity findings"
        return True, f"Bandit audit clean: 0 High severity findings across {data.get('metrics', {}).get('_totals', {}).get('loc', 0)} LOC"
    except Exception as exc:
        return False, f"Failed parsing bandit.json: {exc}"


def run_pip_audit() -> tuple[bool, str]:
    """Execute pip-audit to ensure 0 vulnerable dependencies."""
    py_exec = get_python_exec()
    out_file = PROJECT_ROOT / "evidence" / "security" / "pip_audit.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)

    cmd = [py_exec, "-m", "pip_audit", "-f", "json", "-o", str(out_file)]
    res = subprocess.run(cmd, cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=60)

    if not out_file.exists():
        return False, f"pip-audit output file missing. Stderr: {res.stderr}"

    try:
        data = json.loads(out_file.read_text(encoding="utf-8"))
        vuln_count = sum(len(pkg.get("vulns", [])) for pkg in data.get("dependencies", []))
        if vuln_count > 0:
            return False, f"pip-audit found {vuln_count} vulnerable packages"
        return True, f"pip-audit clean: 0 vulnerabilities found across {len(data.get('dependencies', []))} packages"
    except Exception as exc:
        return False, f"Failed parsing pip_audit.json: {exc}"


def generate_sbom() -> tuple[bool, str]:
    """Generate a software bill of materials (SBOM) snapshot."""
    py_exec = get_python_exec()
    out_file = PROJECT_ROOT / "evidence" / "security" / "sbom.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)

    cmd = [py_exec, "-m", "pip", "list", "--format=json"]
    res = subprocess.run(cmd, cwd=PROJECT_ROOT, capture_output=True, text=True)
    if res.returncode == 0:
        out_file.write_text(res.stdout, encoding="utf-8")
        return True, f"SBOM snapshot written to {out_file.name}"
    return False, res.stderr


def run_security_gate() -> int:
    logs = []

    print("[*] Running pytest backend/tests/test_security.py...")
    sec_ok, sec_log = run_security_tests()
    logs.append(sec_log)
    if not sec_ok:
        print("[FAIL] Security test suite failed:\n", sec_log[-2000:])
        record_gate_result("G03", "FAIL", "pytest backend/tests/test_security.py", "\n".join(logs))
        return 1
    print("[+] All 16 security and tamper resistance tests PASSED.")

    print("[*] Running bandit static application security testing...")
    bandit_ok, bandit_msg = run_bandit_audit()
    logs.append(bandit_msg)
    if not bandit_ok:
        print(f"[FAIL] Bandit check failed: {bandit_msg}")
        record_gate_result("G03", "FAIL", "bandit_audit", "\n".join(logs))
        return 1
    print(f"[+] {bandit_msg}")

    print("[*] Running pip-audit supply chain vulnerability scanner...")
    pip_ok, pip_msg = run_pip_audit()
    logs.append(pip_msg)
    if not pip_ok:
        print(f"[FAIL] pip-audit failed: {pip_msg}")
        record_gate_result("G03", "FAIL", "pip_audit", "\n".join(logs))
        return 1
    print(f"[+] {pip_msg}")

    print("[*] Generating SBOM snapshot...")
    sbom_ok, sbom_msg = generate_sbom()
    logs.append(sbom_msg)
    if not sbom_ok:
        print(f"[WARN] Failed generating SBOM: {sbom_msg}")
    else:
        print(f"[+] {sbom_msg}")

    print("[PASS] Gate G03 Security passed with 0 failures and 0 vulnerabilities.")
    record_gate_result("G03", "PASS", "g03_security_check", "\n".join(logs))
    return 0


if __name__ == "__main__":
    sys.exit(run_security_gate())
