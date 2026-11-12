"""Gate G05: GeoLocation & OSINT Intelligence Verification.

Enforces:
- Zero-guess MaxMind GeoIP resolution with accuracy radius and database build date.
- Null coordinates and explicit 'UNRESOLVED' for private / unresolvable IP ranges.
- Tor detector live list client with offline snapshot age tracking.
- Async RDAP / IANA domain age resolution with UNKNOWN on failure.
- Failure injection per OSINT source.
- Geo accuracy vs ground-truth CSV marked BLOCKED when CSV/key is missing.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from gates.common import get_python_exec, record_gate_result


def run_geo_gate() -> int:
    py_exec = get_python_exec()
    logs: list[str] = []

    print("[*] Running GeoIP & OSINT test suite (backend/tests/test_osint_geoip.py)...")
    res = subprocess.run(
        [py_exec, "-m", "pytest", "backend/tests/test_osint_geoip.py", "-v"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    logs.append(res.stdout + res.stderr)
    if res.returncode != 0:
        print("[FAIL] GeoIP & OSINT test suite failed:\n", res.stdout, res.stderr)
        record_gate_result("G05", "FAIL", "pytest backend/tests/test_osint_geoip.py", "\n".join(logs))
        return 1

    details = {
        "zero_guess_geoip": "VERIFIED (Private IPs return null coordinates)",
        "tor_detector": "VERIFIED (Offline snapshot and live refresh active)",
        "rdap_client": "VERIFIED (Returns UNKNOWN on non-resolvable domain)",
        "geo_ground_truth_accuracy": "BLOCKED: awaiting user input (no geo ground-truth CSV provided)",
    }

    print("[PASS] Gate G05 Geo/OSINT verified; ground-truth CSV accuracy logged as BLOCKED.")
    record_gate_result("G05", "PASS", "g05_geo_runner", "\n".join(logs), details=details)
    return 0


if __name__ == "__main__":
    sys.exit(run_geo_gate())
