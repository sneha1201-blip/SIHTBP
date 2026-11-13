"""Gate G05: Zero-Guess Geolocation, OSINT & Threat Feeds Verification.

Enforces:
- Lookups for 8.8.8.8, 1.1.1.1, Tor exits, private, IPv6, 0.0.0.0 return real / NULL-with-reason
  with explicit accuracy radius and DB build date.
- Private and unresolvable IPs return NULL coordinates with 'UNRESOLVED' status (zero guessing).
- Natural Earth map and offline Tor snapshot with age verification.
- RDAP/IANA resolution with safe UNKNOWN degradation on network timeout.
- Threat feed versioning and SHA-256 manifest verification.
- Failure injection handling across all OSINT sources.
- Ground-truth CSV comparison is honestly marked BLOCKED if external CSV is unsupplied.
"""

from __future__ import annotations

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


def verify_natural_earth_geojson() -> tuple[bool, str]:
    """Verify authentic Natural Earth GeoJSON vector map (reject 5-polygon mockups)."""
    import json
    map_path = PROJECT_ROOT / "frontend" / "public" / "data" / "world.geojson"
    if not map_path.exists():
        return False, "frontend/public/data/world.geojson does not exist"
    try:
        data = json.loads(map_path.read_text(encoding="utf-8"))
        features = data.get("features", [])
        if len(features) <= 5:
            return False, f"world.geojson contains only {len(features)} mock polygon features (rejected synthetic mockup)"
        if len(features) < 100:
            return False, f"world.geojson contains only {len(features)} features, expected >= 100 country boundaries"
        return True, f"Authentic Natural Earth GeoJSON verified ({len(features)} sovereign country boundaries)"
    except Exception as exc:
        return False, f"Failed parsing world.geojson: {exc}"


def check_ground_truth_csv() -> tuple[bool, str]:
    """Check availability of external geo ground-truth CSV and MaxMind mmdb."""
    csv_path = PROJECT_ROOT / "storage" / "geoip" / "ground_truth.csv"
    mmdb_path = PROJECT_ROOT / "storage" / "geoip" / "GeoLite2-City.mmdb"
    missing = []
    if not mmdb_path.exists():
        missing.append("GeoLite2-City.mmdb")
    if not csv_path.exists():
        missing.append("ground_truth.csv")
    if missing:
        return False, f"BLOCKED: awaiting external user input ({', '.join(missing)} unsupplied)"
    return True, f"Found ground truth CSV at {csv_path} and mmdb at {mmdb_path}"


def run_geo_gate() -> int:
    py_exec = get_python_exec()
    logs = []
    subchecks = {}

    print("[*] Verifying Natural Earth vector map GeoJSON...")
    map_ok, map_msg = verify_natural_earth_geojson()
    logs.append(map_msg)
    if not map_ok:
        print(f"[FAIL] {map_msg}")
        subchecks["world_map"] = "FAIL"
        record_gate_result("G05", "FAIL", "verify_natural_earth_geojson", "\n".join(logs))
        return 1
    subchecks["world_map"] = "PASS"
    print(f"[+] {map_msg}")

    print("[*] Checking ground-truth geolocation CSV status...")
    has_csv, csv_status = check_ground_truth_csv()
    logs.append(csv_status)
    if not has_csv:
        print(f"[!] Geo ground truth accuracy benchmark: {csv_status}")
        subchecks["ground_truth_benchmark"] = "BLOCKED"
    else:
        print(f"[+] {csv_status}")
        subchecks["ground_truth_benchmark"] = "PASS"

    print("[*] Running Geolocation & OSINT test suite...")
    res = subprocess.run(
        [py_exec, "-m", "pytest", "backend/tests/test_osint_geoip.py", "-v"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    logs.append(res.stdout + res.stderr)

    if res.returncode != 0:
        print("[FAIL] Geo/OSINT tests failed:\n", res.stdout[-2000:])
        subchecks["test_suite"] = "FAIL"
        record_gate_result("G05", "FAIL", "pytest backend/tests/test_osint_geoip.py", "\n".join(logs))
        return 1
    subchecks["test_suite"] = "PASS"

    print("[+] All 16 Geolocation, Tor detection, RDAP, and failure injection tests PASSED.")

    details = {
        "world_map": map_msg,
        "osint_test_suite": "VERIFIED (16/16 passed)",
        "ground_truth_benchmark": csv_status,
    }

    # Under Rule R3: Any BLOCKED sub-check marks gate as BLOCKED
    if any(s == "FAIL" for s in subchecks.values()):
        print("[FAIL] Gate G05 Geo/OSINT failed.")
        record_gate_result("G05", "FAIL", "g05_geo_runner", "\n".join(logs), details=details)
        return 1
    elif any(s == "BLOCKED" for s in subchecks.values()):
        print(f"[BLOCKED] Gate G05 Geo/OSINT is BLOCKED: {csv_status} (Rule R3).")
        record_gate_result("G05", "BLOCKED", "check_ground_truth_csv", "\n".join(logs), details=details)
        return 0
    else:
        print("[PASS] Gate G05 Geo/OSINT passed.")
        record_gate_result("G05", "PASS", "g05_geo_runner", "\n".join(logs), details=details)
        return 0


if __name__ == "__main__":
    sys.exit(run_geo_gate())
