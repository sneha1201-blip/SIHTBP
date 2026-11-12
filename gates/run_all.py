"""Master Gate Orchestrator: Clean-Clone Gate Verification Runner.

Executes all 16 verification gates from G00 to G15 in an isolated clean clone
to guarantee zero reliance on uncommitted files or local working tree state.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from gates.common import get_python_exec

GATE_ORDER = [
    ("G00", "gates/g00_hygiene.py", "Hygiene & Suppressions"),
    ("G01", "gates/g01_antigaming.py", "Anti-Gaming & Zero-Seed"),
    ("G02", "gates/g02_canary.py", "Mutation Canary (10/10 killed)"),
    ("G03", "gates/g03_security.py", "Security & Tamper Suite"),
    ("G04", "gates/g04_auth.py", "Protocol Auth (DKIM/SPF/DMARC/ARC)"),
    ("G05", "gates/g05_geo.py", "GeoIP & OSINT Intelligence"),
    ("G06", "gates/g06_headers.py", "Header Forensics & Fuzzing"),
    ("G07", "gates/g07_detection.py", "AI Intent Classification & Triage"),
    ("G08", "gates/g08_campaigns.py", "Threat Campaigns & STIX 2.1"),
    ("G09", "gates/g09_legal.py", "Section 63 BSA 2023 Reporting"),
    ("G10", "gates/g10_architecture.py", "Architecture & Backup Recovery"),
    ("G11", "gates/g11_frontend.py", "Frontend Completeness & Build"),
    ("G12", "gates/g12_coverage.py", "Test Suite Pass & Coverage"),
    ("G13", "gates/g13_performance.py", "Empirical Benchmarks & Zero Cache"),
    ("G14", "gates/g14_ci.py", "Continuous Integration / Actions"),
    ("G15", "gates/g15_docs.py", "Docs Completeness & Metric Trace"),
]


def verify_gate_hashes() -> tuple[bool, str]:
    """Verify that gate shell scripts match evidence/gates/GATE_HASHES.txt."""
    hashes_file = PROJECT_ROOT / "evidence" / "gates" / "GATE_HASHES.txt"
    if not hashes_file.exists():
        return False, "evidence/gates/GATE_HASHES.txt missing"

    changelog_file = PROJECT_ROOT / "evidence" / "GATE_CHANGELOG.md"
    changelog_text = changelog_file.read_text(encoding="utf-8") if changelog_file.exists() else ""

    expected_hashes = {}
    for line in hashes_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            expected_hashes[parts[1]] = parts[0]

    for script_name, expected_hash in expected_hashes.items():
        script_path = PROJECT_ROOT / "gates" / script_name
        if not script_path.exists():
            return False, f"Gate script missing: {script_name}"
        computed_hash = hashlib.sha256(script_path.read_bytes()).hexdigest()
        if computed_hash != expected_hash:
            # Check if recorded in changelog
            if script_name not in changelog_text:
                return False, f"Hash mismatch for {script_name} without entry in GATE_CHANGELOG.md"

    return True, "All gate script hashes verified"


def run_all_gates_in_clean_clone() -> int:
    py_exec = get_python_exec()
    print("================================================================================")
    print("   AICTE CYBER SECURITY CELL | SMART INDIA HACKATHON 2026 (SIH PS 26106)")
    print("   MASTER VERIFICATION GATE HARNESS (CLEAN CLONE ISOLATION)")
    print("================================================================================\n")

    # Step 1: Verify gate hashes
    print("[*] Verifying gate script integrity against evidence/gates/GATE_HASHES.txt...")
    hash_ok, hash_msg = verify_gate_hashes()
    if not hash_ok:
        print(f"[FAIL] Gate script integrity failure: {hash_msg}")
        return 1
    print("[+] All gate script hashes intact.\n")

    # Step 2: Create clean temporary clone
    temp_dir = Path(tempfile.mkdtemp(prefix="sihtbp_clean_clone_"))
    clean_clone_dir = temp_dir / "repo"

    print(f"[*] Creating clean clone from current HEAD into {clean_clone_dir}...")
    clone_res = subprocess.run(["git", "clone", str(PROJECT_ROOT), str(clean_clone_dir)], capture_output=True, text=True)
    if clone_res.returncode != 0:
        print("[FAIL] git clone failed:\n", clone_res.stderr)
        shutil.rmtree(temp_dir, ignore_errors=True)
        return 1

    # Link frontend node_modules if present to avoid npm install overhead
    repo_node_modules = PROJECT_ROOT / "frontend" / "node_modules"
    clean_node_modules = clean_clone_dir / "frontend" / "node_modules"
    if repo_node_modules.exists() and not clean_node_modules.exists():
        if os.name == "nt":
            subprocess.run(["cmd.exe", "/c", "mklink", "/j", str(clean_node_modules), str(repo_node_modules)], capture_output=True)
        else:
            clean_node_modules.symlink_to(repo_node_modules)

    # Step 3: Iterate through gates
    results: list[dict] = []
    print("[*] Executing 16 verification gates in clean clone environment...\n")

    try:
        for gate_id, script_rel, name in GATE_ORDER:
            script_path = clean_clone_dir / script_rel
            print(f"--- Running {gate_id}: {name} ---")

            env = os.environ.copy()
            env["TESTING"] = "1"
            env["PYTHONPATH"] = str(clean_clone_dir)

            res = subprocess.run([py_exec, str(script_path)], cwd=clean_clone_dir, capture_output=True, text=True, env=env)

            # Read generated artifact in clean clone
            artifact_file = clean_clone_dir / "evidence" / "gates" / f"{gate_id.lower()}.json"
            status = "FAIL"
            details = {}

            if artifact_file.exists():
                try:
                    artifact_data = json.loads(artifact_file.read_text(encoding="utf-8"))
                    status = artifact_data.get("status", "FAIL")
                    details = artifact_data.get("details", {})
                    # Sync artifact back to main repository
                    main_artifact = PROJECT_ROOT / "evidence" / "gates" / f"{gate_id.lower()}.json"
                    main_artifact.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(artifact_file, main_artifact)
                except Exception:
                    pass
            else:
                status = "PASS" if res.returncode == 0 else "FAIL"

            results.append({
                "gate_id": gate_id,
                "name": name,
                "status": status,
                "exit_code": res.returncode,
                "details": details,
            })
            print(f"Result for {gate_id}: {status}\n")

    finally:
        # Clean up temporary clone
        shutil.rmtree(temp_dir, ignore_errors=True)

    # Step 4: Print summary table
    print("================================================================================")
    print("   MASTER VERIFICATION GATE RESULTS (CLEAN CLONE AUDIT)")
    print("================================================================================")
    print(f"{'Gate ID':<8} | {'Scope / Deliverable':<36} | {'Status':<10} | {'Verification Notes'}")
    print("-" * 88)

    passed_count = 0
    blocked_count = 0
    failed_count = 0

    for r in results:
        gid = r["gate_id"]
        nm = r["name"]
        st = r["status"]
        if st == "PASS":
            passed_count += 1
            note = "VERIFIED (100% green)"
        elif st == "BLOCKED":
            blocked_count += 1
            note = "BLOCKED: awaiting external user input"
        else:
            failed_count += 1
            note = "FAIL (investigation required)"

        print(f"{gid:<8} | {nm:<36} | {st:<10} | {note}")

    print("=" * 88)
    print(f"Summary: {passed_count} PASS | {blocked_count} BLOCKED | {failed_count} FAIL | Total: {len(results)}\n")

    # Update docs/STATE.md
    update_state_doc(results)

    return 0 if failed_count == 0 else 1


def update_state_doc(results: list[dict]) -> None:
    """Synchronize docs/STATE.md with the latest clean clone run results."""
    state_file = PROJECT_ROOT / "docs" / "STATE.md"
    if not state_file.exists():
        return

    rows = []
    for r in results:
        gid = r["gate_id"]
        nm = r["name"]
        st = r["status"]
        note = "Verified clean" if st == "PASS" else ("Awaiting user input" if st == "BLOCKED" else "Failed")
        rows.append(f"| **{gid}** | {nm} | `{st}` | {note} | HEAD |")

    table_content = "\n".join(rows)

    content = state_file.read_text(encoding="utf-8")
    table_start = content.find("| **G00** |")
    table_end = content.find("---", table_start) if table_start != -1 else -1

    if table_start != -1 and table_end != -1:
        new_content = content[:table_start] + table_content + "\n\n" + content[table_end:]
        state_file.write_text(new_content, encoding="utf-8")
        print("[+] docs/STATE.md updated with latest clean clone gate table.")


if __name__ == "__main__":
    sys.exit(run_all_gates_in_clean_clone())
