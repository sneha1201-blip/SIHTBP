"""Gate G02: Mutation Canary Fault Injection Suite.

Enforces:
Injects 10 known architectural and forensic faults one by one on a temporary working copy.
For each fault, the corresponding unit/security test MUST FAIL (killing the mutation).
If any mutant survives (test passes despite the injected flaw), the gate FAILS.

Expected: 10/10 mutants killed.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import List

os.environ.setdefault("TESTING", "1")
os.environ.setdefault("DEBUG", "1")

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from gates.common import get_python_exec, record_gate_result


class MutationCanary:
    def __init__(self, name: str, file_path: str, target: str, replacement: str, test_target: str):
        self.name = name
        self.file_path = PROJECT_ROOT / file_path
        self.target = target
        self.replacement = replacement
        self.test_target = test_target

    def inject(self) -> str:
        content = self.file_path.read_text(encoding="utf-8")
        if self.target not in content:
            raise ValueError(f"Target pattern not found for mutation '{self.name}' in {self.file_path}")
        mutated = content.replace(self.target, self.replacement, 1)
        self.file_path.write_text(mutated, encoding="utf-8")
        return content

    def restore(self, original_content: str) -> None:
        self.file_path.write_text(original_content, encoding="utf-8")


MUTATION_SUITE: List[MutationCanary] = [
    MutationCanary(
        name="Mutant 1: DKIM verification always True",
        file_path="backend/app/forensics/auth_validator.py",
        target="sig_valid = d.verify(idx=idx, dnsfunc=active_dnsfunc)",
        replacement="sig_valid = True",
        test_target="backend/tests/test_protocol_auth.py::test_dkim_tampered_body_fails",
    ),
    MutationCanary(
        name="Mutant 2: Vault hash check removed",
        file_path="backend/app/database/vault.py",
        target="if computed_sha256.lower() != sha256_hash.lower():",
        replacement="if False:",
        test_target="backend/tests/test_database.py::test_vault_tamper_detection",
    ),
    MutationCanary(
        name="Mutant 3: Auth dependency removed from reports endpoint",
        file_path="backend/app/api/v1/endpoints_reports.py",
        target="current_user: User = Depends(require_any_authenticated)",
        replacement="current_user: Optional[User] = None",
        test_target="backend/tests/test_security.py::test_unauthenticated_requests_rejected_with_401",
    ),
    MutationCanary(
        name="Mutant 4: Multi-signal clustering weakened to single family",
        file_path="backend/app/forensics/campaign_clusterer.py",
        target="is_clustered = is_deterministic or (len(matched_families) >= 2)",
        replacement="is_clustered = is_deterministic or (len(matched_families) >= 1)",
        test_target="backend/tests/test_campaign_clustering.py::test_multi_signal_clustering_requires_two_signals",
    ),
    MutationCanary(
        name="Mutant 5: GeoIP returns dummy default coordinates for private IP",
        file_path="backend/app/osint/geo_resolver.py",
        target="latitude=None,\n            longitude=None,",
        replacement="latitude=0.0,\n            longitude=0.0,",
        test_target="backend/tests/test_osint_geoip.py::test_private_ip_zero_guess",
    ),
    MutationCanary(
        name="Mutant 6: Vault HMAC signature generation corrupted",
        file_path="backend/app/database/vault.py",
        target="return hmac.new(key_bytes, message_bytes, hashlib.sha256).hexdigest()",
        replacement='return "0" * 64',
        test_target="backend/tests/test_database.py::test_hmac_signatures",
    ),
    MutationCanary(
        name="Mutant 7: Audit ledger parent hash chaining ignored",
        file_path="backend/app/database/audit_service.py",
        target="prev_hash = compute_entry_hash(latest_entry.hmac_signature, str(latest_entry.id))",
        replacement="prev_hash = GENESIS_HASH",
        test_target="backend/tests/test_security.py::test_tampered_audit_chain_detected",
    ),
    MutationCanary(
        name="Mutant 8: Composite threat score forced to constant 0.0",
        file_path="backend/app/ai/threat_scorer.py",
        target="final_score = round(min(100.0, override_score if critical_override else weighted_score), 1)",
        replacement="final_score = 0.0",
        test_target="backend/tests/test_ai_detection.py::test_composite_threat_scoring_formula",
    ),
    MutationCanary(
        name="Mutant 9: Upload size limit disabled",
        file_path="backend/app/core/upload_validator.py",
        target="if total_read > limit:",
        replacement="if False:",
        test_target="backend/tests/test_security.py::test_oversize_upload_rejected",
    ),
    MutationCanary(
        name="Mutant 10: PDF export ignores physical vault tamper",
        file_path="backend/app/api/v1/endpoints_reports.py",
        target="if computed_sha256.lower() != email.sha256_hash.lower():",
        replacement="if False:",
        test_target="backend/tests/test_pipeline.py::test_pdf_report_aborts_with_409_on_vault_tamper",
    ),
]


def run_mutation_gate() -> int:
    py_exec = get_python_exec()
    killed = 0
    survived = 0
    log_lines = []

    print(f"[*] Running Mutation Canary Fault Injection ({len(MUTATION_SUITE)} faults)...")

    for i, mutant in enumerate(MUTATION_SUITE, 1):
        original = None
        try:
            original = mutant.inject()
            print(f"  [{i}/{len(MUTATION_SUITE)}] Testing {mutant.name} against {mutant.test_target}...")

            res = subprocess.run(
                [py_exec, "-m", "pytest", mutant.test_target, "-q"],
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
                timeout=60,
            )

            if res.returncode != 0:
                print(f"    -> [KILLED] Test failed as expected (Returncode: {res.returncode})")
                killed += 1
                log_lines.append(f"{mutant.name}: KILLED by {mutant.test_target}")
            else:
                print(f"    -> [SURVIVED!] Test unexpectedly PASSED! Mutant survived!")
                survived += 1
                log_lines.append(f"{mutant.name}: SURVIVED (Test passed when it should have failed)")
        except Exception as exc:
            print(f"    -> [ERROR injecting mutant {mutant.name}]: {exc}")
            survived += 1
            log_lines.append(f"{mutant.name}: INJECTION_ERROR: {exc}")
        finally:
            if original is not None:
                mutant.restore(original)

    print("----------------------------------------------------------------------")
    print(f"[*] Mutation Canary Summary: {killed}/{len(MUTATION_SUITE)} Killed | {survived} Survived")
    print("----------------------------------------------------------------------")

    status = "PASS" if survived == 0 else "FAIL"
    record_gate_result(
        "G02",
        status,
        f"mutation_canary_run ({len(MUTATION_SUITE)} mutants)",
        "\n".join(log_lines),
        details={"total": len(MUTATION_SUITE), "killed": killed, "survived": survived},
    )

    return 0 if survived == 0 else 1


if __name__ == "__main__":
    sys.exit(run_mutation_gate())
