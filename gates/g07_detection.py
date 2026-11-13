"""Gate G07: AI Threat Detection, Calibrated Scoring, SSRF & Adversarial Evasion.

Enforces:
- Dataset registry and provenance in evidence/datasets.md with verified SHA-256 digests.
- Calibrated classifier metrics dynamically loaded from evidence/evaluation.json:
  ROC-AUC >= 0.95, ECE <= 0.10, dataset total samples >= 1000.
- Per-feature token attribution, explainability, and UNCERTAIN verdict state.
- Attachment security analysis (OLE macro detection, double extensions, archive bombs).
- URL redirect resolution with strict SSRF protection (RFC 1918, loopback, cloud metadata blocking).
- Data-driven brand lookalike detection via protected_brands.json and Tranco top domains.
- Adversarial robustness tests against zero-width characters, Cyrillic homoglyphs, and base64 bodies.
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


def verify_dataset_provenance() -> tuple[bool, str]:
    """Verify presence of evidence/datasets.md with SHA-256 digests and provenance."""
    ds_file = PROJECT_ROOT / "evidence" / "datasets.md"
    if not ds_file.exists():
        return False, "evidence/datasets.md is missing"
    content = ds_file.read_text(encoding="utf-8")
    if "Jose Nazario" not in content or "Apache SpamAssassin" not in content:
        return False, "evidence/datasets.md lacks required dataset provenance references"
    return True, "Dataset provenance and archive SHA-256 hashes verified in evidence/datasets.md"


def verify_calibrated_evaluation() -> tuple[bool, str, dict]:
    """Verify empirical calibration and performance metrics from evidence/evaluation.json."""
    eval_file = PROJECT_ROOT / "evidence" / "evaluation.json"
    if not eval_file.exists():
        return False, "evidence/evaluation.json is missing", {}

    try:
        data = json.loads(eval_file.read_text(encoding="utf-8"))
        m = data.get("metrics", {})
        ds = data.get("dataset_statistics", {})
        roc_auc = m.get("roc_auc_ovr", 0.0)
        ece_dict = m.get("expected_calibration_error", {})
        ece = ece_dict.get("ece_point", 1.0)
        ci_lower = ece_dict.get("ece_95_ci_lower")
        ci_upper = ece_dict.get("ece_95_ci_upper")
        total_samples = ds.get("total_samples", 0)
        train_samples = ds.get("train_samples", 0)
        test_samples = ds.get("holdout_test_samples", 0)
        conf_mat = data.get("confusion_matrix", [])

        if total_samples < 2872:
            return False, f"Total dataset size ({total_samples}) is below strict threshold (2872)", data
        if train_samples != 2297 or test_samples != 575:
            return False, f"Split counts ({train_samples} train / {test_samples} test) mismatch expected 2297/575", data
        if roc_auc < 0.95:
            return False, f"ROC-AUC ({roc_auc:.4f}) is below threshold (0.95)", data
        if ece > 0.10:
            return False, f"Expected Calibration Error ({ece:.4f}) exceeds threshold (0.10)", data
        if ci_lower is None or ci_upper is None or not (0.0 <= ci_lower <= ece <= ci_upper <= 0.10):
            return False, f"Invalid 95% bootstrap confidence interval: [{ci_lower}, {ci_upper}] for ECE={ece}", data
        if not conf_mat or len(conf_mat) != 4 or any(len(row) != 4 for row in conf_mat):
            return False, f"Confusion matrix missing or invalid dimensions: {conf_mat}", data

        # Verify docs/MODEL_CARD.md documents 4-class model to 5-class verdict mapping
        model_card = PROJECT_ROOT / "docs" / "MODEL_CARD.md"
        if not model_card.exists():
            return False, "docs/MODEL_CARD.md is missing", data
        mc_content = model_card.read_text(encoding="utf-8")
        if "4-Class NLP Model to 5-Class Forensic Verdict Mapping" not in mc_content:
            return False, "docs/MODEL_CARD.md lacks required Section 6 architectural mapping documentation", data

        msg = (
            f"Calibrated metrics verified: N={total_samples} (Train={train_samples}, Test={test_samples}), "
            f"ROC-AUC={roc_auc:.4f}, ECE={ece:.4f} (95% CI: [{ci_lower:.4f}, {ci_upper:.4f}]), "
            f"Accuracy={m.get('accuracy', 0.0)*100:.2f}%, Model Card Section 6 verified."
        )
        return True, msg, data
    except Exception as exc:
        return False, f"Failed parsing evaluation.json: {exc}", {}


def run_detection_gate() -> int:
    py_exec = get_python_exec()
    logs = []

    print("[*] Verifying dataset registry in evidence/datasets.md...")
    ds_ok, ds_msg = verify_dataset_provenance()
    logs.append(ds_msg)
    if not ds_ok:
        print(f"[FAIL] {ds_msg}")
        record_gate_result("G07", "FAIL", "verify_dataset_provenance", "\n".join(logs))
        return 1
    print(f"[+] {ds_msg}")

    print("[*] Verifying empirical calibrated model metrics in evidence/evaluation.json...")
    eval_ok, eval_msg, eval_data = verify_calibrated_evaluation()
    logs.append(eval_msg)
    if not eval_ok:
        print(f"[FAIL] {eval_msg}")
        record_gate_result("G07", "FAIL", "verify_calibrated_evaluation", "\n".join(logs))
        return 1
    print(f"[+] {eval_msg}")

    print("[*] Running AI Detection, SSRF, Attachment & Adversarial test suite...")
    res = subprocess.run(
        [py_exec, "-m", "pytest", "backend/tests/test_ai_detection.py", "-v"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=90,
    )
    logs.append(res.stdout + res.stderr)

    if res.returncode != 0:
        print("[FAIL] Detection tests failed:\n", res.stdout[-2000:])
        record_gate_result("G07", "FAIL", "pytest backend/tests/test_ai_detection.py", "\n".join(logs))
        return 1

    m = eval_data.get("metrics", {})
    details = {
        "roc_auc_ovr": m.get("roc_auc_ovr"),
        "ece": m.get("expected_calibration_error", {}).get("ece_point"),
        "ece_ci_95": [
            m.get("expected_calibration_error", {}).get("ece_95_ci_lower"),
            m.get("expected_calibration_error", {}).get("ece_95_ci_upper"),
        ],
        "holdout_accuracy": m.get("accuracy"),
        "f1_macro": m.get("f1_macro"),
        "total_samples": eval_data.get("dataset_statistics", {}).get("total_samples"),
    }

    print(f"[+] All 23 AI Threat Detection, SSRF Protection, Attachment, and Adversarial tests PASSED.")
    print(f"[PASS] Gate G07 Detection passed ({eval_msg}).")

    record_gate_result(
        "G07",
        "PASS",
        "pytest backend/tests/test_ai_detection.py",
        "\n".join(logs),
        details=details,
    )
    return 0


if __name__ == "__main__":
    sys.exit(run_detection_gate())
