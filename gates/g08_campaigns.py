"""Gate G08: Multi-Signal Threat Campaign Correlation & STIX 2.1 Intelligence.

Enforces:
- Multi-signal correlation requiring >=2 independent signal families.
- High-fanout infrastructure (Google, Microsoft, Amazon, Cloudflare) never forms a sole link.
- 3 unrelated Google-ASN emails do NOT cluster; 3 near-identical bodies DO cluster.
- Empirical clustering metrics from evidence/cluster_eval.json: ARI >= 0.85, NMI >= 0.85, Purity >= 0.90, Noise FPR = 0%.
- Analyst workflows (merge, split, label) append to hash-chained audit ledger.
- STIX 2.1 JSON bundle verified against official OASIS stix2 library schemas.
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


def validate_stix2_bundle() -> tuple[bool, str]:
    """Validate generated STIX 2.1 bundle using the official stix2 Python library."""
    bundle_path = PROJECT_ROOT / "evidence" / "campaign_bundle.json"
    if not bundle_path.exists():
        return False, "evidence/campaign_bundle.json does not exist"

    try:
        import stix2
        raw_bundle = bundle_path.read_text(encoding="utf-8")
        parsed = stix2.parse(raw_bundle, allow_custom=True)
        if not hasattr(parsed, "objects") or len(parsed.objects) == 0:
            return False, "STIX 2.1 bundle contains 0 objects"
        return True, f"Successfully validated STIX 2.1 bundle with {len(parsed.objects)} objects"
    except Exception as exc:
        return False, f"STIX 2.1 schema validation failed: {exc}"


def verify_cluster_eval_metrics() -> tuple[bool, str, dict]:
    """Dynamically verify empirical clustering metrics from evidence/cluster_eval.json."""
    eval_file = PROJECT_ROOT / "evidence" / "cluster_eval.json"
    if not eval_file.exists():
        return False, "evidence/cluster_eval.json does not exist", {}

    clusterer_file = PROJECT_ROOT / "backend" / "app" / "forensics" / "campaign_clusterer.py"
    if clusterer_file.exists() and eval_file.stat().st_mtime < clusterer_file.stat().st_mtime:
        return False, f"evidence/cluster_eval.json is older than {clusterer_file.name}", {}

    try:
        data = json.loads(eval_file.read_text(encoding="utf-8"))
        meta = data.get("metadata", {})
        if "seed" not in meta:
            return False, "cluster_eval.json metadata is missing 'seed'", data
        if "split" not in meta and "dev_test_split" not in meta:
            return False, "cluster_eval.json metadata is missing split documentation", data
        if "held_out_n" not in meta and "test_n" not in meta:
            return False, "cluster_eval.json metadata is missing held-out sample count ('held_out_n')", data

        m = data.get("held_out_metrics") or data.get("metrics", {})
        ari = m.get("adjusted_rand_index_ari", 0.0)
        nmi = m.get("normalized_mutual_info_nmi", 0.0)
        purity = m.get("clustering_purity", 0.0)
        noise_fp = m.get("noise_false_positive_rate", 1.0)

        if ari < 0.85:
            return False, f"Held-out ARI ({ari}) is below required threshold (0.85)", data
        if nmi < 0.85:
            return False, f"Held-out NMI ({nmi}) is below required threshold (0.85)", data
        if purity < 0.90:
            return False, f"Held-out Clustering Purity ({purity}) is below required threshold (0.90)", data
        if noise_fp > 0.0:
            return False, f"Held-out Noise False Positive Rate ({noise_fp}) must be 0.0", data

        msg = f"Held-out clustering metrics verified: ARI={ari}, NMI={nmi}, Purity={purity}, Noise FPR={noise_fp}"
        return True, msg, data
    except Exception as e:
        return False, f"Failed parsing cluster_eval.json: {e}", {}


def run_campaigns_gate() -> int:
    py_exec = get_python_exec()
    logs: list[str] = []

    print("[*] Running campaign clustering test suite (backend/tests/test_campaign_clustering.py)...")
    res = subprocess.run(
        [py_exec, "-m", "pytest", "backend/tests/test_campaign_clustering.py", "-v"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    logs.append(res.stdout + res.stderr)
    if res.returncode != 0:
        print("[FAIL] Campaign clustering test suite failed:\n", res.stdout, res.stderr)
        record_gate_result("G08", "FAIL", "pytest backend/tests/test_campaign_clustering.py", "\n".join(logs))
        return 1

    print("[*] Verifying empirical campaign clustering metrics...")
    eval_ok, eval_msg, eval_data = verify_cluster_eval_metrics()
    logs.append(eval_msg)
    if not eval_ok:
        print(f"[FAIL] {eval_msg}")
        record_gate_result("G08", "FAIL", "verify_cluster_eval_metrics", "\n".join(logs))
        return 1
    print(f"[+] {eval_msg}")

    print("[*] Validating STIX 2.1 JSON bundle with stix2 library...")
    stix_ok, stix_msg = validate_stix2_bundle()
    logs.append(stix_msg)
    if not stix_ok:
        print(f"[FAIL] {stix_msg}")
        record_gate_result("G08", "FAIL", "validate_stix2_bundle", stix_msg)
        return 1
    print(f"[+] {stix_msg}")

    m = eval_data.get("metrics", {})
    details = {
        "ari": m.get("adjusted_rand_index_ari"),
        "nmi": m.get("normalized_mutual_info_nmi"),
        "purity": m.get("clustering_purity"),
        "noise_fp_rate": m.get("noise_false_positive_rate"),
        "stix2_validation": stix_msg,
    }

    print("[PASS] Gate G08 Campaigns passed with all clustering metrics and STIX 2.1 schemas verified.")
    record_gate_result("G08", "PASS", "g08_campaigns_runner", "\n".join(logs), details=details)
    return 0


if __name__ == "__main__":
    sys.exit(run_campaigns_gate())
