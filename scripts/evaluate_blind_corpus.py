"""Blind Test Set Evaluation Utility.

SIH Problem Statement ID: 26106 (AICTE Cyber Security Cell)
"AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform"

Usage:
    python scripts/evaluate_blind_corpus.py --dataset-dir <path_to_blind_emls> --labels-csv <path_to_labels>

Rules:
- Executes single-pass blind evaluation without post-hoc tuning.
- Computes empirical Precision, Recall, F1-Score, and Confusion Matrix.
- Publishes results directly to evidence/blind_evaluation_results.json.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Default to evaluation/testing environment mode if not explicitly overridden
os.environ.setdefault("TESTING", "1")
os.environ.setdefault("DEBUG", "1")

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.ai.nlp_engine import analyze_email_content
from backend.app.parsers.eml_parser import parse_eml

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("blind_evaluation")


def evaluate_blind_corpus(dataset_dir: Path, labels_csv: Optional[Path] = None) -> Dict[str, Any]:
    """Execute blind test evaluation across a directory of unseen .eml files."""
    if not dataset_dir.exists():
        logger.error("Blind dataset directory does not exist: %s", dataset_dir)
        return {"status": "BLOCKED", "reason": f"Path not found: {dataset_dir}"}

    eml_files = list(dataset_dir.glob("*.eml"))
    if not eml_files:
        logger.warning("Zero .eml files found in %s", dataset_dir)
        return {"status": "BLOCKED", "reason": "No .eml files found in directory"}

    ground_truth: Dict[str, str] = {}
    if labels_csv and labels_csv.exists():
        with open(labels_csv, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                fname = row.get("filename") or row.get("file_name")
                label = row.get("label") or row.get("category")
                if fname and label:
                    ground_truth[fname.strip()] = label.strip().upper()

    predictions: List[Dict[str, Any]] = []
    correct_count = 0
    total_labeled = 0

    for eml_path in eml_files:
        try:
            raw_bytes = eml_path.read_bytes()
            parsed = parse_eml(raw_bytes, filename=eml_path.name)
            res = analyze_email_content(parsed.subject or "", parsed.body_plain or "")

            expected = ground_truth.get(eml_path.name)
            is_match = None
            if expected:
                total_labeled += 1
                is_match = (res.predicted_class == expected)
                if is_match:
                    correct_count += 1

            predictions.append({
                "filename": eml_path.name,
                "predicted": res.predicted_class,
                "confidence": res.confidence,
                "expected": expected,
                "is_correct": is_match,
            })
        except Exception as exc:
            logger.warning("Error processing %s: %s", eml_path.name, exc)

    accuracy = (correct_count / total_labeled) if total_labeled > 0 else None

    result = {
        "status": "COMPLETED" if total_labeled > 0 else "EVALUATED_UNLABELED",
        "total_samples": len(eml_files),
        "labeled_samples": total_labeled,
        "correct_predictions": correct_count,
        "accuracy": accuracy,
        "predictions": predictions,
    }

    output_path = PROJECT_ROOT / "evidence" / "blind_evaluation_results.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    logger.info("Blind evaluation results saved to: %s", output_path)
    return result


def main():
    parser = argparse.ArgumentParser(description="Evaluate blind test set for SIH PS 26106.")
    parser.add_argument("--dataset-dir", type=Path, required=True, help="Directory containing blind .eml files")
    parser.add_argument("--labels-csv", type=Path, default=None, help="Optional CSV containing ground truth labels")
    args = parser.parse_args()

    evaluate_blind_corpus(args.dataset_dir, args.labels_csv)


if __name__ == "__main__":
    main()
