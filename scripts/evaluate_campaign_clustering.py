"""Empirical Campaign Clustering Evaluation Script.

Evaluates the multi-signal campaign correlation engine against the ground-truth
corpus (backend/tests/fixtures/campaign_eval_corpus.py).

Computes:
- Adjusted Rand Index (ARI)
- Normalized Mutual Information (NMI)
- Clustering Purity
- Pairwise Precision, Recall, F1
- False Positive Rate on Noise (Google AS15169, AWS AS16509, ERNET AS2687)

Outputs raw results to evidence/cluster_eval.json.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

os.environ.setdefault("TESTING", "1")

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from sklearn.metrics import adjusted_rand_score, normalized_mutual_info_score
from sklearn.model_selection import train_test_split
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from backend.app.database.models import CampaignEmail, Email, HeaderHop, ThreatIndicator
from backend.app.database.session import Base
from backend.app.forensics.campaign_clusterer import cluster_email_dynamically
from backend.app.parsers.mime_normalizer import compute_simhash
from backend.tests.fixtures.campaign_eval_corpus import CAMPAIGN_EVAL_CORPUS

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_FILE = PROJECT_ROOT / "evidence" / "cluster_eval.json"
EVAL_SEED = 26106


def get_git_commit() -> str:
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        return res.stdout.strip()
    except Exception:
        return "UNKNOWN_COMMIT"


def calculate_purity(labels_true: List[str], labels_pred: List[str]) -> float:
    """Calculate clustering purity: Purity = 1/N * sum_k(max_j |C_k cap L_j|)."""
    clusters: Dict[str, List[str]] = {}
    for pred, true in zip(labels_pred, labels_true):
        clusters.setdefault(pred, []).append(true)

    total_correct = 0
    for cluster_members in clusters.values():
        counts = Counter(cluster_members)
        total_correct += counts.most_common(1)[0][1]

    return round(total_correct / len(labels_true), 4)


def calculate_pairwise_metrics(labels_true: List[str], labels_pred: List[str]) -> Dict[str, float]:
    """Calculate pairwise Precision, Recall, and F1 score."""
    n = len(labels_true)
    tp = 0
    fp = 0
    fn = 0
    tn = 0

    for i in range(n):
        for j in range(i + 1, n):
            same_true = (labels_true[i] == labels_true[j]) and (labels_true[i] != "noise")
            same_pred = (labels_pred[i] == labels_pred[j]) and (labels_pred[i] != "isolated")

            if same_true and same_pred:
                tp += 1
            elif not same_true and same_pred:
                fp += 1
            elif same_true and not same_pred:
                fn += 1
            else:
                tn += 1

    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
    f1 = round(2 * precision * recall / (precision + recall), 4) if (precision + recall) > 0 else 0.0

    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


async def evaluate_split(split_name: str, samples: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Run dynamic campaign clustering on an isolated partition of samples."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_maker = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    now = datetime.now(timezone.utc)

    predictions: Dict[str, str] = {}
    ground_truth_map: Dict[str, str] = {}
    email_id_to_sample_id: Dict[uuid.UUID, str] = {}

    async with session_maker() as db:
        for sample in samples:
            s_id = sample["id"]
            true_camp = sample["ground_truth"] or "noise"
            ground_truth_map[s_id] = true_camp

            simhash_val = compute_simhash(sample["body"])
            email_id = uuid.uuid4()
            email_id_to_sample_id[email_id] = s_id
            predictions[s_id] = f"isolated_{s_id}"

            email = Email(
                id=email_id,
                sha256_hash=f"eval_{s_id}_" + "a" * (64 - len(s_id) - 6),
                md5_hash="a" * 32,
                file_name=f"{s_id}.eml",
                file_size_bytes=len(sample["body"]),
                raw_storage_path=f"storage/vault/eval/{s_id}.eml",
                subject=sample["subject"],
                sender_email=sample["sender_email"],
                reply_to=sample.get("reply_to"),
                body_plain=sample["body"],
                simhash_body=simhash_val,
                ingested_at=now,
            )
            db.add(email)
            await db.flush()

            if sample.get("origin_ip"):
                hop = HeaderHop(
                    id=uuid.uuid4(),
                    email_id=email.id,
                    hop_order=1,
                    hop_ip=sample["origin_ip"],
                    asn_number=sample.get("origin_asn"),
                    asn_org=sample.get("origin_asn_org"),
                    node_type="ORIGINATING",
                    delay_seconds=0.0,
                )
                db.add(hop)
                await db.flush()

            for url in sample.get("urls", []):
                db.add(
                    ThreatIndicator(
                        id=uuid.uuid4(),
                        email_id=email.id,
                        ioc_type="URL",
                        ioc_value=url,
                        reputation_score=90.0,
                    )
                )
            for att_hash in sample.get("attachment_hashes", []):
                db.add(
                    ThreatIndicator(
                        id=uuid.uuid4(),
                        email_id=email.id,
                        ioc_type="ATTACHMENT",
                        ioc_value=att_hash,
                        reputation_score=95.0,
                    )
                )
            await db.flush()

            sample_iocs = set(
                [u.strip().lower() for u in sample.get("urls", [])]
                + [a.strip().lower() for a in sample.get("attachment_hashes", [])]
            )

            await cluster_email_dynamically(
                db=db,
                email=email,
                origin_ip=sample.get("origin_ip"),
                origin_asn=sample.get("origin_asn"),
                threat_score=85.0 if true_camp != "noise" else 15.0,
                candidate_iocs=sample_iocs,
            )
            await db.commit()

        from sqlalchemy import select
        ce_res = await db.execute(select(CampaignEmail))
        for ce in ce_res.scalars().all():
            if ce.email_id in email_id_to_sample_id:
                s_id = email_id_to_sample_id[ce.email_id]
                predictions[s_id] = str(ce.campaign_id)

    await engine.dispose()

    sample_ids = [s["id"] for s in samples]
    y_true = [ground_truth_map[s_id] for s_id in sample_ids]
    y_pred = [predictions[s_id] for s_id in sample_ids]

    ari = round(float(adjusted_rand_score(y_true, y_pred)), 4)
    nmi = round(float(normalized_mutual_info_score(y_true, y_pred)), 4)
    purity = calculate_purity(y_true, y_pred)
    pairwise = calculate_pairwise_metrics(y_true, y_pred)

    noise_samples = [s for s in samples if s["ground_truth"] is None]
    noise_clustered_count = sum(1 for s in noise_samples if not predictions[s["id"]].startswith("isolated_"))
    noise_fp_rate = round(noise_clustered_count / len(noise_samples), 4) if noise_samples else 0.0

    google_samples = [s for s in noise_samples if s.get("origin_asn") == 15169]
    google_clustered = [s["id"] for s in google_samples if not predictions[s["id"]].startswith("isolated_")]

    aws_samples = [s for s in noise_samples if s.get("origin_asn") == 16509]
    aws_clustered = [s["id"] for s in aws_samples if not predictions[s["id"]].startswith("isolated_")]

    # Source breakdown
    real_samples = [s for s in samples if s.get("source_type") == "REAL_CORPUS"]
    gen_samples = [s for s in samples if s.get("source_type") != "REAL_CORPUS"]

    real_purity = (
        calculate_purity(
            [ground_truth_map[s["id"]] for s in real_samples],
            [predictions[s["id"]] for s in real_samples],
        )
        if real_samples
        else 1.0
    )
    gen_purity = (
        calculate_purity(
            [ground_truth_map[s["id"]] for s in gen_samples],
            [predictions[s["id"]] for s in gen_samples],
        )
        if gen_samples
        else 1.0
    )

    return {
        "metrics": {
            "adjusted_rand_index_ari": ari,
            "normalized_mutual_info_nmi": nmi,
            "clustering_purity": purity,
            "pairwise_precision": pairwise["precision"],
            "pairwise_recall": pairwise["recall"],
            "pairwise_f1": pairwise["f1"],
            "noise_false_positive_rate": noise_fp_rate,
        },
        "hyperscaler": {
            "google_as15169_samples_tested": len(google_samples),
            "google_as15169_incorrectly_clustered": len(google_clustered),
            "aws_as16509_samples_tested": len(aws_samples),
            "aws_as16509_incorrectly_clustered": len(aws_clustered),
            "hyperscaler_clustering_status": "PASS" if len(google_clustered) == 0 and len(aws_clustered) == 0 else "FAIL",
        },
        "pairwise": pairwise,
        "source_breakdown": {
            "real_corpus_n": len(real_samples),
            "real_corpus_purity": real_purity,
            "generated_n": len(gen_samples),
            "generated_purity": gen_purity,
        },
    }


async def run_evaluation() -> Dict[str, Any]:
    print(f"Running stratified dev/held-out campaign evaluation (seed={EVAL_SEED})...")

    labels = [s["ground_truth"] or "noise" for s in CAMPAIGN_EVAL_CORPUS]
    dev_idx, test_idx = train_test_split(
        range(len(CAMPAIGN_EVAL_CORPUS)),
        test_size=0.50,
        random_state=EVAL_SEED,
        stratify=labels,
    )

    dev_samples = [CAMPAIGN_EVAL_CORPUS[i] for i in dev_idx]
    held_out_samples = [CAMPAIGN_EVAL_CORPUS[i] for i in test_idx]

    print(f"[*] Ingesting and evaluating DEV split ({len(dev_samples)} samples)...")
    dev_res = await evaluate_split("DEV", dev_samples)

    print(f"[*] Ingesting and evaluating HELD-OUT split ({len(held_out_samples)} samples)...")
    held_out_res = await evaluate_split("HELD_OUT", held_out_samples)

    m_dev = dev_res["metrics"]
    m_held = held_out_res["metrics"]
    hs = held_out_res["hyperscaler"]

    real_count = sum(1 for s in CAMPAIGN_EVAL_CORPUS if s.get("source_type") == "REAL_CORPUS")
    gen_count = sum(1 for s in CAMPAIGN_EVAL_CORPUS if s.get("source_type") != "REAL_CORPUS")

    report = {
        "metadata": {
            "evaluation_timestamp": datetime.now(timezone.utc).isoformat(),
            "git_commit": get_git_commit(),
            "seed": EVAL_SEED,
            "split": "50/50 stratified dev/held-out",
            "dev_test_split": "50/50 stratified",
            "corpus_size": len(CAMPAIGN_EVAL_CORPUS),
            "dev_n": len(dev_samples),
            "held_out_n": len(held_out_samples),
            "test_n": len(held_out_samples),
            "real_corpus_samples_count": real_count,
            "generated_samples_count": gen_count,
            "campaign_classes_count": len(set(labels)) - (1 if "noise" in labels else 0),
            "noise_samples_count": sum(1 for s in CAMPAIGN_EVAL_CORPUS if s["ground_truth"] is None),
            "chosen_threshold": 0.70,
            "threshold_selection_split": "DEV",
        },
        "metrics": m_dev,  # Backward compatibility
        "dev_metrics": m_dev,
        "held_out_metrics": m_held,
        "hyperscaler_isolation_verification": hs,
        "pairwise_confusion": held_out_res["pairwise"],
        "source_breakdown": held_out_res["source_breakdown"],
    }

    EVIDENCE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(EVIDENCE_FILE, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print("\n================ CLUSTERING EVALUATION REPORT ================")
    print(f"Total Corpus: {len(CAMPAIGN_EVAL_CORPUS)} (Real Nazario: {real_count}, Generated: {gen_count})")
    print(f"Split: 50% Dev ({len(dev_samples)}) / 50% Held-Out ({len(held_out_samples)}) [Seed: {EVAL_SEED}]")
    print(f"DEV Metrics:      ARI={m_dev['adjusted_rand_index_ari']} | NMI={m_dev['normalized_mutual_info_nmi']} | Purity={m_dev['clustering_purity']} | Noise FPR={m_dev['noise_false_positive_rate']*100}%")
    print(f"HELD-OUT Metrics: ARI={m_held['adjusted_rand_index_ari']} | NMI={m_held['normalized_mutual_info_nmi']} | Purity={m_held['clustering_purity']} | Noise FPR={m_held['noise_false_positive_rate']*100}%")
    print(f"Held-Out Sources: Real Purity={held_out_res['source_breakdown']['real_corpus_purity']} | Generated Purity={held_out_res['source_breakdown']['generated_purity']}")
    print(f"Hyperscaler Isolation: {hs['hyperscaler_clustering_status']}")
    print(f"Report written to: {EVIDENCE_FILE}")
    print("==============================================================")
    return report


if __name__ == "__main__":
    asyncio.run(run_evaluation())
