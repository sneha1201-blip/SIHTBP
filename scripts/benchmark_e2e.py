"""Comprehensive End-to-End Pipeline Performance Benchmark Script.

SIH Problem Statement ID: 26106 (AICTE Cyber Security Cell)
"AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform"

Executes real-corpus forensic ingestion across the end-to-end pipeline,
measuring exact stage-by-stage latencies, throughput (emails/second),
and Section 63 BSA 2023 PDF generation performance.

Persists verifiable performance artifact to evidence/benchmark_results.json.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Set mandatory cryptographic secrets for benchmarking runtime
os.environ.setdefault("VAULT_HMAC_SECRET", "aicte_sec63_bsa_production_hmac_secret_2026_super_secure_vault_key")
os.environ.setdefault("JWT_SECRET_KEY", "aicte_jwt_secret_key_production_2026_argon2_super_secure")
os.environ.setdefault("SECRET_KEY", "aicte_jwt_secret_key_production_2026_argon2_super_secure")

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import selectinload

from backend.app.ai.nlp_engine import analyze_email_content
from backend.app.ai.threat_scorer import compute_threat_score
from backend.app.ai.url_analyzer import analyze_url
from backend.app.database.models import Email, User, UserRole
from backend.app.database.session import Base
from backend.app.database.vault import calculate_hashes, store_raw_evidence
from backend.app.forensics.auth_validator import validate_protocol_authentication
from backend.app.forensics.campaign_clusterer import cluster_email_dynamically
from backend.app.forensics.hop_traversal import reverse_hop_traversal
from backend.app.forensics.ioc_extractor import extract_iocs
from backend.app.forensics.job_queue import execute_forensic_pipeline
from backend.app.forensics.spoof_detector import detect_spoofing
from backend.app.parsers.eml_parser import parse_eml
from backend.app.reporting.pdf_generator import generate_forensic_pdf

FIXTURES_DIR = PROJECT_ROOT / "backend" / "tests" / "fixtures" / "emails"
EVIDENCE_FILE = PROJECT_ROOT / "evidence" / "benchmark_results.json"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("benchmark")


def get_git_commit() -> str:
    """Retrieve current git commit hash."""
    try:
        res = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True)
        return res.stdout.strip()
    except Exception:
        return "UNKNOWN"


async def run_benchmark(iterations: int = 3) -> Dict[str, Any]:
    """Run E2E forensic pipeline benchmark across real corpus samples."""
    logger.info("Initializing isolated SQLite database for benchmark run...")
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_maker = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    eml_files = sorted(list(FIXTURES_DIR.glob("*.eml")))
    if not eml_files:
        raise RuntimeError(f"No .eml fixtures found in {FIXTURES_DIR}")

    logger.info("Found %d test corpus samples. Running %d iterations (%d total runs)...",
                len(eml_files), iterations, len(eml_files) * iterations)

    stage_latencies: Dict[str, List[float]] = {
        "dual_hashing_vault_store": [],
        "mime_rfc822_parsing": [],
        "hop_traversal_geoip_asn": [],
        "protocol_auth_dkim_spf_dmarc": [],
        "spoof_homoglyph_detection": [],
        "ioc_extraction_url_deobfuscation": [],
        "nlp_intent_and_entity_extraction": [],
        "threat_scoring_formula": [],
        "dynamic_campaign_clustering": [],
        "pdf_generation_section63_bsa": [],
        "full_pipeline_ingest_e2e": [],
    }

    total_start = time.perf_counter()
    run_count = 0

    async with session_maker() as db:
        # Seed test examiner account
        examiner = User(
            id=uuid.uuid4(),
            username="analyst_benchmark",
            email="analyst@aicte.gov.in",
            password_hash="fakehashforbench",
            role=UserRole.ANALYST,
            is_active=True,
        )
        db.add(examiner)
        await db.commit()

        for it in range(iterations):
            for eml_path in eml_files:
                raw_bytes = eml_path.read_bytes()
                filename = f"bench_it{it}_{eml_path.name}"

                # -----------------------------------------------------------------
                # MICRO-BENCHMARKS: Stage-by-Stage Latency Profiling
                # -----------------------------------------------------------------
                # 1. Dual Hashing & Vault
                t_s1 = time.perf_counter()
                sha256_hash, md5_hash, stored_path, size_bytes = store_raw_evidence(raw_bytes, filename)
                s1_ms = (time.perf_counter() - t_s1) * 1000.0
                stage_latencies["dual_hashing_vault_store"].append(s1_ms)

                # 2. MIME / RFC 822 Parsing
                t_s2 = time.perf_counter()
                parsed = parse_eml(raw_bytes, filename=filename)
                s2_ms = (time.perf_counter() - t_s2) * 1000.0
                stage_latencies["mime_rfc822_parsing"].append(s2_ms)

                # 3. Hop Traversal & MaxMind GeoIP / ASN
                t_s3 = time.perf_counter()
                hops_analyzed, earliest_ip = reverse_hop_traversal(parsed.received_headers)
                s3_ms = (time.perf_counter() - t_s3) * 1000.0
                stage_latencies["hop_traversal_geoip_asn"].append(s3_ms)

                # 4. Protocol Authentication (DKIM/SPF/DMARC/ARC)
                t_s4 = time.perf_counter()
                auth_res = validate_protocol_authentication(
                    from_email=parsed.sender_email,
                    return_path=parsed.return_path,
                    headers_dict=parsed.headers_dict,
                    auth_results_header=parsed.authentication_results,
                    raw_bytes=raw_bytes,
                    connecting_ip=earliest_ip,
                    helo_name=hops_analyzed[0].from_mta if hops_analyzed else None,
                )
                s4_ms = (time.perf_counter() - t_s4) * 1000.0
                stage_latencies["protocol_auth_dkim_spf_dmarc"].append(s4_ms)

                # 5. Spoofing & Impersonation Engine
                t_s5 = time.perf_counter()
                spoof_res = detect_spoofing(
                    sender_display=parsed.sender_display,
                    sender_email=parsed.sender_email,
                    return_path=parsed.return_path,
                    reply_to=parsed.reply_to,
                )
                s5_ms = (time.perf_counter() - t_s5) * 1000.0
                stage_latencies["spoof_homoglyph_detection"].append(s5_ms)

                # 6. IOC Extraction & URL Analysis
                t_s6 = time.perf_counter()
                raw_iocs = extract_iocs(
                    body_plain=parsed.body_plain,
                    body_html=parsed.body_html,
                    sender_email=parsed.sender_email,
                    reply_to=parsed.reply_to,
                    attachments=parsed.attachments,
                    hop_ips=[str(h.hop_ip) for h in hops_analyzed if h.hop_ip],
                )
                analyzed_urls = []
                for ioc in raw_iocs[:3]:
                    if ioc.ioc_type == "URL":
                        u_res = analyze_url(ioc.raw_value, check_rdap=False)
                        analyzed_urls.append(u_res)
                s6_ms = (time.perf_counter() - t_s6) * 1000.0
                stage_latencies["ioc_extraction_url_deobfuscation"].append(s6_ms)

                # 7. AI NLP Content Classification
                t_s7 = time.perf_counter()
                nlp_res = analyze_email_content(
                    subject=parsed.subject,
                    body=parsed.body_plain,
                )
                s7_ms = (time.perf_counter() - t_s7) * 1000.0
                stage_latencies["nlp_intent_and_entity_extraction"].append(s7_ms)

                # 8. Threat Scoring Formula
                t_s8 = time.perf_counter()
                score_calc = compute_threat_score(
                    auth_res=auth_res,
                    spoof_res=spoof_res,
                    nlp_res=nlp_res,
                    url_results=analyzed_urls,
                )
                s8_ms = (time.perf_counter() - t_s8) * 1000.0
                stage_latencies["threat_scoring_formula"].append(s8_ms)

                # -----------------------------------------------------------------
                # FULL PIPELINE E2E INGESTION BENCHMARK
                # -----------------------------------------------------------------
                t_e2e_start = time.perf_counter()
                dossier = await execute_forensic_pipeline(
                    raw_bytes=raw_bytes,
                    file_name=f"run_{run_count}_{eml_path.name}",
                    actor="analyst_benchmark",
                    db=db,
                )
                e2e_ms = (time.perf_counter() - t_e2e_start) * 1000.0
                stage_latencies["full_pipeline_ingest_e2e"].append(e2e_ms)

                # -----------------------------------------------------------------
                # SECTION 63 BSA 2023 PDF GENERATION BENCHMARK
                # -----------------------------------------------------------------
                t_pdf = time.perf_counter()
                pdf_buffer = generate_forensic_pdf(
                    email_data=dossier["email"],
                    hops=dossier.get("header_hops", []),
                    analysis=dossier.get("forensic_analysis") or {},
                    iocs=dossier.get("threat_indicators", []),
                    audit_logs=dossier.get("audit_logs", []),
                    examiner_name="analyst_benchmark",
                    examiner_designation="Forensic ANALYST, AICTE Cyber Security Cell",
                )
                pdf_ms = (time.perf_counter() - t_pdf) * 1000.0
                stage_latencies["pdf_generation_section63_bsa"].append(pdf_ms)

                run_count += 1

            await db.commit()

    total_wall_time = time.perf_counter() - total_start
    throughput_eps = round(run_count / total_wall_time, 2)

    def stats_for(lst: List[float]) -> Dict[str, float]:
        if not lst:
            return {"mean_ms": 0.0, "p95_ms": 0.0, "min_ms": 0.0, "max_ms": 0.0}
        s = sorted(lst)
        p95_idx = int(len(s) * 0.95)
        return {
            "mean_ms": round(sum(s) / len(s), 2),
            "p95_ms": round(s[min(p95_idx, len(s) - 1)], 2),
            "min_ms": round(s[0], 2),
            "max_ms": round(s[-1], 2),
        }

    report = {
        "benchmark_metadata": {
            "sih_problem_id": "26106",
            "statutory_mandate": "Section 63 Bharatiya Sakshya Adhiniyam, 2023",
            "git_commit": get_git_commit(),
            "execution_timestamp": datetime.now(timezone.utc).isoformat(),
            "total_samples_evaluated": run_count,
            "unique_test_corpus_files": len(eml_files),
            "iterations": iterations,
            "total_wall_time_seconds": round(total_wall_time, 3),
            "throughput_emails_per_second": throughput_eps,
        },
        "stage_latency_breakdown_ms": {
            k: stats_for(v) for k, v in stage_latencies.items()
        },
    }

    EVIDENCE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(EVIDENCE_FILE, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    logger.info("Benchmark complete: %d runs in %.2fs (%.2f emails/sec). Results saved to %s",
                run_count, total_wall_time, throughput_eps, EVIDENCE_FILE)
    return report


if __name__ == "__main__":
    report_data = asyncio.run(run_benchmark(iterations=3))
    print("\n" + "=" * 85)
    print("   AICTE CYBER FORENSICS PLATFORM - END-TO-END PIPELINE PERFORMANCE BENCHMARK")
    print("=" * 85)
    print(f"Throughput: {report_data['benchmark_metadata']['throughput_emails_per_second']} emails/second")
    print(f"Total Evaluations: {report_data['benchmark_metadata']['total_samples_evaluated']} emails")
    print(f"Wall Time: {report_data['benchmark_metadata']['total_wall_time_seconds']} seconds")
    print("-" * 85)
    print(f"  {'Forensic Stage':<36} | {'Mean (ms)':<10} | {'P95 (ms)':<10} | {'Min (ms)':<10} | {'Max (ms)':<10}")
    print("-" * 85)
    for stage, metrics in report_data["stage_latency_breakdown_ms"].items():
        print(f"  {stage:<36} | {metrics['mean_ms']:>9.2f}  | {metrics['p95_ms']:>9.2f}  | {metrics['min_ms']:>9.2f}  | {metrics['max_ms']:>9.2f}")
    print("=" * 85)
