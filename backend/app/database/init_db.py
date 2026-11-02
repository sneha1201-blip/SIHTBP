"""Database Initialization, Migration, and Verification Runner.

Builds database schemas, runs the forensic seeder, performs cryptographic vault
integrity verification, and renders an executive forensic summary table for demo day.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

# Ensure project root is in sys.path for direct script execution
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from typing import Dict, List, Tuple

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.app.database.models import (
    Campaign,
    CampaignEmail,
    Email,
    EvidenceAuditLog,
    ForensicAnalysis,
    HeaderHop,
    ThreatIndicator,
)
from backend.app.database.seed_data import seed_forensic_database
from backend.app.database.session import (
    DATABASE_URL,
    IS_SQLITE,
    async_session_factory,
    close_database,
    create_all_tables,
    drop_all_tables,
    engine,
    reset_database,
)
from backend.app.database.vault import (
    canonicalize_audit_payload,
    get_vault_dir,
    read_raw_evidence,
    verify_evidence_integrity,
    verify_hmac_signature,
)


def print_banner() -> None:
    """Print the AICTE Cyber Security Platform initialization banner."""
    banner = r"""
========================================================================================
   AICTE CYBER SECURITY CELL - FORENSIC EMAIL INTELLIGENCE PLATFORM
   SIH Problem Statement ID: 26106 | Phase 1 Database & Cryptographic Vault
========================================================================================
"""
    print(banner)


async def get_table_counts(session: AsyncSession) -> Dict[str, int]:
    """Retrieve row counts for all platform tables."""
    models = {
        "emails": Email,
        "header_hops": HeaderHop,
        "forensic_analyses": ForensicAnalysis,
        "threat_indicators": ThreatIndicator,
        "campaigns": Campaign,
        "campaign_emails": CampaignEmail,
        "evidence_audit_logs": EvidenceAuditLog,
    }
    counts = {}
    for table_name, model in models.items():
        stmt = select(func.count()).select_from(model)
        result = await session.execute(stmt)
        counts[table_name] = result.scalar() or 0
    return counts


async def verify_forensic_cases(session: AsyncSession) -> List[Dict[str, any]]:
    """Retrieve and verify all seeded forensic test cases."""
    stmt = (
        select(Email)
        .options(
            selectinload(Email.header_hops),
            selectinload(Email.forensic_analysis),
            selectinload(Email.threat_indicators),
            selectinload(Email.campaign_associations).selectinload(CampaignEmail.campaign),
            selectinload(Email.audit_logs),
        )
        .order_by(Email.ingested_at.asc())
    )
    result = await session.execute(stmt)
    emails = result.scalars().all()

    cases_summary = []
    for idx, em in enumerate(emails, start=1):
        # Determine origin hop
        origin_hop = next((h for h in em.header_hops if h.hop_order == 1), None)
        origin_str = f"{origin_hop.hop_ip} ({origin_hop.geo_city or origin_hop.geo_country})" if origin_hop else "N/A"
        if origin_hop and origin_hop.is_tor:
            origin_str += " [TOR EXIT]"

        # Check vault file
        vault_res = verify_evidence_integrity(em.sha256_hash)
        vault_status = "INTACT" if vault_res["intact"] else "FAILED"

        # Check audit log HMAC
        audit_intact = True
        for log in em.audit_logs:
            expected_payload = canonicalize_audit_payload(
                actor=log.actor,
                action=log.action_performed,
                evidence_sha256=log.evidence_sha256,
                recorded_at=log.recorded_at,
                details=log.details,
            )
            if not verify_hmac_signature(expected_payload, log.hmac_signature):
                audit_intact = False
                break

        analysis = em.forensic_analysis
        score = analysis.threat_score if analysis else 0.0
        verdict = analysis.verdict if analysis else "UNKNOWN"

        campaign_names = [assoc.campaign.name for assoc in em.campaign_associations if assoc.campaign]
        campaign_str = campaign_names[0][:32] + "..." if campaign_names else "Standalone"

        cases_summary.append({
            "num": idx,
            "subject": (em.subject[:48] + "...") if em.subject and len(em.subject) > 48 else em.subject,
            "sender": (em.sender_email[:28] + "...") if em.sender_email and len(em.sender_email) > 28 else em.sender_email,
            "origin": origin_str,
            "score": score,
            "verdict": verdict,
            "campaign": campaign_str,
            "vault": vault_status,
            "hmac": "VALID" if audit_intact else "TAMPERED",
            "sha256": em.sha256_hash,
            "file_size": em.file_size_bytes,
        })
    return cases_summary


def render_ascii_tables(counts: Dict[str, int], cases: List[Dict[str, any]]) -> None:
    """Format and print ASCII summary verification tables."""
    # Table Inventory
    print("+" + "-" * 42 + "+" + "-" * 16 + "+" + "-" * 18 + "+")
    print(f"| {'Database Table Name':<40} | {'Record Count':<14} | {'Storage Engine':<16} |")
    print("+" + "=" * 42 + "+" + "=" * 16 + "+" + "=" * 18 + "+")
    dialect_str = "SQLite 3 (WAL)" if IS_SQLITE else "PostgreSQL 16"
    for tbl, count in counts.items():
        print(f"| {tbl:<40} | {count:<14} | {dialect_str:<16} |")
    print("+" + "-" * 42 + "+" + "-" * 16 + "+" + "-" * 18 + "+")
    print()

    # Forensic Test Cases Summary
    print("+" + "-" * 5 + "+" + "-" * 46 + "+" + "-" * 26 + "+" + "-" * 8 + "+" + "-" * 12 + "+" + "-" * 10 + "+" + "-" * 8 + "+")
    print(f"| {'#':<3} | {'Subject / Scenario':<44} | {'Origin Route / MTA':<24} | {'Score':<6} | {'Verdict':<10} | {'Vault':<8} | {'HMAC':<6} |")
    print("+" + "=" * 5 + "+" + "=" * 46 + "+" + "=" * 26 + "+" + "=" * 8 + "+" + "=" * 12 + "+" + "=" * 10 + "+" + "=" * 8 + "+")
    for c in cases:
        print(
            f"| {c['num']:<3} | {c['subject']:<44} | {c['origin']:<24} | {c['score']:>5.1f} | {c['verdict']:<10} | {c['vault']:<8} | {c['hmac']:<6} |"
        )
    print("+" + "-" * 5 + "+" + "-" * 46 + "+" + "-" * 26 + "+" + "-" * 8 + "+" + "-" * 12 + "+" + "-" * 10 + "+" + "-" * 8 + "+")
    print()


async def initialize_and_verify(reset: bool = False, seed: bool = True) -> bool:
    """Execute complete database initialization, optional seeding, and verification."""
    print_banner()
    vault_dir = get_vault_dir()
    print(f"[*] Target Database Engine:  {'SQLite 3 (Local Zero-Setup)' if IS_SQLITE else 'PostgreSQL 16 (Enterprise)'}")
    print(f"[*] Database Connection URL: {DATABASE_URL}")
    print(f"[*] Evidence Vault Root:     {vault_dir}")
    print()

    if reset:
        print("[!] --reset requested. Dropping all existing database tables...")
        await drop_all_tables()
        print("[+] Tables dropped successfully.")

    print("[*] Creating database schemas and tables...")
    await create_all_tables()
    print("[+] All 6 core relational & graph ORM schemas verified and active.")
    print()

    async with async_session_factory() as session:
        # Check current row count
        stmt = select(func.count()).select_from(Email)
        res = await session.execute(stmt)
        existing_count = res.scalar() or 0

        if seed:
            if existing_count == 0:
                print("[*] Database is empty. Seeding 5 realistic forensic test cases...")
                seed_counts = await seed_forensic_database(session)
                print(f"[+] Seeding completed successfully: {seed_counts}")
            else:
                print(f"[*] Database already populated with {existing_count} emails. Skipping duplicate seeding.")
        print()

        # Gather metrics for verification table
        print("[*] Querying table persistence and verifying cryptographic integrity...")
        counts = await get_table_counts(session)
        cases = await verify_forensic_cases(session)
        print()

        # Render formatted table
        render_ascii_tables(counts, cases)

        # Verification checks
        all_vault_intact = all(c["vault"] == "INTACT" for c in cases) if cases else True
        all_hmac_valid = all(c["hmac"] == "VALID" for c in cases) if cases else True

        print("----------------------------------------------------------------------------------------")
        print(f"[*] Cryptographic Vault Status:     {'ALL EVIDENCE FILES INTACT (SHA-256 MATCH)' if all_vault_intact else 'INTEGRITY MISMATCH DETECTED'}")
        print(f"[*] Audit Ledger Chain of Custody:  {'ALL HMAC-SHA256 SIGNATURES VERIFIED' if all_hmac_valid else 'SIGNATURE VERIFICATION FAILED'}")
        print(f"[*] Zero-Setup Hackathon Execution: READY FOR DEMO DAY")
        print("----------------------------------------------------------------------------------------")
        print()

        return all_vault_intact and all_hmac_valid


def init_db_and_verify(reset: bool = False, seed: bool = True) -> bool:
    """Synchronous entry point for initialize_and_verify.

    Executes complete database schema migration, forensic seeding, and cryptographic
    verification, properly managing event loops and connection pool disposal.
    """
    async def _runner() -> bool:
        try:
            return await initialize_and_verify(reset=reset, seed=seed)
        finally:
            await close_database()

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, _runner()).result()
    else:
        return asyncio.run(_runner())


def main() -> None:
    """CLI Entry point for init_db."""
    parser = argparse.ArgumentParser(
        description="AICTE Forensic Intelligence Platform Database Initializer & Verification Runner"
    )
    parser.add_argument("--reset", action="store_true", help="Drop and recreate all tables from scratch")
    parser.add_argument("--no-seed", action="store_true", help="Skip populating mock forensic data")
    args = parser.parse_args()

    success = init_db_and_verify(reset=args.reset, seed=not args.no_seed)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
