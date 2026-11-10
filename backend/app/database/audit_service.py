"""Cryptographic Hash-Chained Audit Ledger Service.

Implements immutable, blockchain-style hash chaining for EvidenceAuditLog entries,
guaranteeing Section 63 BSA 2023 legal integrity across all evidence operations.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.database.models import EvidenceAuditLog
from backend.app.database.vault import (
    canonicalize_audit_payload,
    generate_hmac_signature,
    verify_hmac_signature,
)

logger = logging.getLogger(__name__)

GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"


def compute_entry_hash(hmac_sig: str, record_id: str) -> str:
    """Compute the linking hash of an audit entry for the forward chain."""
    return hashlib.sha256(f"{hmac_sig}:{record_id}".encode("utf-8")).hexdigest()


async def record_chained_audit_log(
    db: AsyncSession,
    action: str,
    actor: str,
    evidence_sha256: str,
    email_id: Optional[uuid.UUID] = None,
    details: Optional[Dict[str, Any]] = None,
    integrity_check: bool = True,
    recorded_at: Optional[datetime] = None,
) -> EvidenceAuditLog:
    """Create and append a tamper-evident, hash-chained audit log entry."""
    now = recorded_at or datetime.now(timezone.utc)
    details_dict = details or {}

    # Query the most recent audit log entry to establish the chain link
    stmt = select(EvidenceAuditLog).order_by(EvidenceAuditLog.recorded_at.desc(), EvidenceAuditLog.id.desc()).limit(1)
    result = await db.execute(stmt)
    latest_entry = result.scalar_one_or_none()

    if latest_entry is None:
        prev_hash = GENESIS_HASH
    else:
        prev_hash = compute_entry_hash(latest_entry.hmac_signature, str(latest_entry.id))

    canonical_payload = canonicalize_audit_payload(
        actor=actor,
        action=action,
        evidence_sha256=evidence_sha256,
        recorded_at=now,
        details=details_dict,
        prev_hash=prev_hash,
    )
    hmac_sig = generate_hmac_signature(canonical_payload)

    audit_log = EvidenceAuditLog(
        id=uuid.uuid4(),
        email_id=email_id,
        action_performed=action,
        actor=actor,
        recorded_at=now,
        evidence_sha256=evidence_sha256,
        integrity_check=integrity_check,
        prev_hash=prev_hash,
        hmac_signature=hmac_sig,
        details=details_dict,
    )
    db.add(audit_log)
    return audit_log


async def verify_audit_log_chain(db: AsyncSession) -> Dict[str, Any]:
    """Verify cryptographic integrity of the entire audit chain from genesis to head.

    Returns:
        Dict[str, Any]: Verification outcome including valid flag, records count, and error details if broken.
    """
    stmt = select(EvidenceAuditLog).order_by(EvidenceAuditLog.recorded_at.asc(), EvidenceAuditLog.id.asc())
    result = await db.execute(stmt)
    records = result.scalars().all()

    if not records:
        return {
            "valid": True,
            "total_records": 0,
            "chain_head": GENESIS_HASH,
            "status": "EMPTY_LEDGER",
        }

    expected_prev_hash = GENESIS_HASH

    for index, record in enumerate(records):
        # 1. Verify prev_hash link
        # For legacy or seeded records where prev_hash might be None, establish genesis on first record
        if index == 0 and (record.prev_hash is None or record.prev_hash == GENESIS_HASH):
            expected_prev_hash = record.prev_hash or GENESIS_HASH

        if record.prev_hash is not None and record.prev_hash != expected_prev_hash:
            return {
                "valid": False,
                "tampered_at_index": index,
                "tampered_at_id": str(record.id),
                "action": record.action_performed,
                "actor": record.actor,
                "error": f"Chain link broken at record {index} (ID: {record.id}). Expected prev_hash {expected_prev_hash}, got {record.prev_hash}.",
            }

        # 2. Verify HMAC signature
        canonical_payload = canonicalize_audit_payload(
            actor=record.actor,
            action=record.action_performed,
            evidence_sha256=record.evidence_sha256,
            recorded_at=record.recorded_at,
            details=record.details,
            prev_hash=record.prev_hash,
        )
        if not verify_hmac_signature(canonical_payload, record.hmac_signature):
            # Check legacy format (without prev_hash in canonical payload)
            legacy_payload = canonicalize_audit_payload(
                actor=record.actor,
                action=record.action_performed,
                evidence_sha256=record.evidence_sha256,
                recorded_at=record.recorded_at,
                details=record.details,
            )
            if not verify_hmac_signature(legacy_payload, record.hmac_signature):
                return {
                    "valid": False,
                    "tampered_at_index": index,
                    "tampered_at_id": str(record.id),
                    "action": record.action_performed,
                    "actor": record.actor,
                    "error": f"HMAC signature tampering detected at record {index} (ID: {record.id}). Data has been modified.",
                }

        # Advance expected hash for next link
        expected_prev_hash = compute_entry_hash(record.hmac_signature, str(record.id))

    return {
        "valid": True,
        "total_records": len(records),
        "chain_head": expected_prev_hash,
        "status": "CHAIN_INTEGRITY_VERIFIED",
    }
