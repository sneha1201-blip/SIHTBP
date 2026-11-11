"""Court-Admissible PDF Report Generation Endpoints.

Streams cryptographic forensic dossiers formatted for Section 63 BSA 2023.
"""

from __future__ import annotations

import hashlib
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.app.core.security import require_any_authenticated
from backend.app.database.audit_service import record_chained_audit_log
from backend.app.database.models import Email, User
from backend.app.database.session import get_db
from backend.app.database.vault import generate_hmac_signature, get_vault_dir, verify_hmac_signature
from backend.app.reporting.pdf_generator import generate_forensic_pdf

router = APIRouter()


@router.get("/{evidence_id}/report")
async def stream_forensic_pdf_report(
    evidence_id: str,
    current_user: User = Depends(require_any_authenticated),
    db: AsyncSession = Depends(get_db),
):
    """Stream a Section 63 BSA 2023 certified forensic PDF dossier for the specified evidence UUID."""
    try:
        e_uuid = uuid.UUID(evidence_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid evidence UUID format.")

    stmt = (
        select(Email)
        .options(
            selectinload(Email.header_hops),
            selectinload(Email.forensic_analysis),
            selectinload(Email.threat_indicators),
            selectinload(Email.audit_logs),
        )
        .where(Email.id == e_uuid)
    )
    result = await db.execute(stmt)
    email = result.scalar_one_or_none()

    if not email:
        raise HTTPException(status_code=404, detail=f"Evidence not found for UUID: {evidence_id}")

    # 1. Cryptographic Vault Integrity Verification before Report Generation
    vault_path = Path(email.raw_storage_path) if email.raw_storage_path else get_vault_dir() / f"{email.sha256_hash}.raw"
    if not vault_path.exists():
        vault_path = get_vault_dir() / f"{email.sha256_hash}.raw"

    if not vault_path.exists():
        await record_chained_audit_log(
            db=db,
            action="INTEGRITY_FAILURE",
            actor=current_user.username,
            evidence_sha256=email.sha256_hash,
            email_id=email.id,
            details={"error": f"Vault evidence artifact missing on disk: {vault_path}"},
            integrity_check=False,
        )
        await db.commit()
        raise HTTPException(
            status_code=409,
            detail="Cryptographic integrity verification failed: evidence file missing from vault.",
        )

    try:
        raw_bytes = vault_path.read_bytes()
    except Exception as exc:
        await record_chained_audit_log(
            db=db,
            action="INTEGRITY_FAILURE",
            actor=current_user.username,
            evidence_sha256=email.sha256_hash,
            email_id=email.id,
            details={"error": f"Failed to read raw vault evidence: {exc}"},
            integrity_check=False,
        )
        await db.commit()
        raise HTTPException(
            status_code=409,
            detail=f"Cryptographic integrity verification failed: unable to read vault evidence ({exc}).",
        )

    computed_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    computed_sha512 = hashlib.sha512(raw_bytes).hexdigest()

    # Verify SHA-256 matches database ground truth
    if computed_sha256.lower() != email.sha256_hash.lower():
        await record_chained_audit_log(
            db=db,
            action="INTEGRITY_FAILURE",
            actor=current_user.username,
            evidence_sha256=email.sha256_hash,
            email_id=email.id,
            details={
                "error": "Vault file SHA-256 mismatch: physical corruption or unauthorized tampering detected",
                "expected_sha256": email.sha256_hash,
                "computed_sha256": computed_sha256,
            },
            integrity_check=False,
        )
        await db.commit()
        raise HTTPException(
            status_code=409,
            detail=(
                f"Cryptographic integrity violation! Stored vault evidence hash ({computed_sha256}) "
                f"does not match registered evidence hash ({email.sha256_hash})."
            ),
        )

    # Verify HMAC Seal
    vault_hmac_seal = generate_hmac_signature(raw_bytes)
    if not verify_hmac_signature(raw_bytes, vault_hmac_seal):
        await record_chained_audit_log(
            db=db,
            action="INTEGRITY_FAILURE",
            actor=current_user.username,
            evidence_sha256=email.sha256_hash,
            email_id=email.id,
            details={"error": "Vault HMAC cryptographic seal verification failed"},
            integrity_check=False,
        )
        await db.commit()
        raise HTTPException(
            status_code=409,
            detail="Cryptographic integrity violation: vault HMAC seal validation failed.",
        )

    # Record report export in chained audit log
    await record_chained_audit_log(
        db=db,
        action="REPORT_EXPORTED",
        actor=current_user.username,
        evidence_sha256=email.sha256_hash,
        email_id=email.id,
        details={
            "format": "PDF",
            "statutory_act": "Section 63 BSA 2023",
            "analyst_role": current_user.role,
            "verified_sha256": computed_sha256,
            "verified_sha512": computed_sha512,
        },
    )
    await db.commit()

    email_dict = email.to_dict()
    email_dict["sha512_hash"] = computed_sha512
    email_dict["hmac_signature"] = vault_hmac_seal
    analysis_dict = email.forensic_analysis.to_dict() if email.forensic_analysis else {}
    hops_list = [h.to_dict() for h in email.header_hops]
    iocs_list = [i.to_dict() for i in email.threat_indicators]
    audit_list = [a.to_dict() for a in email.audit_logs]

    pdf_buffer = generate_forensic_pdf(
        email_data=email_dict,
        hops=hops_list,
        analysis=analysis_dict,
        iocs=iocs_list,
        audit_logs=audit_list,
        examiner_name=current_user.username,
        examiner_designation=f"Forensic {current_user.role}, AICTE Cyber Security Cell",
    )

    filename = f"Forensic_Dossier_BSA63_{email.sha256_hash[:12]}.pdf"
    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Access-Control-Expose-Headers": "Content-Disposition, X-Evidence-SHA256, X-Statutory-Authority",
            "X-Evidence-SHA256": email.sha256_hash,
            "X-Statutory-Authority": "Section 63 Bharatiya Sakshya Adhiniyam, 2023",
        },
    )

