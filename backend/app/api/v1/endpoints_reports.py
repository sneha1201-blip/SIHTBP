"""Court-Admissible PDF Report Generation Endpoints.

Streams cryptographic forensic dossiers formatted for Section 63 BSA, 2023 / Section 65B IEA.
"""

from __future__ import annotations

import uuid
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.app.database.models import Email
from backend.app.database.session import get_db
from backend.app.reporting.pdf_generator import generate_forensic_pdf

router = APIRouter()


@router.get("/{evidence_id}/report")
async def stream_forensic_pdf_report(
    evidence_id: str,
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

    email_dict = email.to_dict()
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

