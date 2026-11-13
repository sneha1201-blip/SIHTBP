"""Forensic Analysis and Evidence Ingestion API Endpoints.

Provides endpoints for email ingestion (EML / MSG / raw RFC 822), automated forensic pipeline
execution (Reverse Hop-Traversal, SPF/DKIM/DMARC, VIP spoofing, IOC extraction, BEC NLP),
background job processing, hash-chained audit verification, and GeoJSON topological routing exports.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any, AsyncGenerator, Dict, Optional

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
    status,
)
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.app.core.rate_limiter import rate_limit_guard
from backend.app.core.security import require_analyst, require_any_authenticated, require_roles
from backend.app.core.upload_validator import stream_and_validate_upload, validate_email_bytes
from backend.app.database.audit_service import record_chained_audit_log, verify_audit_log_chain
from backend.app.database.models import (
    CampaignEmail,
    Email,
    HeaderHop,
    User,
    UserRole,
)
from backend.app.database.session import get_db
from backend.app.database.vault import read_raw_evidence
from backend.app.forensics.job_queue import (
    JobStatus,
    execute_forensic_pipeline,
    job_manager,
    run_background_job,
)

router = APIRouter()


@router.post("/analyze")
async def analyze_email_evidence(
    request: Request,
    file: Optional[UploadFile] = File(None),
    raw_headers: Optional[str] = Form(None),
    sync: bool = Query(False, description="Execute synchronously and return completed dossier immediately"),
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
    _rate_limit: None = Depends(rate_limit_guard),
) -> Any:
    """Ingest an email artifact (.eml / .msg / raw text), stream-validating payload cap and format,
    and process through the forensic pipeline (async job by default, synchronous if sync=true).
    """
    raw_bytes: bytes = b""
    file_name = "evidence.eml"

    if file:
        raw_bytes, file_name = await stream_and_validate_upload(file)
    elif raw_headers:
        raw_bytes = raw_headers.encode("utf-8")
        file_name = "raw_headers_submission.eml"
        validate_email_bytes(raw_bytes, file_name)
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either a multipart email file (.eml/.msg) or raw_headers form field must be provided.",
        )

    if len(raw_bytes) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The uploaded evidence file or header stream is empty.",
        )

    actor = current_user.username

    # Synchronous processing (used by automated test suites or synchronous API clients)
    if sync:
        dossier = await execute_forensic_pipeline(
            raw_bytes=raw_bytes,
            file_name=file_name,
            actor=actor,
            db=db,
        )
        return JSONResponse(status_code=status.HTTP_201_CREATED, content=dossier)

    # Asynchronous background job queue
    job = await job_manager.create_job(file_name=file_name, actor=actor)
    asyncio.create_task(run_background_job(job.job_id, raw_bytes, file_name, actor))

    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content={
            "job_id": job.job_id,
            "status": job.status,
            "stage": job.stage,
            "progress_percent": job.progress_percent,
            "poll_url": f"/api/v1/forensics/jobs/{job.job_id}",
            "stream_url": f"/api/v1/forensics/jobs/{job.job_id}/stream",
        },
    )


@router.get("/jobs/{job_id}")
async def get_job_status(
    job_id: str,
    current_user: User = Depends(require_any_authenticated),
) -> Dict[str, Any]:
    """Poll status and progress of an asynchronous forensic ingestion job."""
    job = await job_manager.get_job(job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Forensic job with ID '{job_id}' not found.",
        )
    return job.to_dict()


@router.get("/jobs/{job_id}/stream")
async def stream_job_progress(
    job_id: str,
    current_user: User = Depends(require_any_authenticated),
) -> StreamingResponse:
    """Stream Server-Sent Events (SSE) reporting real-time job progress."""
    job = await job_manager.get_job(job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Forensic job with ID '{job_id}' not found.",
        )

    async def event_generator() -> AsyncGenerator[str, None]:
        while True:
            current_job = await job_manager.get_job(job_id)
            if not current_job:
                break
            payload = json.dumps(current_job.to_dict())
            yield f"data: {payload}\n\n"
            if current_job.status in (JobStatus.COMPLETED, JobStatus.FAILED):
                break
            await asyncio.sleep(0.3)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.get("/audit/verify-chain")
async def verify_audit_ledger_chain(
    current_user: User = Depends(require_any_authenticated),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Verify cryptographic integrity of the entire audit chain from genesis to head."""
    result = await verify_audit_log_chain(db)
    return result


@router.get("/evidence/{evidence_id}")
async def get_evidence_dossier(
    evidence_id: str,
    current_user: User = Depends(require_any_authenticated),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Retrieve the full forensic dossier by email UUID, recording analyst access in audit log."""
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
            selectinload(Email.campaign_associations).selectinload(CampaignEmail.campaign),
            selectinload(Email.audit_logs),
        )
        .where(Email.id == e_uuid)
    )
    result = await db.execute(stmt)
    email = result.scalar_one_or_none()

    if not email:
        raise HTTPException(status_code=404, detail=f"No forensic evidence found for ID: {evidence_id}")

    # Record evidence access in chained audit log
    await record_chained_audit_log(
        db=db,
        action="EVIDENCE_ACCESSED",
        actor=current_user.username,
        evidence_sha256=email.sha256_hash,
        email_id=email.id,
        details={"analyst_role": current_user.role},
    )
    await db.commit()

    return {
        "email": email.to_dict(),
        "forensic_analysis": email.forensic_analysis.to_dict() if email.forensic_analysis else None,
        "header_hops": [h.to_dict() for h in email.header_hops],
        "threat_indicators": [i.to_dict() for i in email.threat_indicators],
        "campaigns": [
            {
                "campaign_id": str(assoc.campaign_id),
                "name": assoc.campaign.name if assoc.campaign else "Unknown",
                "cluster_type": assoc.campaign.cluster_type if assoc.campaign else None,
                "similarity_score": assoc.similarity_score,
                "matched_criteria": assoc.matched_criteria,
            }
            for assoc in email.campaign_associations
        ],
        "audit_logs": [log.to_dict() for log in email.audit_logs],
    }


@router.get("/evidence/{evidence_id}/raw")
async def get_raw_vault_evidence(
    evidence_id: str,
    current_user: User = Depends(require_any_authenticated),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Read raw email bytes directly from the cryptographic vault with SHA-256 integrity verification."""
    try:
        e_uuid = uuid.UUID(evidence_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid evidence UUID format.")

    stmt = select(Email).where(Email.id == e_uuid)
    result = await db.execute(stmt)
    email = result.scalar_one_or_none()

    if not email:
        raise HTTPException(status_code=404, detail=f"No forensic evidence found for ID: {evidence_id}")

    raw_bytes = read_raw_evidence(email.sha256_hash)

    # Record vault read event in chained audit log
    await record_chained_audit_log(
        db=db,
        action="VAULT_RAW_READ",
        actor=current_user.username,
        evidence_sha256=email.sha256_hash,
        email_id=email.id,
        details={"file_name": email.file_name, "analyst_role": current_user.role},
    )
    await db.commit()

    return Response(
        content=raw_bytes,
        media_type="message/rfc822",
        headers={"Content-Disposition": f'attachment; filename="{email.file_name}"'},
    )


@router.get("/evidence/{evidence_id}/hops")
async def get_evidence_hops_geojson(
    evidence_id: str,
    current_user: User = Depends(require_any_authenticated),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Return transit hops formatted as a GeoJSON FeatureCollection for frontend map rendering."""
    try:
        e_uuid = uuid.UUID(evidence_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid evidence UUID format.")

    stmt = select(HeaderHop).where(HeaderHop.email_id == e_uuid).order_by(HeaderHop.hop_order.asc())
    result = await db.execute(stmt)
    hops = result.scalars().all()

    if not hops:
        raise HTTPException(status_code=404, detail="No hop routes found for this evidence ID.")

    features = []
    line_coordinates = []

    for h in hops:
        if h.geo_lat is not None and h.geo_lon is not None:
            coord = [h.geo_lon, h.geo_lat]
            line_coordinates.append(coord)
            features.append(
                {
                    "type": "Feature",
                    "geometry": {
                        "type": "Point",
                        "coordinates": coord,
                    },
                    "properties": {
                        "hop_order": h.hop_order,
                        "ip": h.hop_ip,
                        "city": h.geo_city,
                        "country": h.geo_country,
                        "asn": h.asn_number,
                        "asn_org": h.asn_org,
                        "node_type": h.node_type,
                        "is_tor": h.is_tor,
                        "is_vpn": h.is_vpn,
                        "delay_seconds": h.delay_seconds,
                    },
                }
            )

    if len(line_coordinates) >= 2:
        features.insert(
            0,
            {
                "type": "Feature",
                "geometry": {
                    "type": "LineString",
                    "coordinates": line_coordinates,
                },
                "properties": {
                    "route_type": "MTA_TRANSIT_TRAJECTORY",
                    "total_hops": len(hops),
                },
            },
        )

    return {
        "type": "FeatureCollection",
        "evidence_id": evidence_id,
        "features": features,
    }


@router.post("/vault/sweep")
async def sweep_vault_integrity(
    current_user: User = Depends(require_roles([UserRole.ADMIN, UserRole.AUDITOR])),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Perform a comprehensive cryptographic integrity sweep across all vault files (Admin/Auditor)."""
    from datetime import datetime, timezone

    from backend.app.database.vault import get_vault_dir, verify_evidence_integrity

    vault_dir = get_vault_dir()
    raw_files = list(vault_dir.glob("*.raw"))

    total_files = len(raw_files)
    verified = 0
    corrupted = 0
    details = []

    for rf in raw_files:
        sha256 = rf.stem
        check = verify_evidence_integrity(sha256, vault_dir=vault_dir)
        if check.get("intact"):
            verified += 1
            details.append({"sha256": sha256, "status": "VERIFIED", "size": check.get("size")})
        else:
            corrupted += 1
            details.append({"sha256": sha256, "status": "CORRUPTED", "error": check.get("error")})
            await record_chained_audit_log(
                db=db,
                action="INTEGRITY_FAILURE",
                actor=current_user.username,
                evidence_sha256=sha256,
                details={"sweep_error": check.get("error"), "path": str(rf)},
            )

    await db.commit()

    return {
        "sweep_timestamp": datetime.now(timezone.utc).isoformat(),
        "total_files": total_files,
        "verified": verified,
        "corrupted": corrupted,
        "integrity_rate_pct": round((verified / max(1, total_files)) * 100.0, 2),
        "details": details,
    }
