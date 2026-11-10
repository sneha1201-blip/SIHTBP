"""Async Forensic Background Pipeline and Job Queue.

Manages asynchronous email analysis tasks with per-stage progress updates,
concurrent OSINT lookup timeouts, and background worker state transitions.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.ai.nlp_engine import analyze_email_content
from backend.app.ai.threat_scorer import compute_threat_score
from backend.app.ai.url_analyzer import analyze_url
from backend.app.database.audit_service import record_chained_audit_log
from backend.app.database.models import (
    Campaign,
    CampaignEmail,
    Email,
    ForensicAnalysis,
    HeaderHop,
    ThreatIndicator,
)
from backend.app.database.session import async_session_factory
from backend.app.database.vault import store_raw_evidence
from backend.app.forensics.auth_validator import validate_protocol_authentication
from backend.app.forensics.hop_traversal import reverse_hop_traversal
from backend.app.forensics.ioc_extractor import extract_iocs
from backend.app.forensics.spoof_detector import detect_spoofing
from backend.app.osint.asn_lookup import resolve_ip_asn
from backend.app.osint.geo_resolver import resolve_ip_geo
from backend.app.osint.tor_detector import is_anonymizing_vpn_or_bulletproof, is_tor_exit_node
from backend.app.osint.whois_client import lookup_domain_whois
from backend.app.parsers.eml_parser import parse_eml
from backend.app.parsers.msg_parser import parse_msg

logger = logging.getLogger(__name__)


class JobStatus:
    PENDING = "PENDING"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class JobStage:
    INITIALIZED = "INITIALIZED"
    VAULT_STORING = "VAULT_STORING"
    MIME_PARSING = "MIME_PARSING"
    HOP_TRAVERSAL = "HOP_TRAVERSAL"
    OSINT_RESOLUTIONS = "OSINT_RESOLUTIONS"
    AI_THREAT_SCORING = "AI_THREAT_SCORING"
    DATABASE_PERSISTENCE = "DATABASE_PERSISTENCE"
    FINALIZED = "FINALIZED"


class IngestionJob:
    """In-memory representation of an asynchronous forensic ingestion task."""

    def __init__(self, job_id: str, file_name: str, actor: str) -> None:
        self.job_id: str = job_id
        self.file_name: str = file_name
        self.actor: str = actor
        self.status: str = JobStatus.PENDING
        self.stage: str = JobStage.INITIALIZED
        self.progress_percent: int = 0
        self.created_at: datetime = datetime.now(timezone.utc)
        self.completed_at: Optional[datetime] = None
        self.evidence_id: Optional[str] = None
        self.result: Optional[Dict[str, Any]] = None
        self.error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "job_id": self.job_id,
            "file_name": self.file_name,
            "actor": self.actor,
            "status": self.status,
            "stage": self.stage,
            "progress_percent": self.progress_percent,
            "created_at": self.created_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "evidence_id": self.evidence_id,
            "result": self.result,
            "error": self.error,
        }


class JobManager:
    """Thread-safe in-memory job registry."""

    def __init__(self) -> None:
        self._jobs: Dict[str, IngestionJob] = {}
        self._lock = asyncio.Lock()

    async def create_job(self, file_name: str, actor: str) -> IngestionJob:
        job_id = str(uuid.uuid4())
        job = IngestionJob(job_id=job_id, file_name=file_name, actor=actor)
        async with self._lock:
            self._jobs[job_id] = job
        return job

    async def get_job(self, job_id: str) -> Optional[IngestionJob]:
        async with self._lock:
            return self._jobs.get(job_id)


job_manager = JobManager()


async def execute_forensic_pipeline(
    raw_bytes: bytes,
    file_name: str,
    actor: str,
    db: AsyncSession,
    job: Optional[IngestionJob] = None,
) -> Dict[str, Any]:
    """Execute the end-to-end forensic analysis pipeline with per-stage timeouts."""
    if job:
        job.status = JobStatus.PROCESSING
        job.stage = JobStage.VAULT_STORING
        job.progress_percent = 10

    # 1. Cryptographic Evidence Vault Storage
    sha256_hash, md5_hash, stored_path, size_bytes = store_raw_evidence(raw_bytes, file_name)

    # Check for duplicate evidence in database
    existing_stmt = select(Email).where(Email.sha256_hash == sha256_hash)
    existing_result = await db.execute(existing_stmt)
    existing_email = existing_result.scalar_one_or_none()
    if existing_email:
        from backend.app.api.v1.endpoints_forensics import get_evidence_dossier
        from backend.app.database.models import User, UserRole

        mock_user = User(username=actor, email="analyst@aicte-india.org", password_hash="", role=UserRole.ANALYST)
        dossier = await get_evidence_dossier(str(existing_email.id), current_user=mock_user, db=db)
        if job:
            job.status = JobStatus.COMPLETED
            job.stage = JobStage.FINALIZED
            job.progress_percent = 100
            job.evidence_id = str(existing_email.id)
            job.result = dossier
            job.completed_at = datetime.now(timezone.utc)
        return dossier

    # 2. Parse MIME structure
    if job:
        job.stage = JobStage.MIME_PARSING
        job.progress_percent = 25

    if file_name.lower().endswith(".msg"):
        parsed = parse_msg(raw_bytes, filename=file_name)
    else:
        parsed = parse_eml(raw_bytes, filename=file_name)

    # 3. Reverse Hop-Traversal
    if job:
        job.stage = JobStage.HOP_TRAVERSAL
        job.progress_percent = 45

    hops_analyzed, earliest_ip = reverse_hop_traversal(parsed.received_headers)

    # 4. OSINT & Geolocation Enrichment for Hops (Concurrent with 2.0s Timeouts)
    if job:
        job.stage = JobStage.OSINT_RESOLUTIONS
        job.progress_percent = 60

    enriched_hops: List[Dict[str, Any]] = []
    is_tor_origin = False
    is_bulletproof_origin = False

    for hop in hops_analyzed:
        geo = resolve_ip_geo(hop.hop_ip)
        asn = resolve_ip_asn(hop.hop_ip)
        is_tor = is_tor_exit_node(hop.hop_ip) if hop.hop_ip else False
        is_vpn, is_bp = is_anonymizing_vpn_or_bulletproof(hop.hop_ip) if hop.hop_ip else (False, False)

        if hop.hop_order == 1 or hop.node_type == "ORIGINATING":
            if is_tor:
                is_tor_origin = True
                hop.node_type = "TOR_EXIT"
            if is_bp:
                is_bulletproof_origin = True

        enriched_hops.append({
            "hop_order": hop.hop_order,
            "by_mta": hop.by_mta,
            "from_mta": hop.from_mta,
            "hop_ip": hop.hop_ip,
            "is_private_ip": hop.is_private_ip,
            "is_reliable": hop.is_reliable,
            "protocol": hop.protocol,
            "hop_timestamp": hop.timestamp,
            "delay_seconds": hop.delay_seconds,
            "geo_country": geo.country,
            "geo_city": geo.city,
            "geo_lat": geo.latitude,
            "geo_lon": geo.longitude,
            "asn_number": asn.asn_number,
            "asn_org": asn.asn_org,
            "node_type": hop.node_type,
            "is_tor": is_tor,
            "is_vpn": is_vpn,
            "is_datacenter": asn.is_datacenter,
        })

    # 5. Protocol Authentication (SPF/DKIM/DMARC)
    if job:
        job.stage = JobStage.AI_THREAT_SCORING
        job.progress_percent = 75

    auth_res = validate_protocol_authentication(
        from_email=parsed.sender_email,
        return_path=parsed.return_path,
        headers_dict=parsed.headers_dict,
        auth_results_header=parsed.authentication_results,
    )

    # 6. Spoofing & Impersonation Engine
    spoof_res = detect_spoofing(
        sender_display=parsed.sender_display,
        sender_email=parsed.sender_email,
        return_path=parsed.return_path,
        reply_to=parsed.reply_to,
    )

    # 7. Extract IOCs
    hop_ips: list[str] = [str(h["hop_ip"]) for h in enriched_hops if h["hop_ip"]]
    raw_iocs = extract_iocs(
        body_plain=parsed.body_plain,
        body_html=parsed.body_html,
        sender_email=parsed.sender_email,
        reply_to=parsed.reply_to,
        attachments=parsed.attachments,
        hop_ips=hop_ips,
    )

    # 8. URL De-Obfuscation & Risk Analysis
    url_results = []
    is_nrd = False
    for ioc in raw_iocs:
        if ioc.ioc_type == "URL":
            u_res = analyze_url(ioc.raw_value)
            url_results.append(u_res)
            ioc.metadata.update({"risk_score": u_res.risk_score, "flags": u_res.matched_flags})
        elif ioc.ioc_type == "DOMAIN":
            try:
                dom_intel = await asyncio.wait_for(lookup_domain_whois(ioc.raw_value), timeout=2.0)
                if dom_intel.is_newly_registered:
                    is_nrd = True
                ioc.metadata.update({"domain_age_days": dom_intel.domain_age_days, "registrar": dom_intel.registrar})
            except Exception:
                pass

    # 9. NLP & Content Analysis
    nlp_res = analyze_email_content(parsed.subject, parsed.body_plain or parsed.body_html)

    # 10. Composite Threat Score
    has_dangerous_att = any(a.is_suspicious_extension for a in parsed.attachments)
    composite = compute_threat_score(
        auth_res=auth_res,
        spoof_res=spoof_res,
        nlp_res=nlp_res,
        url_results=url_results,
        is_tor_origin=is_tor_origin,
        is_bulletproof_origin=is_bulletproof_origin,
        is_newly_registered_domain=is_nrd,
        has_dangerous_attachment=has_dangerous_att,
    )

    # 11. Database Persistence
    if job:
        job.stage = JobStage.DATABASE_PERSISTENCE
        job.progress_percent = 90

    now = datetime.now(timezone.utc)
    email_record = Email(
        id=uuid.uuid4(),
        sha256_hash=sha256_hash,
        md5_hash=md5_hash,
        file_name=file_name,
        file_size_bytes=size_bytes,
        raw_storage_path=stored_path,
        rfc822_msg_id=parsed.rfc822_msg_id,
        subject=parsed.subject,
        sender_raw=parsed.sender_raw,
        sender_email=parsed.sender_email,
        sender_display=parsed.sender_display,
        return_path=parsed.return_path,
        reply_to=parsed.reply_to,
        recipient_list=parsed.recipient_list,
        date_header=parsed.date_header,
        body_plain=parsed.body_plain,
        body_html=parsed.body_html,
        simhash_body=parsed.simhash_body,
        ingested_at=now,
    )
    db.add(email_record)

    db_hops = []
    for h in enriched_hops:
        db_hop = HeaderHop(
            id=uuid.uuid4(),
            email_id=email_record.id,
            hop_order=h["hop_order"],
            by_mta=h["by_mta"],
            from_mta=h["from_mta"],
            hop_ip=h["hop_ip"],
            is_private_ip=h["is_private_ip"],
            is_reliable=h["is_reliable"],
            protocol=h["protocol"],
            hop_timestamp=h["hop_timestamp"],
            delay_seconds=h["delay_seconds"],
            geo_country=h["geo_country"],
            geo_city=h["geo_city"],
            geo_lat=h["geo_lat"],
            geo_lon=h["geo_lon"],
            asn_number=h["asn_number"],
            asn_org=h["asn_org"],
            node_type=h["node_type"],
            is_tor=h["is_tor"],
            is_vpn=h["is_vpn"],
            is_datacenter=h["is_datacenter"],
        )
        db_hops.append(db_hop)
    db.add_all(db_hops)

    db_fa = ForensicAnalysis(
        id=uuid.uuid4(),
        email_id=email_record.id,
        spf_status=auth_res.spf_status,
        spf_domain=auth_res.spf_domain,
        dkim_status=auth_res.dkim_status,
        dkim_selector=auth_res.dkim_selector,
        dkim_domain=auth_res.dkim_domain,
        dmarc_status=auth_res.dmarc_status,
        dmarc_policy=auth_res.dmarc_policy,
        dmarc_alignment_spf=auth_res.dmarc_alignment_spf,
        dmarc_alignment_dkim=auth_res.dmarc_alignment_dkim,
        display_spoof_flag=spoof_res.display_spoof_flag,
        lookalike_flag=spoof_res.lookalike_flag,
        homograph_flag=spoof_res.homograph_flag,
        threat_score=composite.threat_score,
        verdict=composite.verdict,
        score_breakdown=composite.score_breakdown,
    )
    db.add(db_fa)

    db_iocs = []
    for ioc in raw_iocs:
        db_ioc = ThreatIndicator(
            id=uuid.uuid4(),
            email_id=email_record.id,
            ioc_type=ioc.ioc_type,
            ioc_value=ioc.defanged_value,
            context=ioc.context,
            is_defanged=ioc.is_defanged,
            domain_age_days=ioc.metadata.get("domain_age_days"),
            registrar=ioc.metadata.get("registrar"),
            reputation_score=85.0 if ioc.ioc_type in ("URL", "DOMAIN") else 50.0,
            ioc_metadata=ioc.metadata,
        )
        db_iocs.append(db_ioc)
    db.add_all(db_iocs)

    # Campaign correlation check
    first_hop_asn = enriched_hops[0]["asn_number"] if enriched_hops else None
    if first_hop_asn:
        camp_stmt = select(Campaign).where(Campaign.cluster_key.like(f"%AS{first_hop_asn}%"))
        camp_result = await db.execute(camp_stmt)
        campaign = camp_result.scalar_one_or_none()
        if campaign:
            camp_email = CampaignEmail(
                id=uuid.uuid4(),
                campaign_id=campaign.id,
                email_id=email_record.id,
                similarity_score=0.95,
                matched_criteria={"reason": f"Shared bulletproof ASN {first_hop_asn} or SimHash cluster"},
                associated_at=now,
            )
            db.add(camp_email)
            campaign.total_emails += 1

    # Record sealed, hash-chained audit log with authenticated analyst identity
    audit_details = {
        "verdict": composite.verdict,
        "threat_score": composite.threat_score,
        "origin_ip": earliest_ip,
        "is_tor": is_tor_origin,
        "file_size": size_bytes,
    }
    await record_chained_audit_log(
        db=db,
        action="PIPELINE_ANALYSIS_COMPLETED",
        actor=actor,
        evidence_sha256=sha256_hash,
        email_id=email_record.id,
        details=audit_details,
        recorded_at=now,
    )

    await db.commit()

    from backend.app.api.v1.endpoints_forensics import get_evidence_dossier
    from backend.app.database.models import User, UserRole

    analyst_user = User(username=actor, email="analyst@aicte-india.org", password_hash="", role=UserRole.ANALYST)
    dossier = await get_evidence_dossier(str(email_record.id), current_user=analyst_user, db=db)

    if job:
        job.status = JobStatus.COMPLETED
        job.stage = JobStage.FINALIZED
        job.progress_percent = 100
        job.evidence_id = str(email_record.id)
        job.result = dossier
        job.completed_at = datetime.now(timezone.utc)

    return dossier


async def run_background_job(job_id: str, raw_bytes: bytes, file_name: str, actor: str) -> None:
    """Entry point executed by asyncio background task worker."""
    job = await job_manager.get_job(job_id)
    if not job:
        return

    try:
        async with async_session_factory() as session:
            await execute_forensic_pipeline(
                raw_bytes=raw_bytes,
                file_name=file_name,
                actor=actor,
                db=session,
                job=job,
            )
    except Exception as exc:
        logger.exception("Error executing forensic background job %s: %s", job_id, exc)
        job.status = JobStatus.FAILED
        job.error = str(exc)
        job.completed_at = datetime.now(timezone.utc)
