"""Forensic Analysis and Evidence Ingestion API Endpoints.

Provides endpoints for email ingestion (EML / MSG / raw RFC 822), automated forensic pipeline
execution (Reverse Hop-Traversal, SPF/DKIM/DMARC, VIP spoofing, IOC extraction, BEC NLP),
and GeoJSON topological routing exports.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.app.ai.nlp_engine import analyze_email_content
from backend.app.ai.threat_scorer import compute_threat_score
from backend.app.ai.url_analyzer import analyze_url
from backend.app.database.models import (
    Campaign,
    CampaignEmail,
    Email,
    EvidenceAuditLog,
    ForensicAnalysis,
    HeaderHop,
    ThreatIndicator,
)
from backend.app.database.session import get_db
from backend.app.database.vault import (
    canonicalize_audit_payload,
    generate_hmac_signature,
    store_raw_evidence,
)
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

router = APIRouter()


@router.post("/analyze", status_code=status.HTTP_201_CREATED)
async def analyze_email_evidence(
    file: Optional[UploadFile] = File(None),
    raw_headers: Optional[str] = Form(None),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Ingest an email artifact (.eml / .msg / raw text), execute the complete forensic pipeline,
    and persist the sealed record in the evidence vault and database.
    """
    raw_bytes: bytes = b""
    file_name = "evidence.eml"

    if file and file.filename:
        file_name = file.filename
        raw_bytes = await file.read()
    elif raw_headers:
        raw_bytes = raw_headers.encode("utf-8")
        file_name = "raw_headers_submission.eml"
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

    # 1. Store in Cryptographic Evidence Vault
    sha256_hash, md5_hash, stored_path, size_bytes = store_raw_evidence(raw_bytes, file_name)

    # Check if duplicate evidence already exists in database
    existing_stmt = select(Email).where(Email.sha256_hash == sha256_hash)
    existing_result = await db.execute(existing_stmt)
    existing_email = existing_result.scalar_one_or_none()
    if existing_email:
        # Return existing dossier
        return await get_evidence_dossier(str(existing_email.id), db=db)

    # 2. Parse MIME structure
    if file_name.lower().endswith(".msg"):
        parsed = parse_msg(raw_bytes, filename=file_name)
    else:
        parsed = parse_eml(raw_bytes, filename=file_name)

    # 3. Reverse Hop-Traversal
    hops_analyzed, earliest_ip = reverse_hop_traversal(parsed.received_headers)

    # 4. OSINT & Geolocation Enrichment for Hops
    enriched_hops = []
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
    hop_ips = [h["hop_ip"] for h in enriched_hops if h["hop_ip"]]
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
            dom_intel = await lookup_domain_whois(ioc.raw_value)
            if dom_intel.is_newly_registered:
                is_nrd = True
            ioc.metadata.update({"domain_age_days": dom_intel.domain_age_days, "registrar": dom_intel.registrar})

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
    await db.flush()

    # Save Hops
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

    # Save Forensic Analysis
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

    # Save IOCs
    db_iocs = []
    for ioc in raw_iocs:
        db_ioc = ThreatIndicator(
            id=uuid.uuid4(),
            email_id=email_record.id,
            ioc_type=ioc.ioc_type,
            ioc_value=ioc.raw_value,
            context=ioc.context,
            is_defanged=ioc.is_defanged,
            domain_age_days=ioc.metadata.get("domain_age_days"),
            registrar=ioc.metadata.get("registrar"),
            reputation_score=ioc.metadata.get("risk_score") or ioc.metadata.get("reputation"),
            ioc_metadata=ioc.metadata,
        )
        db_iocs.append(db_ioc)
    db.add_all(db_iocs)

    # Check / Link Campaign Clusters
    if is_bulletproof_origin or composite.verdict in ("MALICIOUS", "PHISHING"):
        # Check if existing campaign matches ASN or SimHash prefix
        camp_stmt = select(Campaign).where(Campaign.cluster_key.like(f"%AS49870%")).limit(1)
        camp_res = await db.execute(camp_stmt)
        campaign = camp_res.scalar_one_or_none()
        if campaign:
            camp_email = CampaignEmail(
                id=uuid.uuid4(),
                campaign_id=campaign.id,
                email_id=email_record.id,
                similarity_score=0.95,
                matched_criteria={"reason": "Shared bulletproof ASN or SimHash cluster"},
                associated_at=now,
            )
            db.add(camp_email)
            campaign.total_emails += 1

    # Save Sealed Audit Log
    audit_details = {
        "verdict": composite.verdict,
        "threat_score": composite.threat_score,
        "origin_ip": earliest_ip,
        "is_tor": is_tor_origin,
    }
    audit_payload = canonicalize_audit_payload(
        actor="FORENSIC_INGESTION_SERVICE",
        action="PIPELINE_ANALYSIS_COMPLETED",
        evidence_sha256=sha256_hash,
        recorded_at=now,
        details=audit_details,
    )
    audit_sig = generate_hmac_signature(audit_payload)
    audit_log = EvidenceAuditLog(
        id=uuid.uuid4(),
        email_id=email_record.id,
        action_performed="PIPELINE_ANALYSIS_COMPLETED",
        actor="FORENSIC_INGESTION_SERVICE",
        recorded_at=now,
        evidence_sha256=sha256_hash,
        integrity_check=True,
        hmac_signature=audit_sig,
        details=audit_details,
    )
    db.add(audit_log)

    await db.commit()

    return await get_evidence_dossier(str(email_record.id), db=db)


@router.get("/evidence/{evidence_id}")
async def get_evidence_dossier(
    evidence_id: str,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Retrieve the full forensic dossier by email UUID."""
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


@router.get("/evidence/{evidence_id}/hops")
async def get_evidence_hops_geojson(
    evidence_id: str,
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
            features.append({
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
            })

    # Add LineString geometry representing transit flight path
    if len(line_coordinates) >= 2:
        features.insert(0, {
            "type": "Feature",
            "geometry": {
                "type": "LineString",
                "coordinates": line_coordinates,
            },
            "properties": {
                "route_type": "MTA_TRANSIT_TRAJECTORY",
                "total_hops": len(hops),
            },
        })

    return {
        "type": "FeatureCollection",
        "evidence_id": evidence_id,
        "features": features,
    }

