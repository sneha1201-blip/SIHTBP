"""Forensic Mock Seed Data Generator for AICTE Cyber Security Platform.

Populates the database and cryptographic vault with 5 complete, realistic forensic test cases:
1. Legitimate academic email (AICTE Circular - Threat Score: 12/100, All Auth Passed)
2. Executive BEC Wire Fraud (Impersonating AICTE Chairman with Display Spoofing & Gmail Reply-To - Score: 94/100)
3. Credential Harvesting via Tor Exit Node (Origin IP 185.220.101.5 in Frankfurt - Score: 98/100)
4. Cousin Domain Attack (alcte-india.org using Cyrillic homograph 'а' U+0430 - Score: 88/100)
5. Campaign Cluster (Operation FalconShield: 3 victim emails sharing AS49870 and SimHash template)
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Ensure project root is in sys.path for direct script execution
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from typing import Dict, List, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.database.models import (
    Campaign,
    CampaignEmail,
    Email,
    EvidenceAuditLog,
    ForensicAnalysis,
    HeaderHop,
    ThreatIndicator,
)
from backend.app.database.session import async_session_factory
from backend.app.database.vault import (
    canonicalize_audit_payload,
    generate_hmac_signature,
    store_raw_evidence,
)

logger = logging.getLogger("seed_data")


def create_sealed_audit_log(
    email_id: uuid.UUID,
    action: str,
    actor: str,
    recorded_at: datetime,
    evidence_sha256: str,
    details: dict,
) -> EvidenceAuditLog:
    """Create an EvidenceAuditLog with a mathematically valid HMAC-SHA256 signature."""
    payload = canonicalize_audit_payload(
        actor=actor,
        action=action,
        evidence_sha256=evidence_sha256,
        recorded_at=recorded_at,
        details=details,
    )
    sig = generate_hmac_signature(payload)
    return EvidenceAuditLog(
        id=uuid.uuid4(),
        email_id=email_id,
        action_performed=action,
        actor=actor,
        recorded_at=recorded_at,
        evidence_sha256=evidence_sha256,
        integrity_check=True,
        hmac_signature=sig,
        details=details,
    )


def create_rfc822_raw_eml(
    msg_id: str,
    date_str: str,
    from_header: str,
    to_header: str,
    subject: str,
    reply_to: str | None,
    return_path: str,
    received_headers: List[str],
    auth_results: str,
    body_text: str,
    body_html: str,
) -> bytes:
    """Generate authentic RFC 822 raw MIME email bytes."""
    lines = []
    # Received hops in reverse transit order (top is most recent)
    for rec in received_headers:
        lines.append(f"Received: {rec}")

    lines.append(f"Authentication-Results: {auth_results}")
    lines.append(f"Return-Path: <{return_path}>")
    lines.append(f"Delivered-To: <{to_header}>")
    lines.append(f"Date: {date_str}")
    lines.append(f"From: {from_header}")
    if reply_to:
        lines.append(f"Reply-To: <{reply_to}>")
    lines.append(f"To: {to_header}")
    lines.append(f"Message-ID: <{msg_id}>")
    lines.append(f"Subject: {subject}")
    lines.append("MIME-Version: 1.0")
    lines.append('Content-Type: multipart/alternative; boundary="====_BOUNDARY_AICTE_FORENSIC_===="')
    lines.append("")
    lines.append("--====_BOUNDARY_AICTE_FORENSIC_====")
    lines.append('Content-Type: text/plain; charset="UTF-8"')
    lines.append("Content-Transfer-Encoding: 7bit")
    lines.append("")
    lines.append(body_text)
    lines.append("")
    lines.append("--====_BOUNDARY_AICTE_FORENSIC_====")
    lines.append('Content-Type: text/html; charset="UTF-8"')
    lines.append("Content-Transfer-Encoding: 7bit")
    lines.append("")
    lines.append(body_html)
    lines.append("")
    lines.append("--====_BOUNDARY_AICTE_FORENSIC_====--")
    lines.append("")

    return "\r\n".join(lines).encode("utf-8")


async def seed_forensic_database(session: AsyncSession) -> Dict[str, int]:
    """Populate the database with the 5 realistic forensic seed cases."""
    now = datetime.now(timezone.utc)
    counts = {
        "emails": 0,
        "hops": 0,
        "analyses": 0,
        "iocs": 0,
        "campaigns": 0,
        "campaign_emails": 0,
        "audit_logs": 0,
    }

    # =========================================================================
    # CASE 1: Legitimate Academic Email (AICTE Official Circular)
    # =========================================================================
    logger.info("Generating Case 1: Legitimate Academic Email (AICTE Circular)...")
    c1_date = now - timedelta(days=4, hours=2)
    c1_date_str = c1_date.strftime("%a, %d %b %Y %H:%M:%S +0000")
    c1_msg_id = f"20261028091522.7841.aicte-cell@mta01.delhi.nic.in"
    c1_subject = "[AICTE-OFFICIAL] Circular: Mandatory Faculty Development Programme on Cyber Security & Incident Response 2026-27"
    c1_sender_raw = '"AICTE Cyber Security Cell" <no-reply@aicte-india.org>'
    c1_sender_email = "no-reply@aicte-india.org"
    c1_sender_display = "AICTE Cyber Security Cell"
    c1_return_path = "bounces@aicte-india.org"
    c1_reply_to = "cybersecurity-cell@aicte-india.org"
    c1_recipients = ["principal@vjti.ac.in", "director@coep.ac.in", "hod.cse@pec.edu.in"]
    c1_simhash = "0xa1b2c3d4e5f60718"

    c1_body_plain = (
        "ALL INDIA COUNCIL FOR TECHNICAL EDUCATION (AICTE)\n"
        "Nelson Mandela Marg, Vasant Kunj, New Delhi - 110070\n\n"
        "Ref: AICTE/CS-CELL/FDP/2026-27/089\n"
        "To: All Directors / Principals of AICTE Approved Technical Institutions\n\n"
        "Subject: Mandatory Faculty Development Programme (FDP) on Cyber Security & AI Incident Response\n\n"
        "Dear Sir/Madam,\n"
        "In compliance with National Cyber Security Policy guidelines, AICTE Cyber Security Cell\n"
        "announces a fully-funded 5-day national workshop for CSE, IT, and Cyber Security faculty.\n"
        "Institutions are requested to nominate 2 faculty members by November 15, 2026.\n\n"
        "Official Notification and Registration Portal:\n"
        "https://www.aicte-india.org/bulletins/fdp-cyber-security-2026\n\n"
        "Yours faithfully,\n"
        "Director, Policy & Academic Planning Bureau\n"
        "AICTE New Delhi"
    )

    c1_body_html = (
        "<!DOCTYPE html><html><body>"
        "<div style='font-family: Arial, sans-serif; max-width: 600px; margin: auto;'>"
        "<h2 style='color: #0b3c61;'>All India Council for Technical Education (AICTE)</h2>"
        "<p><strong>Ref: AICTE/CS-CELL/FDP/2026-27/089</strong></p>"
        "<p>Mandatory Faculty Development Programme on Cyber Security & Incident Response.</p>"
        "<p>Please access the official bulletin: <a href='https://www.aicte-india.org/bulletins/fdp-cyber-security-2026'>AICTE FDP Portal</a></p>"
        "<hr><p style='font-size: 11px; color: #777;'>Sent from AICTE Cyber Security Cell, New Delhi.</p>"
        "</div></body></html>"
    )

    c1_received = [
        "from mail-gateway.vjti.ac.in (115.112.82.14) by mx01.vjti.ac.in with ESMTPS id v4982 for <principal@vjti.ac.in>; " + c1_date_str,
        "from relay.nic.in (164.100.24.12) by mail-gateway.vjti.ac.in with ESMTPS id r8391; " + c1_date_str,
        "from mta01.delhi.nic.in (164.100.24.88) by relay.nic.in with ESMTPA id nic-9213; " + c1_date_str,
    ]
    c1_auth_results = (
        "mx01.vjti.ac.in; spf=pass (aicte-india.org: domain of no-reply@aicte-india.org designates 164.100.24.88 as permitted sender) "
        "smtp.mailfrom=no-reply@aicte-india.org; dkim=pass (signature was verified) header.d=aicte-india.org header.s=202409; "
        "dmarc=pass (p=reject dis=none) header.from=aicte-india.org"
    )

    c1_raw = create_rfc822_raw_eml(
        msg_id=c1_msg_id,
        date_str=c1_date_str,
        from_header=c1_sender_raw,
        to_header="principal@vjti.ac.in",
        subject=c1_subject,
        reply_to=c1_reply_to,
        return_path=c1_return_path,
        received_headers=c1_received,
        auth_results=c1_auth_results,
        body_text=c1_body_plain,
        body_html=c1_body_html,
    )
    c1_sha256, c1_md5, c1_vault_path, c1_size = store_raw_evidence(c1_raw, "aicte_circular_legit.eml")

    email_c1 = Email(
        id=uuid.uuid4(),
        sha256_hash=c1_sha256,
        md5_hash=c1_md5,
        file_name="aicte_circular_fdp_2026.eml",
        file_size_bytes=c1_size,
        raw_storage_path=c1_vault_path,
        rfc822_msg_id=c1_msg_id,
        subject=c1_subject,
        sender_raw=c1_sender_raw,
        sender_email=c1_sender_email,
        sender_display=c1_sender_display,
        return_path=c1_return_path,
        reply_to=c1_reply_to,
        recipient_list=c1_recipients,
        date_header=c1_date,
        body_plain=c1_body_plain,
        body_html=c1_body_html,
        simhash_body=c1_simhash,
        ingested_at=now - timedelta(days=4),
    )
    session.add(email_c1)
    counts["emails"] += 1

    # Hops for Case 1
    c1_hops = [
        HeaderHop(
            id=uuid.uuid4(),
            email_id=email_c1.id,
            hop_order=1,
            by_mta="relay.nic.in",
            from_mta="mta01.delhi.nic.in",
            hop_ip="164.100.24.88",
            is_private_ip=False,
            is_reliable=True,
            protocol="ESMTPA",
            hop_timestamp=c1_date,
            delay_seconds=0.4,
            geo_country="India",
            geo_city="New Delhi",
            geo_lat=28.6139,
            geo_lon=77.2090,
            asn_number=38029,
            asn_org="National Informatics Centre (NIC)",
            node_type="ORIGINATING",
            is_tor=False,
            is_vpn=False,
            is_datacenter=False,
        ),
        HeaderHop(
            id=uuid.uuid4(),
            email_id=email_c1.id,
            hop_order=2,
            by_mta="mail-gateway.vjti.ac.in",
            from_mta="relay.nic.in",
            hop_ip="164.100.24.12",
            is_private_ip=False,
            is_reliable=True,
            protocol="ESMTPS",
            hop_timestamp=c1_date + timedelta(seconds=1),
            delay_seconds=0.8,
            geo_country="India",
            geo_city="New Delhi",
            geo_lat=28.6139,
            geo_lon=77.2090,
            asn_number=38029,
            asn_org="National Informatics Centre (NIC)",
            node_type="INTERNAL",
            is_tor=False,
            is_vpn=False,
            is_datacenter=False,
        ),
        HeaderHop(
            id=uuid.uuid4(),
            email_id=email_c1.id,
            hop_order=3,
            by_mta="mx01.vjti.ac.in",
            from_mta="mail-gateway.vjti.ac.in",
            hop_ip="115.112.82.14",
            is_private_ip=False,
            is_reliable=True,
            protocol="ESMTPS",
            hop_timestamp=c1_date + timedelta(seconds=2),
            delay_seconds=1.2,
            geo_country="India",
            geo_city="Mumbai",
            geo_lat=19.0760,
            geo_lon=72.8777,
            asn_number=4755,
            asn_org="Tata Communications Limited",
            node_type="EDGE_GATEWAY",
            is_tor=False,
            is_vpn=False,
            is_datacenter=False,
        ),
    ]
    session.add_all(c1_hops)
    counts["hops"] += len(c1_hops)

    # Forensic Analysis for Case 1
    fa_c1 = ForensicAnalysis(
        id=uuid.uuid4(),
        email_id=email_c1.id,
        spf_status="PASS",
        spf_domain="aicte-india.org",
        dkim_status="PASS",
        dkim_selector="202409",
        dkim_domain="aicte-india.org",
        dmarc_status="PASS",
        dmarc_policy="reject",
        dmarc_alignment_spf=True,
        dmarc_alignment_dkim=True,
        display_spoof_flag=False,
        lookalike_flag=False,
        homograph_flag=False,
        threat_score=12.0,
        verdict="BENIGN",
        score_breakdown={
            "spf_score": 0.0,
            "dkim_score": 0.0,
            "dmarc_score": 0.0,
            "display_spoof_score": 0.0,
            "reputation_penalty": 0.0,
            "base_anomaly": 12.0,
            "nlp_urgency_score": 4.0,
            "reasons": [
                "All cryptographic sender authentications passed",
                "Originating IP verified under National Informatics Centre (AS38029)",
                "Valid official government institutional domain",
            ],
        },
    )
    session.add(fa_c1)
    counts["analyses"] += 1

    # Threat Indicators for Case 1
    ioc_c1_url = ThreatIndicator(
        id=uuid.uuid4(),
        email_id=email_c1.id,
        ioc_type="URL",
        ioc_value="https://www.aicte-india.org/bulletins/fdp-cyber-security-2026",
        context="EMAIL_BODY",
        is_defanged=False,
        domain_age_days=8420,
        registrar="National Informatics Centre",
        reputation_score=2.0,
        ioc_metadata={"official_portal": True, "ssl_valid": True},
    )
    ioc_c1_domain = ThreatIndicator(
        id=uuid.uuid4(),
        email_id=email_c1.id,
        ioc_type="DOMAIN",
        ioc_value="aicte-india.org",
        context="SENDER",
        is_defanged=False,
        domain_age_days=8420,
        registrar="National Informatics Centre",
        reputation_score=1.0,
        ioc_metadata={"category": "GOVERNMENT_EDUCATION", "trust_rank": "HIGH"},
    )
    session.add_all([ioc_c1_url, inoc_c1_domain := ioc_c1_domain])
    counts["iocs"] += 2

    # Audit Log for Case 1
    session.add(
        create_sealed_audit_log(
            email_id=email_c1.id,
            action="VAULT_SEALED",
            actor="INGESTION_AGENT_01",
            recorded_at=now - timedelta(days=4),
            evidence_sha256=c1_sha256,
            details={"verdict": "BENIGN", "pipeline_stage": "INITIAL_INGESTION"},
        )
    )
    counts["audit_logs"] += 1

    # =========================================================================
    # CASE 2: Executive BEC Wire Fraud (Impersonating AICTE Chairman)
    # =========================================================================
    logger.info("Generating Case 2: Executive BEC Wire Fraud (Chairman Impersonation)...")
    c2_date = now - timedelta(days=3, hours=5)
    c2_date_str = c2_date.strftime("%a, %d %b %Y %H:%M:%S +0000")
    c2_msg_id = "9f83a210-91bf-4b21-a124-789a23bca@smtp.aicte-emergency-portal.org"
    c2_subject = "URGENT & CONFIDENTIAL: Release of Emergency Cybersecurity Modernization Grant Allocation"
    c2_sender_raw = '"Prof. T. G. Sitharam (Chairman, AICTE)" <chairman-office@aicte-emergency-portal.org>'
    c2_sender_email = "chairman-office@aicte-emergency-portal.org"
    c2_sender_display = "Prof. T. G. Sitharam (Chairman, AICTE)"
    c2_return_path = "bounce@aicte-emergency-portal.org"
    c2_reply_to = "chairman.aicte.funds.dept@gmail.com"  # BEC Red Flag!
    c2_recipients = ["finance.officer@iitb.ac.in", "accounts@coep.ac.in"]
    c2_simhash = "0xbc882190aa34f012"

    c2_body_plain = (
        "CONFIDENTIAL & HIGH PRIORITY\n\n"
        "From: Office of the Chairman, AICTE New Delhi\n"
        "To: Chief Finance Officer / Bursar\n\n"
        "Dear Finance Officer,\n\n"
        "Under the Special Cybersecurity Infrastructure Modernization Scheme approved in today's\n"
        "emergency executive council meeting, your institution has been allocated an expedited matching grant\n"
        "of Rs. 45,00,000 (Forty-Five Lakhs Only) for high-performance server hardware procurement.\n\n"
        "Due to end-of-quarter treasury reconciliation, the initial statutory commitment fee of\n"
        "Rs. 4,50,000 must be remitted via RTGS immediately to our designated project escrow account\n"
        "before 4:00 PM today to lock in the bilateral ministry disbursement.\n\n"
        "Escrow Account Details:\n"
        "Beneficiary: AICTE Special Projects Escrow\n"
        "Account Number: 50200088192411\n"
        "IFSC Code: HDFC0000122\n\n"
        "Please confirm receipt and forward RTGS UTR reference directly to my confidential liaison at:\n"
        "chairman.aicte.funds.dept@gmail.com\n\n"
        "Sincerely,\n"
        "Prof. T. G. Sitharam\n"
        "Chairman, All India Council for Technical Education"
    )

    c2_body_html = (
        "<html><body>"
        "<p><strong>CONFIDENTIAL & HIGH PRIORITY</strong></p>"
        "<p>Dear Finance Officer,</p>"
        "<p>Your institution has been granted Rs. 45,00,000 under the Cybersecurity Infrastructure Fund.</p>"
        "<p>Remit the commitment fee of <strong>Rs. 4,50,000</strong> to Account: 50200088192411 (IFSC: HDFC0000122).</p>"
        "<p>Reply directly to: <a href='mailto:chairman.aicte.funds.dept@gmail.com'>chairman.aicte.funds.dept@gmail.com</a></p>"
        "<p>Prof. T. G. Sitharam, Chairman AICTE</p>"
        "</body></html>"
    )

    c2_received = [
        "from relay.smtp-inbound.iitb.ac.in (103.21.124.5) by mail.iitb.ac.in with ESMTP id iitb-9912; " + c2_date_str,
        "from mail.aicte-emergency-portal.org (185.174.136.42) by relay.smtp-inbound.iitb.ac.in with ESMTPS id rom-1142; " + c2_date_str,
    ]
    c2_auth_results = (
        "relay.smtp-inbound.iitb.ac.in; spf=softfail (aicte-emergency-portal.org: 185.174.136.42 is neither permitted nor denied) "
        "smtp.mailfrom=bounce@aicte-emergency-portal.org; dkim=fail (body hash did not verify) header.d=aicte-emergency-portal.org; "
        "dmarc=fail (p=none dis=none) header.from=aicte-emergency-portal.org"
    )

    c2_raw = create_rfc822_raw_eml(
        msg_id=c2_msg_id,
        date_str=c2_date_str,
        from_header=c2_sender_raw,
        to_header="finance.officer@iitb.ac.in",
        subject=c2_subject,
        reply_to=c2_reply_to,
        return_path=c2_return_path,
        received_headers=c2_received,
        auth_results=c2_auth_results,
        body_text=c2_body_plain,
        body_html=c2_body_html,
    )
    c2_sha256, c2_md5, c2_vault_path, c2_size = store_raw_evidence(c2_raw, "bec_chairman_spoof.eml")

    email_c2 = Email(
        id=uuid.uuid4(),
        sha256_hash=c2_sha256,
        md5_hash=c2_md5,
        file_name="bec_chairman_emergency_fund.eml",
        file_size_bytes=c2_size,
        raw_storage_path=c2_vault_path,
        rfc822_msg_id=c2_msg_id,
        subject=c2_subject,
        sender_raw=c2_sender_raw,
        sender_email=c2_sender_email,
        sender_display=c2_sender_display,
        return_path=c2_return_path,
        reply_to=c2_reply_to,
        recipient_list=c2_recipients,
        date_header=c2_date,
        body_plain=c2_body_plain,
        body_html=c2_body_html,
        simhash_body=c2_simhash,
        ingested_at=now - timedelta(days=3),
    )
    session.add(email_c2)
    counts["emails"] += 1

    # Hops for Case 2
    c2_hops = [
        HeaderHop(
            id=uuid.uuid4(),
            email_id=email_c2.id,
            hop_order=1,
            by_mta="relay.smtp-inbound.iitb.ac.in",
            from_mta="mail.aicte-emergency-portal.org",
            hop_ip="185.174.136.42",
            is_private_ip=False,
            is_reliable=True,
            protocol="ESMTPS",
            hop_timestamp=c2_date,
            delay_seconds=0.1,
            geo_country="Romania",
            geo_city="Bucharest",
            geo_lat=44.4268,
            geo_lon=26.1025,
            asn_number=208642,
            asn_org="Hostkey B.V.",
            node_type="ORIGINATING",
            is_tor=False,
            is_vpn=False,
            is_datacenter=True,
        ),
        HeaderHop(
            id=uuid.uuid4(),
            email_id=email_c2.id,
            hop_order=2,
            by_mta="mail.iitb.ac.in",
            from_mta="relay.smtp-inbound.iitb.ac.in",
            hop_ip="103.21.124.5",
            is_private_ip=False,
            is_reliable=True,
            protocol="ESMTP",
            hop_timestamp=c2_date + timedelta(seconds=2),
            delay_seconds=1.9,
            geo_country="India",
            geo_city="Mumbai",
            geo_lat=19.1334,
            geo_lon=72.9133,
            asn_number=55824,
            asn_org="Indian Institute of Technology Bombay",
            node_type="EDGE_GATEWAY",
            is_tor=False,
            is_vpn=False,
            is_datacenter=False,
        ),
    ]
    session.add_all(c2_hops)
    counts["hops"] += len(c2_hops)

    # Forensic Analysis for Case 2
    fa_c2 = ForensicAnalysis(
        id=uuid.uuid4(),
        email_id=email_c2.id,
        spf_status="SOFTFAIL",
        spf_domain="aicte-emergency-portal.org",
        dkim_status="FAIL",
        dkim_selector="default",
        dkim_domain="aicte-emergency-portal.org",
        dmarc_status="FAIL",
        dmarc_policy="none",
        dmarc_alignment_spf=False,
        dmarc_alignment_dkim=False,
        display_spoof_flag=True,
        lookalike_flag=True,
        homograph_flag=False,
        threat_score=94.0,
        verdict="BEC",
        score_breakdown={
            "display_spoof_penalty": 35.0,
            "reply_to_mismatch_penalty": 30.0,
            "auth_failure_penalty": 15.0,
            "nlp_wire_transfer_coercion": 14.0,
            "reasons": [
                "Executive identity spoofing detected: 'Prof. T. G. Sitharam (Chairman, AICTE)'",
                "Reply-To header diverts strictly to unauthenticated free mail provider (gmail.com)",
                "Newly registered lookalike domain: aicte-emergency-portal.org",
                "High-coercion wire fraud solicitation (RTGS transfer to unknown commercial account)",
                "Originating host located in foreign datacenter ASN (Bucharest, RO)",
            ],
        },
    )
    session.add(fa_c2)
    counts["analyses"] += 1

    # Threat Indicators for Case 2
    ioc_c2_domain = ThreatIndicator(
        id=uuid.uuid4(),
        email_id=email_c2.id,
        ioc_type="DOMAIN",
        ioc_value="aicte-emergency-portal.org",
        context="SENDER",
        is_defanged=False,
        domain_age_days=4,
        registrar="NameCheap Inc",
        reputation_score=92.0,
        ioc_metadata={"typosquatted_target": "aicte-india.org", "entropy": 3.84},
    )
    ioc_c2_replyto = ThreatIndicator(
        id=uuid.uuid4(),
        email_id=email_c2.id,
        ioc_type="EMAIL_ADDR",
        ioc_value="chairman.aicte.funds.dept@gmail.com",
        context="REPLY_TO",
        is_defanged=False,
        domain_age_days=365,
        registrar="Google LLC",
        reputation_score=88.0,
        ioc_metadata={"free_mail_provider": True, "executive_name_harvested": "T. G. Sitharam"},
    )
    ioc_c2_ip = ThreatIndicator(
        id=uuid.uuid4(),
        email_id=email_c2.id,
        ioc_type="IP",
        ioc_value="185.174.136.42",
        context="HEADER_RECEIVED",
        is_defanged=False,
        domain_age_days=None,
        registrar="RIPE NCC",
        reputation_score=85.0,
        ioc_metadata={"asn": 208642, "datacenter": True, "country": "RO"},
    )
    session.add_all([ioc_c2_domain, ioc_c2_replyto, ioc_c2_ip])
    counts["iocs"] += 3

    # Audit Log for Case 2
    session.add(
        create_sealed_audit_log(
            email_id=email_c2.id,
            action="VAULT_SEALED",
            actor="AUTOMATED_THREAT_CORRELATOR",
            recorded_at=now - timedelta(days=3),
            evidence_sha256=c2_sha256,
            details={"verdict": "BEC", "priority": "CRITICAL", "auto_alert_dispatched": True},
        )
    )
    counts["audit_logs"] += 1

    # =========================================================================
    # CASE 3: Credential Harvesting via Tor Exit Node (Origin IP 185.220.101.5)
    # =========================================================================
    logger.info("Generating Case 3: Credential Harvesting via Tor Exit Node...")
    c3_date = now - timedelta(days=2, hours=8)
    c3_date_str = c3_date.strftime("%a, %d %b %Y %H:%M:%S +0000")
    c3_msg_id = "20261029140219.exit-tor@tor-node-05.frankfurt.de"
    c3_subject = "Immediate Action Required: Faculty Portal Credentials Expiration Notice"
    c3_sender_raw = '"AICTE Central Security Desk" <admin@portal-aicte.com>'
    c3_sender_email = "admin@portal-aicte.com"
    c3_sender_display = "AICTE Central Security Desk"
    c3_return_path = "bounce-tor@portal-aicte.com"
    c3_reply_to = "no-reply@portal-aicte.com"
    c3_recipients = ["dr.sharma@nitk.edu.in", "hod.it@dtu.ac.in"]
    c3_simhash = "0x77ab41029cba88ef"

    c3_body_plain = (
        "AICTE NATIONAL FACULTY AUTHENTICATION GATEWAY\n\n"
        "Security Alert: Your single-sign-on (SSO) faculty account credentials have been flagged\n"
        "for mandatory periodic biometric re-validation. Failure to confirm your credentials\n"
        "within 24 hours will result in suspension of research grant access and approval portal privileges.\n\n"
        "Log in immediately through the secure verification mirror:\n"
        "https://login.aicte-faculty-verification.ru/auth/login.php\n\n"
        "Security Reference: ID-AUTH-TOR-88190\n"
        "AICTE Directorate of Digital Services"
    )

    c3_body_html = (
        "<html><body>"
        "<h3 style='color: red;'>AICTE Security Alert: Credential Expiration Notice</h3>"
        "<p>Your faculty credentials will expire in 24 hours.</p>"
        "<p>Re-authenticate now at: <a href='https://login.aicte-faculty-verification.ru/auth/login.php'>Faculty Verification Portal</a></p>"
        "<p><em>Note: This message was dispatched by the Central Security Desk.</em></p>"
        "</body></html>"
    )

    c3_received = [
        "from mx01.nitk.edu.in (210.212.201.2) by mailbox.nitk.edu.in with ESMTP id nitk-4412; " + c3_date_str,
        "from relay02.mx-inbound-eu.com (195.154.122.9) by mx01.nitk.edu.in with ESMTPS id eu-8821; " + c3_date_str,
        "from tor-exit-05.ip-zone.net (185.220.101.5) by relay02.mx-inbound-eu.com with ESMTP id tor-4410; " + c3_date_str,
    ]
    c3_auth_results = (
        "mx01.nitk.edu.in; spf=fail (portal-aicte.com: 185.220.101.5 is not permitted) "
        "smtp.mailfrom=bounce-tor@portal-aicte.com; dkim=none; "
        "dmarc=fail (p=quarantine dis=quarantine) header.from=portal-aicte.com"
    )

    c3_raw = create_rfc822_raw_eml(
        msg_id=c3_msg_id,
        date_str=c3_date_str,
        from_header=c3_sender_raw,
        to_header="dr.sharma@nitk.edu.in",
        subject=c3_subject,
        reply_to=c3_reply_to,
        return_path=c3_return_path,
        received_headers=c3_received,
        auth_results=c3_auth_results,
        body_text=c3_body_plain,
        body_html=c3_body_html,
    )
    c3_sha256, c3_md5, c3_vault_path, c3_size = store_raw_evidence(c3_raw, "tor_credential_harvesting.eml")

    email_c3 = Email(
        id=uuid.uuid4(),
        sha256_hash=c3_sha256,
        md5_hash=c3_md5,
        file_name="tor_phishing_credential_harvest.eml",
        file_size_bytes=c3_size,
        raw_storage_path=c3_vault_path,
        rfc822_msg_id=c3_msg_id,
        subject=c3_subject,
        sender_raw=c3_sender_raw,
        sender_email=c3_sender_email,
        sender_display=c3_sender_display,
        return_path=c3_return_path,
        reply_to=c3_reply_to,
        recipient_list=c3_recipients,
        date_header=c3_date,
        body_plain=c3_body_plain,
        body_html=c3_body_html,
        simhash_body=c3_simhash,
        ingested_at=now - timedelta(days=2),
    )
    session.add(email_c3)
    counts["emails"] += 1

    # Hops for Case 3
    c3_hops = [
        HeaderHop(
            id=uuid.uuid4(),
            email_id=email_c3.id,
            hop_order=1,
            by_mta="relay02.mx-inbound-eu.com",
            from_mta="tor-exit-05.ip-zone.net",
            hop_ip="185.220.101.5",
            is_private_ip=False,
            is_reliable=True,
            protocol="ESMTP",
            hop_timestamp=c3_date,
            delay_seconds=0.2,
            geo_country="Germany",
            geo_city="Frankfurt am Main",
            geo_lat=50.1109,
            geo_lon=8.6821,
            asn_number=208294,
            asn_org="Zappie Host LLC",
            node_type="TOR_EXIT",
            is_tor=True,
            is_vpn=False,
            is_datacenter=True,
        ),
        HeaderHop(
            id=uuid.uuid4(),
            email_id=email_c3.id,
            hop_order=2,
            by_mta="mx01.nitk.edu.in",
            from_mta="relay02.mx-inbound-eu.com",
            hop_ip="195.154.122.9",
            is_private_ip=False,
            is_reliable=True,
            protocol="ESMTPS",
            hop_timestamp=c3_date + timedelta(seconds=2),
            delay_seconds=2.4,
            geo_country="France",
            geo_city="Paris",
            geo_lat=48.8566,
            geo_lon=2.3522,
            asn_number=12876,
            asn_org="Scaleway SAS",
            node_type="RELAY",
            is_tor=False,
            is_vpn=False,
            is_datacenter=True,
        ),
        HeaderHop(
            id=uuid.uuid4(),
            email_id=email_c3.id,
            hop_order=3,
            by_mta="mailbox.nitk.edu.in",
            from_mta="mx01.nitk.edu.in",
            hop_ip="210.212.201.2",
            is_private_ip=False,
            is_reliable=True,
            protocol="ESMTP",
            hop_timestamp=c3_date + timedelta(seconds=5),
            delay_seconds=3.1,
            geo_country="India",
            geo_city="Surathkal",
            geo_lat=13.0108,
            geo_lon=74.7943,
            asn_number=4755,
            asn_org="Tata Communications Limited",
            node_type="EDGE_GATEWAY",
            is_tor=False,
            is_vpn=False,
            is_datacenter=False,
        ),
    ]
    session.add_all(c3_hops)
    counts["hops"] += len(c3_hops)

    # Forensic Analysis for Case 3
    fa_c3 = ForensicAnalysis(
        id=uuid.uuid4(),
        email_id=email_c3.id,
        spf_status="FAIL",
        spf_domain="portal-aicte.com",
        dkim_status="NONE",
        dkim_selector=None,
        dkim_domain=None,
        dmarc_status="FAIL",
        dmarc_policy="quarantine",
        dmarc_alignment_spf=False,
        dmarc_alignment_dkim=False,
        display_spoof_flag=True,
        lookalike_flag=True,
        homograph_flag=False,
        threat_score=98.0,
        verdict="PHISHING",
        score_breakdown={
            "tor_exit_node_penalty": 40.0,
            "credential_harvesting_url": 30.0,
            "auth_failure_penalty": 18.0,
            "lookalike_penalty": 10.0,
            "reasons": [
                "Direct origin MTA verified as active Tor Exit Node (185.220.101.5 / Frankfurt DE)",
                "Hostile Russian TLD (.ru) hosting credential harvesting form",
                "Total cryptographic authentication breakdown (SPF FAIL, DKIM NONE, DMARC FAIL)",
                "Typosquatted domain mimicking official brand: portal-aicte.com",
            ],
        },
    )
    session.add(fa_c3)
    counts["analyses"] += 1

    # Threat Indicators for Case 3
    ioc_c3_ip = ThreatIndicator(
        id=uuid.uuid4(),
        email_id=email_c3.id,
        ioc_type="IP",
        ioc_value="185.220.101.5",
        context="HEADER_RECEIVED",
        is_defanged=False,
        domain_age_days=None,
        registrar="RIPE NCC",
        reputation_score=99.0,
        ioc_metadata={
            "tor_exit_node": True,
            "tor_node_fingerprint": "8F572C46549C650A481F4BCE0B8BB1371EEAA22B",
            "country": "DE",
            "city": "Frankfurt am Main",
        },
    )
    ioc_c3_url = ThreatIndicator(
        id=uuid.uuid4(),
        email_id=email_c3.id,
        ioc_type="URL",
        ioc_value="hxxps://login[.]aicte-faculty-verification[.]ru/auth/login[.]php",
        context="EMAIL_BODY",
        is_defanged=True,
        domain_age_days=3,
        registrar="Reg.ru LLC",
        reputation_score=99.0,
        ioc_metadata={"form_action": "post", "steals": ["username", "password", "otp_token"], "tld": ".ru"},
    )
    ioc_c3_dom = ThreatIndicator(
        id=uuid.uuid4(),
        email_id=email_c3.id,
        ioc_type="DOMAIN",
        ioc_value="portal-aicte.com",
        context="SENDER",
        is_defanged=False,
        domain_age_days=6,
        registrar="NameSilo LLC",
        reputation_score=94.0,
        ioc_metadata={"entropy": 3.71, "typosquat": "aicte-india.org"},
    )
    session.add_all([ioc_c3_ip, ioc_c3_url, ioc_c3_dom])
    counts["iocs"] += 3

    # Audit Log for Case 3
    session.add(
        create_sealed_audit_log(
            email_id=email_c3.id,
            action="INTEGRITY_VERIFIED",
            actor="SOC_AUTO_ENRICHMENT_ENGINE",
            recorded_at=now - timedelta(days=2),
            evidence_sha256=c3_sha256,
            details={"verdict": "PHISHING", "tor_node": "185.220.101.5", "alert_level": "RED"},
        )
    )
    counts["audit_logs"] += 1

    # =========================================================================
    # CASE 4: Cousin Domain Attack with Cyrillic Homograph 'а' (U+0430)
    # =========================================================================
    logger.info("Generating Case 4: Cousin Domain Attack (Cyrillic Homograph 'а')...")
    c4_date = now - timedelta(days=1, hours=10)
    c4_date_str = c4_date.strftime("%a, %d %b %Y %H:%M:%S +0000")
    c4_msg_id = "20261030082215.9921@smtp-out.xn--icte-india-e1a.org"
    c4_subject = "CRITICAL: Mandatory Compliance Rectification - AICTE Approval Process Handbook (APH 2026-27)"
    # Notice: 'а' in approvals@аicte-india.org is Cyrillic small letter a (U+0430)
    c4_sender_raw = '"Approval Bureau AICTE" <approvals@\u0430icte-india.org>'
    c4_sender_email = "approvals@\u0430icte-india.org"
    c4_sender_display = "Approval Bureau AICTE"
    c4_return_path = "bounce@xn--icte-india-e1a.org"
    c4_reply_to = "compliance-desk@xn--icte-india-e1a.org"
    c4_recipients = ["registrar@annauniv.edu", "approval.cell@jntuh.ac.in"]
    c4_simhash = "0x5e2910fa3c4d7b88"

    c4_body_plain = (
        "APPROVAL BUREAU - ALL INDIA COUNCIL FOR TECHNICAL EDUCATION\n\n"
        "URGENT DEFICIENCY NOTICE\n\n"
        "Institutional Application ID: AICTE/2026/APH-REV-9812\n\n"
        "The Scrutiny Committee has identified severe non-compliance discrepancies in your institution's\n"
        "faculty cadre ratio and land title deed documents submitted for Extension of Approval (EoA) 2026-27.\n\n"
        "To avoid immediate reduction in sanctioned intake or zero-admission category status,\n"
        "download and submit the certified Deficiencies Rectification Form within 48 hours:\n\n"
        "https://\u0430icte-india.org/aph2026/deficiency-rectification-form.xlsm\n\n"
        "Member Secretary, Approval Bureau\n"
        "AICTE Headquarters, New Delhi"
    )

    c4_body_html = (
        "<html><body>"
        "<h3 style='color: #8b0000;'>AICTE Approval Bureau - Critical Deficiency Notice</h3>"
        "<p>Non-compliance detected in your Approval Process Handbook submission.</p>"
        "<p>Download the official response workbook: "
        "<a href='https://xn--icte-india-e1a.org/aph2026/deficiency-rectification-form.xlsm'>Deficiency Rectification Workbook (XLSM)</a></p>"
        "</body></html>"
    )

    c4_received = [
        "from edge-mx.annauniv.edu (14.139.161.2) by mail.annauniv.edu with ESMTP id anna-2910; " + c4_date_str,
        "from smtp-out.xn--icte-india-e1a.org (193.109.69.52) by edge-mx.annauniv.edu with ESMTPS id sey-0012; " + c4_date_str,
    ]
    c4_auth_results = (
        "edge-mx.annauniv.edu; spf=pass (xn--icte-india-e1a.org: 193.109.69.52 is permitted) "
        "smtp.mailfrom=bounce@xn--icte-india-e1a.org; dkim=pass header.d=xn--icte-india-e1a.org header.s=k1; "
        "dmarc=fail (p=reject dis=none dmarc-align=fail) header.from=\u0430icte-india.org"
    )

    c4_raw = create_rfc822_raw_eml(
        msg_id=c4_msg_id,
        date_str=c4_date_str,
        from_header=c4_sender_raw,
        to_header="registrar@annauniv.edu",
        subject=c4_subject,
        reply_to=c4_reply_to,
        return_path=c4_return_path,
        received_headers=c4_received,
        auth_results=c4_auth_results,
        body_text=c4_body_plain,
        body_html=c4_body_html,
    )
    c4_sha256, c4_md5, c4_vault_path, c4_size = store_raw_evidence(c4_raw, "homograph_aph_phish.eml")

    email_c4 = Email(
        id=uuid.uuid4(),
        sha256_hash=c4_sha256,
        md5_hash=c4_md5,
        file_name="homograph_cyrillic_aph_compliance.eml",
        file_size_bytes=c4_size,
        raw_storage_path=c4_vault_path,
        rfc822_msg_id=c4_msg_id,
        subject=c4_subject,
        sender_raw=c4_sender_raw,
        sender_email=c4_sender_email,
        sender_display=c4_sender_display,
        return_path=c4_return_path,
        reply_to=c4_reply_to,
        recipient_list=c4_recipients,
        date_header=c4_date,
        body_plain=c4_body_plain,
        body_html=c4_body_html,
        simhash_body=c4_simhash,
        ingested_at=now - timedelta(days=1),
    )
    session.add(email_c4)
    counts["emails"] += 1

    # Hops for Case 4
    c4_hops = [
        HeaderHop(
            id=uuid.uuid4(),
            email_id=email_c4.id,
            hop_order=1,
            by_mta="edge-mx.annauniv.edu",
            from_mta="smtp-out.xn--icte-india-e1a.org",
            hop_ip="193.109.69.52",
            is_private_ip=False,
            is_reliable=True,
            protocol="ESMTPS",
            hop_timestamp=c4_date,
            delay_seconds=0.3,
            geo_country="Seychelles",
            geo_city="Victoria",
            geo_lat=-4.6191,
            geo_lon=55.4513,
            asn_number=200019,
            asn_org="Alexhost SRL",
            node_type="ORIGINATING",
            is_tor=False,
            is_vpn=True,
            is_datacenter=True,
        ),
        HeaderHop(
            id=uuid.uuid4(),
            email_id=email_c4.id,
            hop_order=2,
            by_mta="mail.annauniv.edu",
            from_mta="edge-mx.annauniv.edu",
            hop_ip="14.139.161.2",
            is_private_ip=False,
            is_reliable=True,
            protocol="ESMTP",
            hop_timestamp=c4_date + timedelta(seconds=2),
            delay_seconds=2.1,
            geo_country="India",
            geo_city="Chennai",
            geo_lat=13.0827,
            geo_lon=80.2707,
            asn_number=38029,
            asn_org="ERNET India / Anna University",
            node_type="EDGE_GATEWAY",
            is_tor=False,
            is_vpn=False,
            is_datacenter=False,
        ),
    ]
    session.add_all(c4_hops)
    counts["hops"] += len(c4_hops)

    # Forensic Analysis for Case 4
    fa_c4 = ForensicAnalysis(
        id=uuid.uuid4(),
        email_id=email_c4.id,
        spf_status="PASS",
        spf_domain="xn--icte-india-e1a.org",
        dkim_status="PASS",
        dkim_selector="k1",
        dkim_domain="xn--icte-india-e1a.org",
        dmarc_status="FAIL",
        dmarc_policy="reject",
        dmarc_alignment_spf=False,
        dmarc_alignment_dkim=False,
        display_spoof_flag=False,
        lookalike_flag=True,
        homograph_flag=True,
        threat_score=88.0,
        verdict="PHISHING",
        score_breakdown={
            "homograph_attack_penalty": 45.0,
            "dmarc_alignment_failure": 25.0,
            "suspicious_bulletproof_asn": 18.0,
            "reasons": [
                "IDN Homograph attack detected (U+0430 Cyrillic Small Letter A replaces ASCII 'a')",
                "Attacker configured valid SPF/DKIM for rogue punycode domain xn--icte-india-e1a.org",
                "Cross-domain DMARC alignment failure against genuine aicte-india.org",
                "Originating from offshore bulletproof ASN AS200019 (Alexhost SRL / Seychelles)",
            ],
        },
    )
    session.add(fa_c4)
    counts["analyses"] += 1

    # Threat Indicators for Case 4
    ioc_c4_domain = ThreatIndicator(
        id=uuid.uuid4(),
        email_id=email_c4.id,
        ioc_type="DOMAIN",
        ioc_value="xn--icte-india-e1a.org",
        context="SENDER",
        is_defanged=False,
        domain_age_days=11,
        registrar="Nicenic International Group",
        reputation_score=95.0,
        ioc_metadata={
            "punycode": "xn--icte-india-e1a.org",
            "unicode_raw": "\u0430icte-india.org",
            "homograph_glyphs": ["U+0430 CYRILLIC SMALL LETTER A"],
            "confusable_with": "aicte-india.org",
        },
    )
    ioc_c4_url = ThreatIndicator(
        id=uuid.uuid4(),
        email_id=email_c4.id,
        ioc_type="URL",
        ioc_value="hxxps://xn--icte-india-e1a[.]org/aph2026/deficiency-rectification-form[.]xlsm",
        context="EMAIL_BODY",
        is_defanged=True,
        domain_age_days=11,
        registrar="Nicenic International Group",
        reputation_score=96.0,
        ioc_metadata={"payload_type": "Macro-enabled Weaponized Excel", "macro_detected": True},
    )
    ioc_c4_hash = ThreatIndicator(
        id=uuid.uuid4(),
        email_id=email_c4.id,
        ioc_type="HASH",
        ioc_value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        context="ATTACHMENT",
        is_defanged=False,
        domain_age_days=None,
        registrar=None,
        reputation_score=95.0,
        ioc_metadata={"file_name": "deficiency-rectification-form.xlsm", "sha256": "e3b0c442..."},
    )
    session.add_all([ioc_c4_domain, ioc_c4_url, ioc_c4_hash])
    counts["iocs"] += 3

    # Audit Log for Case 4
    session.add(
        create_sealed_audit_log(
            email_id=email_c4.id,
            action="VAULT_SEALED",
            actor="CYBER_HOMOGRAPH_DETECTOR",
            recorded_at=now - timedelta(days=1),
            evidence_sha256=c4_sha256,
            details={"verdict": "PHISHING", "homograph": "U+0430", "punycode": "xn--icte-india-e1a.org"},
        )
    )
    counts["audit_logs"] += 1

    # =========================================================================
    # CASE 5: Campaign Cluster (Operation FalconShield - 3 Victim Emails)
    # =========================================================================
    logger.info("Generating Case 5: Campaign Cluster (Operation FalconShield - 3 Victim Emails)...")

    # Campaign Entity
    campaign_5 = Campaign(
        id=uuid.uuid4(),
        name="Operation FalconShield: AICTE Affiliation Extortion & Compliance Scams",
        description=(
            "Multi-state coordinated spear-phishing campaign masquerading as the AICTE Approval Bureau. "
            "Threat actors distribute weaponized intake audit notices from AS49870 bulletproof infrastructure. "
            "All 3 observed incidents share high SimHash text similarity (>96%) and identical call-to-action structures."
        ),
        cluster_type="COMPOSITE_ASN_SIMHASH",
        cluster_key="ASN49870:SIMHASH_8f3c7a",
        severity="CRITICAL",
        first_seen=now - timedelta(days=3),
        last_seen=now - timedelta(hours=3),
        total_emails=3,
        campaign_metadata={
            "threat_actor": "UNC-3841 / Russian-based Bulletproof Cluster",
            "origin_asn": 49870,
            "origin_asn_org": "Alservice Ltd",
            "shared_simhash_prefix": "0x8f3c7a",
            "targeted_institutes": [
                "COEP Technological University (Maharashtra)",
                "RV College of Engineering (Karnataka)",
                "Delhi Technological University (Delhi)",
            ],
            "mitre_attack_techniques": ["T1566.002", "T1584.004", "T1036.007"],
        },
    )
    session.add(campaign_5)
    counts["campaigns"] += 1

    # 3 Cluster Emails (COEP, RVCE, DTU)
    cluster_targets = [
        {
            "tag": "5A",
            "inst_name": "COEP Technological University, Pune",
            "recipient": "director@coep.ac.in",
            "ip": "194.36.191.12",
            "simhash": "0x8f3c7a1029e5b4c1",
            "sim_score": 0.98,
            "inst_code": "MH-COEP-001",
            "time_offset_hours": 18,
            "threat_score": 92.0,
        },
        {
            "tag": "5B",
            "inst_name": "RV College of Engineering, Bengaluru",
            "recipient": "dean.academic@rvce.edu.in",
            "ip": "194.36.191.18",
            "simhash": "0x8f3c7a1029e5b4c4",
            "sim_score": 0.97,
            "inst_code": "KA-RVCE-004",
            "time_offset_hours": 11,
            "threat_score": 93.0,
        },
        {
            "tag": "5C",
            "inst_name": "Delhi Technological University, Delhi",
            "recipient": "registrar@dtu.ac.in",
            "ip": "194.36.191.24",
            "simhash": "0x8f3c7a1029e5b4c7",
            "sim_score": 0.96,
            "inst_code": "DL-DTU-012",
            "time_offset_hours": 4,
            "threat_score": 91.0,
        },
    ]

    for item in cluster_targets:
        c5_date = now - timedelta(hours=item["time_offset_hours"])
        c5_date_str = c5_date.strftime("%a, %d %b %Y %H:%M:%S +0000")
        c5_msg_id = f"20261031-{item['inst_code']}@aicte-compliance-gov.com"
        c5_subject = f"Urgent: Mandatory Compliance Audit of AICTE Approved Intake 2026-27 - {item['inst_name']}"
        c5_sender_raw = '"AICTE Compliance Directorate" <audit-desk@aicte-compliance-gov.com>'
        c5_sender_email = "audit-desk@aicte-compliance-gov.com"
        c5_sender_display = "AICTE Compliance Directorate"
        c5_return_path = "bounce@aicte-compliance-gov.com"
        c5_reply_to = "audit-desk@aicte-compliance-gov.com"

        c5_body_plain = (
            f"AICTE AUDIT & COMPLIANCE DIRECTORATE\n"
            f"TARGET INSTITUTION: {item['inst_name']} [{item['inst_code']}]\n\n"
            f"Notice of Immediate Sanctioned Intake Discrepancy:\n"
            f"During the automated cross-verification of faculty biometric attendance records and\n"
            f"student roll strength, anomalous discrepancy patterns were flagged for the 2026-27 academic cycle.\n\n"
            f"To prevent immediate freezing of your AICTE approval portal, your institution must submit\n"
            f"the audit compliance dossier through our high-speed secured submission server:\n\n"
            f"https://aicte-compliance-gov.com/portal/audit-response.php?inst={item['inst_code']}\n\n"
            f"Compliance deadline: 24 hours from receipt.\n"
            f"Director of Institutional Compliance, AICTE"
        )

        c5_body_html = (
            f"<html><body>"
            f"<h3>AICTE Compliance Directorate - Immediate Audit Notice</h3>"
            f"<p><strong>Target: {item['inst_name']}</strong></p>"
            f"<p>Intake discrepancies detected. Submit your verified faculty roster at:</p>"
            f"<p><a href='https://aicte-compliance-gov.com/portal/audit-response.php?inst={item['inst_code']}'>"
            f"Upload Audit Compliance Dossier ({item['inst_code']})</a></p>"
            f"</body></html>"
        )

        c5_received = [
            f"from mail.{item['recipient'].split('@')[1]} (10.0.0.1) by mx.{item['recipient'].split('@')[1]} with ESMTP id clus-881; {c5_date_str}",
            f"from vps-node.alservice.ru ({item['ip']}) by edge.inbound.net with ESMTPS id vps-901; {c5_date_str}",
        ]
        c5_auth_results = (
            f"edge.inbound.net; spf=softfail (aicte-compliance-gov.com: {item['ip']} is neither permitted nor denied) "
            f"smtp.mailfrom=bounce@aicte-compliance-gov.com; dkim=none; "
            f"dmarc=fail (p=none) header.from=aicte-compliance-gov.com"
        )

        c5_raw = create_rfc822_raw_eml(
            msg_id=c5_msg_id,
            date_str=c5_date_str,
            from_header=c5_sender_raw,
            to_header=item["recipient"],
            subject=c5_subject,
            reply_to=c5_reply_to,
            return_path=c5_return_path,
            received_headers=c5_received,
            auth_results=c5_auth_results,
            body_text=c5_body_plain,
            body_html=c5_body_html,
        )
        c5_sha256, c5_md5, c5_vault_path, c5_size = store_raw_evidence(
            c5_raw, f"falconshield_{item['tag'].lower()}_{item['inst_code']}.eml"
        )

        email_c5 = Email(
            id=uuid.uuid4(),
            sha256_hash=c5_sha256,
            md5_hash=c5_md5,
            file_name=f"falconshield_{item['tag'].lower()}_{item['inst_code']}.eml",
            file_size_bytes=c5_size,
            raw_storage_path=c5_vault_path,
            rfc822_msg_id=c5_msg_id,
            subject=c5_subject,
            sender_raw=c5_sender_raw,
            sender_email=c5_sender_email,
            sender_display=c5_sender_display,
            return_path=c5_return_path,
            reply_to=c5_reply_to,
            recipient_list=[item["recipient"]],
            date_header=c5_date,
            body_plain=c5_body_plain,
            body_html=c5_body_html,
            simhash_body=item["simhash"],
            ingested_at=now - timedelta(hours=item["time_offset_hours"]),
        )
        session.add(email_c5)
        counts["emails"] += 1

        # Header Hop from AS49870 bulletproof VPS
        hop_c5 = HeaderHop(
            id=uuid.uuid4(),
            email_id=email_c5.id,
            hop_order=1,
            by_mta=f"mx.{item['recipient'].split('@')[1]}",
            from_mta="vps-node.alservice.ru",
            hop_ip=item["ip"],
            is_private_ip=False,
            is_reliable=True,
            protocol="ESMTPS",
            hop_timestamp=c5_date,
            delay_seconds=0.4,
            geo_country="Russia",
            geo_city="Moscow",
            geo_lat=55.7558,
            geo_lon=37.6173,
            asn_number=49870,
            asn_org="Alservice Ltd",
            node_type="ORIGINATING",
            is_tor=False,
            is_vpn=False,
            is_datacenter=True,
        )
        session.add(hop_c5)
        counts["hops"] += 1

        # Forensic Analysis
        fa_c5 = ForensicAnalysis(
            id=uuid.uuid4(),
            email_id=email_c5.id,
            spf_status="SOFTFAIL",
            spf_domain="aicte-compliance-gov.com",
            dkim_status="NONE",
            dkim_selector=None,
            dkim_domain=None,
            dmarc_status="FAIL",
            dmarc_policy="none",
            dmarc_alignment_spf=False,
            dmarc_alignment_dkim=False,
            display_spoof_flag=True,
            lookalike_flag=True,
            homograph_flag=False,
            threat_score=item["threat_score"],
            verdict="MALICIOUS",
            score_breakdown={
                "bulletproof_asn_penalty": 35.0,
                "campaign_cluster_penalty": 30.0,
                "auth_failure_penalty": 16.0,
                "nlp_extortion_coercion": 11.0,
                "reasons": [
                    "Originating IP belongs to high-risk bulletproof hosting ASN (AS49870 Alservice Ltd)",
                    "Clustered into Operation FalconShield via shared SimHash and subnet infrastructure",
                    "Fake government compliance domain: aicte-compliance-gov.com",
                ],
            },
        )
        session.add(fa_c5)
        counts["analyses"] += 1

        # IOCs
        ioc_ip = ThreatIndicator(
            id=uuid.uuid4(),
            email_id=email_c5.id,
            ioc_type="IP",
            ioc_value=item["ip"],
            context="HEADER_RECEIVED",
            is_defanged=False,
            domain_age_days=None,
            registrar="RIPE NCC",
            reputation_score=95.0,
            ioc_metadata={"asn": 49870, "asn_org": "Alservice Ltd", "datacenter": True, "country": "RU"},
        )
        ioc_url = ThreatIndicator(
            id=uuid.uuid4(),
            email_id=email_c5.id,
            ioc_type="URL",
            ioc_value=f"hxxps://aicte-compliance-gov[.]com/portal/audit-response[.]php?inst={item['inst_code']}",
            context="EMAIL_BODY",
            is_defanged=True,
            domain_age_days=2,
            registrar="Reg.ru LLC",
            reputation_score=96.0,
            ioc_metadata={"campaign": "Operation FalconShield", "targeted_inst": item["inst_name"]},
        )
        ioc_domain = ThreatIndicator(
            id=uuid.uuid4(),
            email_id=email_c5.id,
            ioc_type="DOMAIN",
            ioc_value="aicte-compliance-gov.com",
            context="SENDER",
            is_defanged=False,
            domain_age_days=2,
            registrar="Reg.ru LLC",
            reputation_score=95.0,
            ioc_metadata={"campaign_pivot": True},
        )
        session.add_all([ioc_ip, ioc_url, ioc_domain])
        counts["iocs"] += 3

        # Campaign Association
        campaign_assoc = CampaignEmail(
            id=uuid.uuid4(),
            campaign_id=campaign_5.id,
            email_id=email_c5.id,
            similarity_score=item["sim_score"],
            matched_criteria={
                "shared_asn": 49870,
                "shared_domain": "aicte-compliance-gov.com",
                "simhash_prefix": "0x8f3c7a",
                "template_match": "aicte_compliance_audit_v2",
            },
            associated_at=now - timedelta(hours=item["time_offset_hours"]),
        )
        session.add(campaign_assoc)
        counts["campaign_emails"] += 1

        # Audit Log
        session.add(
            create_sealed_audit_log(
                email_id=email_c5.id,
                action="CHAIN_OF_CUSTODY_CHECK",
                actor="CAMPAIGN_CORRELATION_ENGINE",
                recorded_at=now - timedelta(hours=item["time_offset_hours"]),
                evidence_sha256=c5_sha256,
                details={
                    "campaign": campaign_5.name,
                    "target": item["inst_name"],
                    "similarity": item["sim_score"],
                },
            )
        )
        counts["audit_logs"] += 1

    # Commit all seed data in single transaction
    await session.commit()
    logger.info("Forensic mock data successfully seeded: %s", counts)
    return counts


async def main() -> None:
    """Standalone entry point for database seeding."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    async with async_session_factory() as session:
        # Check if already seeded to avoid duplicate primary key collisions
        result = await session.execute(select(Email).limit(1))
        existing = result.scalar_one_or_none()
        if existing:
            print("[INFO] Database already contains records. Run with --reset to repopulate.")
            return

        counts = await seed_forensic_database(session)
        print(f"[SUCCESS] Seeded database with forensic cases: {counts}")


if __name__ == "__main__":
    asyncio.run(main())
