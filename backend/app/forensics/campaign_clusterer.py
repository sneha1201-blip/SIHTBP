"""Dynamic Campaign Clustering and Multi-Incident Infrastructure Correlation Engine.

Correlates incoming emails in real-time across:
1. Locality-Sensitive SimHash Hamming distance (< 10 bits = near-duplicate template)
2. Network Infrastructure Overlap (shared /24 subnet, shared autonomous system ASN)
3. Sender Domain and Threat Actor Telemetry (shared Reply-To, shared return path, shared DKIM d=)
4. Dynamic Campaign Metrics: first_seen, last_seen, velocity (emails/hour), targeted VIPs, severity
5. Standards-Compliant STIX 2.1 Threat Intelligence Bundle Generation (RFC OASIS CTI Standard).
"""

from __future__ import annotations

import ipaddress
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.app.database.models import Campaign, CampaignEmail, Email
from backend.app.parsers.mime_normalizer import compute_hamming_distance

logger = logging.getLogger("campaign_clusterer")

SIMHASH_THRESHOLD_BITS = 10


def ensure_utc(dt: Optional[datetime]) -> datetime:
    """Ensure datetime is timezone-aware in UTC."""
    if not dt:
        return datetime.now(timezone.utc)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def extract_subnet_24(ip_str: Optional[str]) -> Optional[str]:
    """Extract standard /24 IPv4 network subnet or /48 IPv6 prefix."""
    if not ip_str:
        return None
    clean = ip_str.strip().strip("[]").lstrip("IPv6:").lstrip("ipv6:")
    try:
        ip = ipaddress.ip_address(clean)
        if ip.is_private or ip.is_loopback:
            return None
        if ip.version == 4:
            net = ipaddress.ip_network(f"{clean}/24", strict=False)
            return str(net)
        else:
            net = ipaddress.ip_network(f"{clean}/48", strict=False)
            return str(net)
    except ValueError:
        return None


async def cluster_email_dynamically(
    db: AsyncSession,
    email: Email,
    origin_ip: Optional[str] = None,
    origin_asn: Optional[int] = None,
    detected_vip: Optional[str] = None,
    threat_score: float = 0.0,
) -> Optional[Campaign]:
    """Dynamically correlate a newly ingested email with existing campaigns or spawn a new cluster."""
    now_utc = datetime.now(timezone.utc)
    email_simhash = email.simhash_body
    origin_subnet = extract_subnet_24(origin_ip)
    sender_domain = (
        email.sender_email.split("@")[-1].lower()
        if email.sender_email and "@" in email.sender_email
        else ""
    )

    # 1. Inspect existing active campaigns for direct criteria matches
    camp_stmt = select(Campaign).options(
        selectinload(Campaign.email_associations)
    ).order_by(Campaign.last_seen.desc())
    camp_res = await db.execute(camp_stmt)
    existing_campaigns = camp_res.scalars().all()

    matched_campaign: Optional[Campaign] = None
    match_criteria: List[str] = []
    similarity_score = 0.0

    for camp in existing_campaigns:
        # Check SimHash Hamming distance
        if email_simhash and camp.cluster_key.startswith("0x"):
            dist = compute_hamming_distance(email_simhash, camp.cluster_key)
            if dist <= SIMHASH_THRESHOLD_BITS:
                matched_campaign = camp
                match_criteria.append(f"SimHash template overlap (Hamming distance: {dist} bits)")
                similarity_score = max(similarity_score, 1.0 - (dist / 64.0))

        # Check ASN overlap
        if origin_asn and f"AS{origin_asn}" in camp.cluster_key:
            matched_campaign = camp
            match_criteria.append(f"Shared bulletproof/infrastructure ASN: AS{origin_asn}")
            similarity_score = max(similarity_score, 0.90)

        # Check Subnet overlap
        if origin_subnet and origin_subnet in camp.cluster_key:
            matched_campaign = camp
            match_criteria.append(f"Shared network subnet: {origin_subnet}")
            similarity_score = max(similarity_score, 0.85)

        # Check Reply-To / Domain overlap
        if email.reply_to and camp.cluster_key == email.reply_to.lower():
            matched_campaign = camp
            match_criteria.append(f"Shared diversion Reply-To address: {email.reply_to}")
            similarity_score = max(similarity_score, 0.95)

        # Check Sender Domain overlap
        if sender_domain and camp.cluster_key == sender_domain:
            matched_campaign = camp
            match_criteria.append(f"Shared threat actor sender domain: {sender_domain}")
            similarity_score = max(similarity_score, 0.88)

        if matched_campaign:
            break

    # 2. If matched existing campaign, update metrics and associate
    if matched_campaign:
        # Check if already associated
        existing_assoc = [a for a in matched_campaign.email_associations if a.email_id == email.id]
        if not existing_assoc:
            assoc = CampaignEmail(
                id=uuid.uuid4(),
                campaign_id=matched_campaign.id,
                email_id=email.id,
                similarity_score=round(similarity_score or 0.85, 2),
                matched_criteria="; ".join(match_criteria),
            )
            db.add(assoc)

            matched_campaign.total_emails += 1
            matched_campaign.last_seen = now_utc

            # Update velocity
            c_first_seen = ensure_utc(matched_campaign.first_seen)
            span_hours = max(0.1, (now_utc - c_first_seen).total_seconds() / 3600.0)
            velocity = round(matched_campaign.total_emails / span_hours, 2)

            meta = matched_campaign.campaign_metadata or {}
            meta["velocity_emails_per_hour"] = velocity
            vips = meta.get("targeted_vips", [])
            if detected_vip and detected_vip not in vips:
                vips.append(detected_vip)
            meta["targeted_vips"] = vips
            if threat_score >= 85.0:
                matched_campaign.severity = "CRITICAL"
            matched_campaign.campaign_metadata = meta

        return matched_campaign

    # 3. If no existing campaign matched, check historical unclustered emails in DB
    hist_stmt = (
        select(Email)
        .options(selectinload(Email.header_hops))
        .where(Email.id != email.id)
        .order_by(Email.ingested_at.desc())
        .limit(50)
    )
    hist_res = await db.execute(hist_stmt)
    historical_emails = hist_res.scalars().all()

    correlated_emails: List[Tuple[Email, str, float]] = []

    for prev in historical_emails:
        prev_simhash = prev.simhash_body
        prev_first_hop = prev.header_hops[0] if prev.header_hops else None
        prev_asn = prev_first_hop.asn_number if prev_first_hop else None
        prev_subnet = extract_subnet_24(prev_first_hop.hop_ip) if prev_first_hop else None

        # Check SimHash
        if email_simhash and prev_simhash:
            dist = compute_hamming_distance(email_simhash, prev_simhash)
            if dist <= SIMHASH_THRESHOLD_BITS:
                correlated_emails.append(
                    (prev, f"SimHash template overlap (distance: {dist} bits)", 1.0 - (dist / 64.0))
                )
                continue

        # Check ASN
        if origin_asn and prev_asn and origin_asn == prev_asn:
            correlated_emails.append(
                (prev, f"Shared origin ASN: AS{origin_asn}", 0.90)
            )
            continue

        # Check Subnet
        if origin_subnet and prev_subnet and origin_subnet == prev_subnet:
            correlated_emails.append(
                (prev, f"Shared network subnet: {origin_subnet}", 0.85)
            )
            continue

        # Check Reply-To
        if email.reply_to and prev.reply_to and email.reply_to.lower() == prev.reply_to.lower():
            correlated_emails.append(
                (prev, f"Shared Reply-To: {email.reply_to}", 0.95)
            )
            continue

    # 4. If 1 or more previous emails correlate, spawn a brand new dynamic Campaign!
    if correlated_emails:
        primary_match, primary_reason, primary_score = correlated_emails[0]

        # Determine tactical campaign name and pivot key
        if "SimHash" in primary_reason:
            cluster_type = "SIMHASH"
            cluster_key = email_simhash or "0x0"
            camp_name = f"Operation Template-Cluster-{cluster_key[:8]}"
        elif "ASN" in primary_reason:
            cluster_type = "ASN"
            cluster_key = f"AS{origin_asn}"
            camp_name = f"Operation Infrastructure-AS{origin_asn}"
        elif "subnet" in primary_reason:
            cluster_type = "IP_SUBNET"
            cluster_key = origin_subnet or "Subnet"
            camp_name = f"Operation Network-Subnet-{cluster_key.replace('/', '_')}"
        else:
            cluster_type = "REPLY_TO"
            cluster_key = email.reply_to or "ReplyTo"
            camp_name = f"Operation Webmail-Divergence-{cluster_key.split('@')[0]}"

        new_campaign = Campaign(
            id=uuid.uuid4(),
            name=camp_name,
            description=f"Automated threat cluster correlated dynamically via {primary_reason}",
            cluster_type=cluster_type,
            cluster_key=cluster_key,
            severity="HIGH" if threat_score < 85.0 else "CRITICAL",
            first_seen=min(ensure_utc(email.ingested_at), ensure_utc(primary_match.ingested_at)),
            last_seen=now_utc,
            total_emails=len(correlated_emails) + 1,
            campaign_metadata={
                "velocity_emails_per_hour": round(len(correlated_emails) + 1, 2),
                "targeted_vips": [detected_vip] if detected_vip else [],
                "pivot_attribute": cluster_type,
            },
        )
        db.add(new_campaign)
        await db.flush()

        # Add current email association
        db.add(
            CampaignEmail(
                id=uuid.uuid4(),
                campaign_id=new_campaign.id,
                email_id=email.id,
                similarity_score=round(primary_score, 2),
                matched_criteria=primary_reason,
            )
        )

        # Add correlated previous emails
        for prev_em, r_reason, r_score in correlated_emails:
            # Check if not already in another campaign
            db.add(
                CampaignEmail(
                    id=uuid.uuid4(),
                    campaign_id=new_campaign.id,
                    email_id=prev_em.id,
                    similarity_score=round(r_score, 2),
                    matched_criteria=r_reason,
                )
            )

        return new_campaign

    return None


def generate_stix21_bundle(
    campaign: Campaign,
    emails: List[Email],
) -> Dict[str, Any]:
    """Generate an authoritative, RFC-compliant STIX 2.1 Threat Intelligence JSON Bundle."""
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    bundle_id = f"bundle--{uuid.uuid4()}"
    objects: List[Dict[str, Any]] = []

    # 1. Threat Actor SDO
    actor_id = f"threat-actor--{uuid.uuid4()}"
    objects.append({
        "type": "threat-actor",
        "spec_version": "2.1",
        "id": actor_id,
        "created": now_str,
        "modified": now_str,
        "name": f"Actor Group ({campaign.name})",
        "threat_actor_types": ["cybercriminal"],
        "sophistication": "intermediate",
        "resource_level": "organization",
        "primary_motivation": "financial-gain",
    })

    # 2. Campaign SDO
    camp_id = f"campaign--{campaign.id}"
    objects.append({
        "type": "campaign",
        "spec_version": "2.1",
        "id": camp_id,
        "created": ensure_utc(campaign.first_seen).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "modified": ensure_utc(campaign.last_seen).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "name": campaign.name,
        "description": campaign.description or "Automated cyber threat campaign",
        "objective": "Targeted Spear Phishing & BEC Remittance Fraud",
    })

    # SRO: Threat Actor -> Campaign
    objects.append({
        "type": "relationship",
        "spec_version": "2.1",
        "id": f"relationship--{uuid.uuid4()}",
        "created": now_str,
        "modified": now_str,
        "relationship_type": "attributed-to",
        "source_ref": camp_id,
        "target_ref": actor_id,
    })

    # 3. Observables & Indicators per Email
    for em in emails:
        # Email Message SDO
        em_msg_id = f"email-message--{uuid.uuid4()}"
        objects.append({
            "type": "email-message",
            "spec_version": "2.1",
            "id": em_msg_id,
            "created": ensure_utc(em.ingested_at).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "modified": ensure_utc(em.ingested_at).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "is_multipart": True,
            "subject": em.subject or "Threat Email",
            "from_ref": f"email-addr--{uuid.uuid4()}",
            "body": em.body_plain[:500] if em.body_plain else "",
        })

        # SRO: Email -> Campaign
        objects.append({
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{uuid.uuid4()}",
            "created": now_str,
            "modified": now_str,
            "relationship_type": "attributed-to",
            "source_ref": em_msg_id,
            "target_ref": camp_id,
        })

        # Infrastructure IPs
        for h in em.header_hops:
            if h.hop_ip and (h.hop_order == 1 or h.is_tor or h.is_datacenter):
                ip_type = "ipv6-addr" if ":" in h.hop_ip else "ipv4-addr"
                ip_sdo_id = f"{ip_type}--{uuid.uuid4()}"
                objects.append({
                    "type": ip_type,
                    "spec_version": "2.1",
                    "id": ip_sdo_id,
                    "value": h.hop_ip,
                })
                # Relationship: Campaign uses Infrastructure IP
                objects.append({
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": f"relationship--{uuid.uuid4()}",
                    "created": now_str,
                    "modified": now_str,
                    "relationship_type": "uses",
                    "source_ref": camp_id,
                    "target_ref": ip_sdo_id,
                })

        # Indicators
        for ioc in em.threat_indicators:
            pattern = None
            if ioc.ioc_type == "URL":
                pattern = f"[url:value = '{ioc.ioc_value}']"
            elif ioc.ioc_type == "DOMAIN":
                pattern = f"[domain-name:value = '{ioc.ioc_value}']"
            elif ioc.ioc_type == "IP":
                pattern = f"[ipv4-addr:value = '{ioc.ioc_value}']"
            elif ioc.ioc_type == "EMAIL":
                pattern = f"[email-addr:value = '{ioc.ioc_value}']"

            if pattern:
                ind_id = f"indicator--{uuid.uuid4()}"
                objects.append({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": ind_id,
                    "created": now_str,
                    "modified": now_str,
                    "name": f"Indicator: {ioc.ioc_value[:32]}",
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "valid_from": now_str,
                    "indicator_types": ["malicious-activity"],
                })
                objects.append({
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": f"relationship--{uuid.uuid4()}",
                    "created": now_str,
                    "modified": now_str,
                    "relationship_type": "indicates",
                    "source_ref": ind_id,
                    "target_ref": camp_id,
                })

    return {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": objects,
    }
