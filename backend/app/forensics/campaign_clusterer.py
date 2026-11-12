"""Dynamic Campaign Clustering and Multi-Incident Infrastructure Correlation Engine.

Correlates incoming emails in real-time across:
1. Locality-Sensitive SimHash Hamming distance (< 10 bits = near-duplicate template; <= 5 = deterministic)
2. Network Infrastructure Overlap (non-fanout ASN, shared /24 subnet)
3. Sender Attribution and Diversion Telemetry (shared Reply-To, shared non-public domain)
4. Threat Indicator (IOC) Overlap (shared phishing URLs, domains, and attachment hashes)
5. Multi-Signal Gate: Requires >= 2 independent signals OR deterministic template/attachment link.
   Explicitly filters high-fanout hyperscalers (Google AS15169, AWS AS16509, Microsoft AS8075, Cloudflare AS13335).
6. Standards-Compliant STIX 2.1 Threat Intelligence Bundle Generation (OASIS CTI Standard).
"""

from __future__ import annotations

import ipaddress
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.app.core.config import settings
from backend.app.database.models import Campaign, CampaignEmail, Email
from backend.app.parsers.mime_normalizer import compute_hamming_distance

logger = logging.getLogger("campaign_clusterer")

SIMHASH_THRESHOLD_BITS = 10
SIMHASH_DETERMINISTIC_BITS = 5


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


def is_high_fanout_asn(asn: Optional[int], asn_org: Optional[str] = None) -> bool:
    """Determine if an ASN belongs to a hyperscaler, CDN, or transit provider where shared ASN is uninformative."""
    if not asn:
        return False
    if asn in settings.HIGH_FANOUT_ASNS:
        return True
    if asn_org:
        org_lower = asn_org.lower()
        if any(pat in org_lower for pat in settings.HIGH_FANOUT_ASN_PATTERNS):
            return True
    return False


def extract_email_ioc_values(em: Email) -> Set[str]:
    """Extract set of normalized IOC values without triggering lazy loading."""
    vals: Set[str] = set()
    if "threat_indicators" in em.__dict__:
        indicators = em.__dict__["threat_indicators"]
        if indicators:
            for ioc in indicators:
                if ioc and hasattr(ioc, "ioc_value") and ioc.ioc_value:
                    vals.add(ioc.ioc_value.strip().lower())
    return vals


def evaluate_pairwise_signals(
    email: Email,
    origin_ip: Optional[str],
    origin_asn: Optional[int],
    prev: Email,
    prev_ip: Optional[str],
    prev_asn: Optional[int],
    prev_asn_org: Optional[str] = None,
    cur_iocs: Optional[Set[str]] = None,
) -> Tuple[List[str], float, bool]:
    """Evaluate pairwise correlation between candidate email and previous email.

    Enforces forensic rigor:
    - SimHash <= 5 bits: Deterministic near-duplicate template link.
    - Shared attachment SHA-256 / IOC: Deterministic indicator link.
    - High-fanout ASNs (Google, AWS, MS, Cloudflare): Completely filtered out as links.
    - All other features: Require >= 2 independent signals to cluster.

    Returns:
        (signals_list, composite_similarity_score, is_clustered)
    """
    signals: List[str] = []
    scores: List[float] = []
    matched_families: Set[str] = set()
    is_deterministic = False

    # 1. Family: TEMPLATE (SimHash Locality-Sensitive Hashing)
    if email.simhash_body and prev.simhash_body:
        dist = compute_hamming_distance(email.simhash_body, prev.simhash_body)
        if dist <= SIMHASH_DETERMINISTIC_BITS:
            signals.append(f"SimHash near-duplicate template (distance: {dist} bits)")
            scores.append(1.0 - (dist / 64.0))
            matched_families.add("TEMPLATE")
            is_deterministic = True
        elif dist <= SIMHASH_THRESHOLD_BITS:
            signals.append(f"SimHash template overlap (distance: {dist} bits)")
            scores.append(1.0 - (dist / 64.0))
            matched_families.add("TEMPLATE")

    # 2. Family: IOC (Shared Indicators of Compromise: URLs, Domains, Attachments)
    if cur_iocs is None:
        cur_iocs = extract_email_ioc_values(email)
    prev_iocs = extract_email_ioc_values(prev)
    shared_iocs = cur_iocs.intersection(prev_iocs)
    if shared_iocs:
        for ioc in list(shared_iocs)[:3]:
            signals.append(f"Shared threat indicator: {ioc[:40]}")
        scores.append(0.95)
        matched_families.add("IOC")
        is_deterministic = True

    # 3. Family: NETWORK (Non-Fanout ASN or Subnet - collinear features from same family)
    has_network_match = False
    if origin_asn and prev_asn and origin_asn == prev_asn:
        if is_high_fanout_asn(origin_asn, prev_asn_org):
            logger.debug("Filtered high-fanout ASN AS%s from correlation candidate", origin_asn)
        else:
            signals.append(f"Shared non-fanout infrastructure ASN: AS{origin_asn}")
            scores.append(0.85)
            has_network_match = True

    cur_subnet = extract_subnet_24(origin_ip)
    prev_subnet = extract_subnet_24(prev_ip)
    if cur_subnet and prev_subnet and cur_subnet == prev_subnet:
        if not is_high_fanout_asn(origin_asn, prev_asn_org):
            signals.append(f"Shared network subnet: {cur_subnet}")
            scores.append(0.85)
            has_network_match = True

    if has_network_match:
        matched_families.add("NETWORK")

    # 4. Family: ATTRIBUTION (Shared Reply-To or Threat Actor Sender Domain)
    has_attribution_match = False
    if email.reply_to and prev.reply_to:
        r1 = email.reply_to.strip().lower()
        r2 = prev.reply_to.strip().lower()
        if r1 == r2 and r1:
            signals.append(f"Shared diversion Reply-To: {r1}")
            scores.append(0.95)
            has_attribution_match = True

    dom1 = (
        email.sender_email.split("@")[-1].lower()
        if email.sender_email and "@" in email.sender_email
        else ""
    )
    dom2 = (
        prev.sender_email.split("@")[-1].lower()
        if prev.sender_email and "@" in prev.sender_email
        else ""
    )
    if dom1 and dom2 and dom1 == dom2:
        if dom1 not in settings.PUBLIC_MAIL_DOMAINS:
            signals.append(f"Shared threat actor sender domain: {dom1}")
            scores.append(0.88)
            has_attribution_match = True

    if has_attribution_match:
        matched_families.add("ATTRIBUTION")

    avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
    # Multi-Signal Rule: Deterministic link OR >= 2 independent feature families
    is_clustered = is_deterministic or (len(matched_families) >= 2)
    return signals, avg_score, is_clustered


async def cluster_email_dynamically(
    db: AsyncSession,
    email: Email,
    origin_ip: Optional[str] = None,
    origin_asn: Optional[int] = None,
    detected_vip: Optional[str] = None,
    threat_score: float = 0.0,
    candidate_iocs: Optional[Set[str]] = None,
) -> Optional[Campaign]:
    """Dynamically correlate a newly ingested email with existing campaigns or spawn a new cluster."""
    now_utc = datetime.now(timezone.utc)
    if candidate_iocs is None:
        candidate_iocs = extract_email_ioc_values(email)

    # 1. Inspect existing active campaigns
    camp_stmt = select(Campaign).options(
        selectinload(Campaign.email_associations)
        .selectinload(CampaignEmail.email)
        .selectinload(Email.header_hops),
        selectinload(Campaign.email_associations)
        .selectinload(CampaignEmail.email)
        .selectinload(Email.threat_indicators),
    ).order_by(Campaign.last_seen.desc())
    camp_res = await db.execute(camp_stmt)
    existing_campaigns = camp_res.scalars().all()

    matched_campaign: Optional[Campaign] = None
    match_criteria: List[str] = []
    similarity_score = 0.0

    for camp in existing_campaigns:
        # Check against member emails in this campaign
        for assoc in camp.email_associations:
            member = assoc.email
            if not member or member.id == email.id:
                continue

            member_first_hop = member.header_hops[0] if member.header_hops else None
            m_ip = member_first_hop.hop_ip if member_first_hop else None
            m_asn = member_first_hop.asn_number if member_first_hop else None
            m_org = member_first_hop.asn_org if member_first_hop else None

            signals, score, is_clustered = evaluate_pairwise_signals(
                email=email,
                origin_ip=origin_ip,
                origin_asn=origin_asn,
                prev=member,
                prev_ip=m_ip,
                prev_asn=m_asn,
                prev_asn_org=m_org,
                cur_iocs=candidate_iocs,
            )

            if is_clustered:
                matched_campaign = camp
                match_criteria = signals
                similarity_score = score
                break

        if matched_campaign:
            break

    # 2. If matched existing campaign, update metrics and associate
    if matched_campaign:
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
        .options(
            selectinload(Email.header_hops),
            selectinload(Email.threat_indicators),
        )
        .where(Email.id != email.id)
        .order_by(Email.ingested_at.desc())
        .limit(100)
    )
    hist_res = await db.execute(hist_stmt)
    historical_emails = hist_res.scalars().all()

    correlated_emails: List[Tuple[Email, List[str], float]] = []

    for prev in historical_emails:
        prev_first_hop = prev.header_hops[0] if prev.header_hops else None
        prev_asn = prev_first_hop.asn_number if prev_first_hop else None
        prev_asn_org = prev_first_hop.asn_org if prev_first_hop else None
        prev_ip = prev_first_hop.hop_ip if prev_first_hop else None

        signals, score, is_clustered = evaluate_pairwise_signals(
            email=email,
            origin_ip=origin_ip,
            origin_asn=origin_asn,
            prev=prev,
            prev_ip=prev_ip,
            prev_asn=prev_asn,
            prev_asn_org=prev_asn_org,
            cur_iocs=candidate_iocs,
        )

        if is_clustered:
            correlated_emails.append((prev, signals, score))

    # 4. If 1 or more previous emails correlate, spawn a brand new dynamic Campaign!
    if correlated_emails:
        primary_match, primary_signals, primary_score = correlated_emails[0]
        primary_signals_text = "; ".join(primary_signals)

        # Determine tactical campaign name and pivot key
        if any("SimHash" in s for s in primary_signals):
            cluster_type = "SIMHASH"
            cluster_key = email.simhash_body or "0x0"
            camp_name = f"Operation Template-Cluster-{cluster_key[:8]}"
        elif any("Reply-To" in s for s in primary_signals):
            cluster_type = "REPLY_TO"
            cluster_key = email.reply_to.strip().lower() if email.reply_to else "ReplyTo"
            camp_name = f"Operation Webmail-Divergence-{cluster_key.split('@')[0]}"
        elif any("non-fanout" in s for s in primary_signals):
            cluster_type = "INFRASTRUCTURE"
            cluster_key = f"AS{origin_asn}"
            camp_name = f"Operation Infrastructure-AS{origin_asn}"
        elif any("indicator" in s for s in primary_signals):
            cluster_type = "MULTI_SIGNAL"
            cluster_key = f"IOC-{uuid.uuid4().hex[:8]}"
            camp_name = f"Operation Threat-Indicator-{cluster_key[:12]}"
        else:
            cluster_type = "MULTI_SIGNAL"
            cluster_key = f"MULTI-{uuid.uuid4().hex[:8]}"
            camp_name = f"Operation Coordinated-Threat-{cluster_key[:10]}"

        new_campaign = Campaign(
            id=uuid.uuid4(),
            name=camp_name,
            description=f"Automated threat cluster correlated dynamically via {primary_signals_text}",
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
                "correlated_signals": primary_signals,
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
                matched_criteria=primary_signals_text,
            )
        )

        # Add correlated previous emails
        for prev_em, r_signals, r_score in correlated_emails:
            db.add(
                CampaignEmail(
                    id=uuid.uuid4(),
                    campaign_id=new_campaign.id,
                    email_id=prev_em.id,
                    similarity_score=round(r_score, 2),
                    matched_criteria="; ".join(r_signals),
                )
            )

        return new_campaign

    return None


def generate_stix21_bundle(
    campaign: Campaign,
    emails: List[Email],
) -> Dict[str, Any]:
    """Generate an authoritative, RFC-compliant STIX 2.1 Threat Intelligence JSON Bundle.

    Strictly compliant with OASIS STIX 2.1 specification:
    - SDOs (threat-actor, campaign, indicator) have spec_version, created, modified.
    - SCOs (email-message, email-addr, ipv4-addr, ipv6-addr) omit created/modified.
    - References between SCOs and SDOs are fully resolved without dangling pointers.
    """
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
        # Create Email Address SCO for Sender
        sender_email_val = em.sender_email or "unknown@domain.local"
        sender_addr_id = f"email-addr--{uuid.uuid5(uuid.NAMESPACE_DNS, sender_email_val)}"
        objects.append({
            "type": "email-addr",
            "spec_version": "2.1",
            "id": sender_addr_id,
            "value": sender_email_val,
        })

        # Email Message SCO (STIX 2.1 SCO does not contain created/modified)
        em_msg_id = f"email-message--{uuid.uuid4()}"
        objects.append({
            "type": "email-message",
            "spec_version": "2.1",
            "id": em_msg_id,
            "is_multipart": False,
            "subject": em.subject or "Threat Email",
            "from_ref": sender_addr_id,
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

        # Infrastructure IPs (SCO)
        for h in em.header_hops:
            if h.hop_ip and (h.hop_order == 1 or h.is_tor or h.is_datacenter):
                ip_type = "ipv6-addr" if ":" in h.hop_ip else "ipv4-addr"
                ip_sco_id = f"{ip_type}--{uuid.uuid5(uuid.NAMESPACE_DNS, h.hop_ip)}"
                objects.append({
                    "type": ip_type,
                    "spec_version": "2.1",
                    "id": ip_sco_id,
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
                    "target_ref": ip_sco_id,
                })

        # Indicators (SDO)
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
        "objects": objects,
    }
