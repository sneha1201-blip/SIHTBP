"""Campaign Clustering, Graph Telemetry, and STIX 2.1 API Endpoints.

Provides Cytoscape / D3.js compatible nodes and edges for visualizing multi-incident
infrastructure linkages, shared bulletproof ASNs, and SimHash body campaign clusters,
along with RFC-compliant STIX 2.1 threat intelligence bundle exports.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.app.core.security import require_any_authenticated, require_roles
from backend.app.database.audit_service import record_chained_audit_log
from backend.app.database.models import Campaign, CampaignEmail, Email, User, UserRole
from backend.app.database.session import get_db
from backend.app.forensics.campaign_clusterer import generate_stix21_bundle

router = APIRouter()


class CampaignLabelRequest(BaseModel):
    name: str
    description: Optional[str] = None
    threat_actor: Optional[str] = None


class CampaignMergeRequest(BaseModel):
    target_campaign_id: uuid.UUID


class CampaignSplitRequest(BaseModel):
    email_ids: List[uuid.UUID]
    new_campaign_name: str


@router.get("/")
async def list_campaigns(
    current_user: User = Depends(require_any_authenticated),
    db: AsyncSession = Depends(get_db),
) -> List[Dict[str, Any]]:
    """List all detected campaign clusters and attribution metrics."""
    stmt = (
        select(Campaign)
        .options(selectinload(Campaign.email_associations).selectinload(CampaignEmail.email))
        .order_by(Campaign.last_seen.desc())
    )
    result = await db.execute(stmt)
    campaigns = result.scalars().all()

    output = []
    for camp in campaigns:
        d = camp.to_dict()
        d["attributed_emails"] = [
            {
                "email_id": str(assoc.email_id),
                "subject": assoc.email.subject if assoc.email else "N/A",
                "sender_email": assoc.email.sender_email if assoc.email else "N/A",
                "similarity_score": assoc.similarity_score,
                "matched_criteria": assoc.matched_criteria,
            }
            for assoc in camp.email_associations
        ]
        output.append(d)
    return output


@router.get("/graph")
async def get_campaign_graph(
    min_threat_score: Optional[float] = Query(None, ge=0.0, le=100.0, description="Minimum threat score filter"),
    cluster_type: Optional[str] = Query(None, description="Cluster pivot type filter (ASN, SIMHASH, IP_SUBNET)"),
    current_user: User = Depends(require_any_authenticated),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Return nodes and edges representing threat campaign relationships for Cytoscape / D3 graph visualization."""
    stmt = (
        select(Campaign)
        .options(
            selectinload(Campaign.email_associations)
            .selectinload(CampaignEmail.email)
            .selectinload(Email.header_hops),
            selectinload(Campaign.email_associations)
            .selectinload(CampaignEmail.email)
            .selectinload(Email.threat_indicators),
            selectinload(Campaign.email_associations)
            .selectinload(CampaignEmail.email)
            .selectinload(Email.forensic_analysis),
        )
    )

    if cluster_type:
        stmt = stmt.where(Campaign.cluster_type == cluster_type)

    result = await db.execute(stmt)
    campaigns = result.scalars().all()

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    seen_node_ids = set()

    def add_node(node_id: str, label: str, node_type: str, metadata: dict | None = None):
        if node_id not in seen_node_ids:
            seen_node_ids.add(node_id)
            nodes.append({
                "id": node_id,
                "label": label,
                "type": node_type,
                "metadata": metadata or {},
            })

    def add_edge(source: str, target: str, relationship: str, metadata: dict | None = None):
        edge_id = f"{source}->{target}:{relationship}"
        edges.append({
            "id": edge_id,
            "source": source,
            "target": target,
            "relationship": relationship,
            "metadata": metadata or {},
        })

    for camp in campaigns:
        camp_node_id = f"campaign_{camp.id}"
        add_node(
            node_id=camp_node_id,
            label=camp.name[:32] + "..." if len(camp.name) > 32 else camp.name,
            node_type="CAMPAIGN",
            metadata={
                "cluster_type": camp.cluster_type,
                "cluster_key": camp.cluster_key,
                "severity": camp.severity,
                "total": camp.total_emails,
                "first_seen": camp.first_seen.isoformat(),
                "last_seen": camp.last_seen.isoformat(),
            },
        )

        for assoc in camp.email_associations:
            em = assoc.email
            if not em:
                continue

            fa = em.forensic_analysis
            em_score = fa.threat_score if fa else 0.0

            if min_threat_score is not None and em_score < min_threat_score:
                continue

            email_node_id = f"email_{em.id}"
            add_node(
                node_id=email_node_id,
                label=em.subject[:28] + "..." if em.subject and len(em.subject) > 28 else (em.subject or "Email"),
                node_type="EMAIL",
                metadata={
                    "sha256": em.sha256_hash,
                    "sender": em.sender_email,
                    "threat_score": em_score,
                    "verdict": fa.verdict if fa else "UNKNOWN",
                },
            )

            # Edge: Email -> Campaign (with explicit why-linked evidence)
            criteria_raw = assoc.matched_criteria
            if isinstance(criteria_raw, str):
                signals_list = [s.strip() for s in criteria_raw.split(";") if s.strip()]
                criteria_str = criteria_raw
            elif isinstance(criteria_raw, dict):
                if "signals" in criteria_raw and isinstance(criteria_raw["signals"], list):
                    signals_list = [str(s) for s in criteria_raw["signals"]]
                else:
                    signals_list = [f"{k}: {v}" for k, v in criteria_raw.items()]
                criteria_str = "; ".join(signals_list)
            else:
                signals_list = []
                criteria_str = ""

            add_edge(
                source=email_node_id,
                target=camp_node_id,
                relationship="CLUSTERED_INTO",
                metadata={
                    "similarity": assoc.similarity_score,
                    "criteria": criteria_str,
                    "signals": signals_list,
                },
            )

            # Node & Edge: Originating IP / ASN
            for h in em.header_hops:
                if h.hop_ip and (h.hop_order == 1 or h.is_tor or h.is_datacenter):
                    ip_node_id = f"ip_{h.hop_ip}"
                    add_node(
                        node_id=ip_node_id,
                        label=f"{h.hop_ip} (AS{h.asn_number or 'N/A'})",
                        node_type="INFRASTRUCTURE_IP",
                        metadata={"country": h.geo_country, "is_tor": h.is_tor, "asn_org": h.asn_org},
                    )
                    add_edge(source=email_node_id, target=ip_node_id, relationship="ORIGINATED_FROM")

            # Nodes & Edges: Threat Indicators
            for ioc in em.threat_indicators[:3]:
                ioc_node_id = f"ioc_{ioc.id}"
                add_node(
                    node_id=ioc_node_id,
                    label=f"{ioc.ioc_type}: {ioc.ioc_value[:24]}",
                    node_type="IOC",
                    metadata={"context": ioc.context, "reputation": ioc.reputation_score},
                )
                add_edge(source=email_node_id, target=ioc_node_id, relationship="EXTRACTED_IOC")

    return {
        "graph": {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "nodes": nodes,
            "edges": edges,
        }
    }


@router.get("/export/stix")
async def export_all_campaigns_stix(
    current_user: User = Depends(require_any_authenticated),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Export all attributed campaigns and associated observables as a STIX 2.1 bundle."""
    stmt = (
        select(Campaign)
        .options(
            selectinload(Campaign.email_associations)
            .selectinload(CampaignEmail.email)
            .selectinload(Email.header_hops),
            selectinload(Campaign.email_associations)
            .selectinload(CampaignEmail.email)
            .selectinload(Email.threat_indicators),
        )
    )
    res = await db.execute(stmt)
    campaigns = res.scalars().all()

    bundle_id = f"bundle--{uuid.uuid4()}"
    all_objects: List[Dict[str, Any]] = []

    for camp in campaigns:
        emails = [assoc.email for assoc in camp.email_associations if assoc.email]
        bundle = generate_stix21_bundle(camp, emails)
        all_objects.extend(bundle.get("objects", []))

    return {
        "type": "bundle",
        "id": bundle_id,
        "objects": all_objects,
    }


@router.get("/{campaign_id}/stix")
async def export_single_campaign_stix(
    campaign_id: uuid.UUID,
    current_user: User = Depends(require_any_authenticated),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Export a specific threat campaign as an RFC-compliant STIX 2.1 JSON bundle."""
    stmt = (
        select(Campaign)
        .options(
            selectinload(Campaign.email_associations)
            .selectinload(CampaignEmail.email)
            .selectinload(Email.header_hops),
            selectinload(Campaign.email_associations)
            .selectinload(CampaignEmail.email)
            .selectinload(Email.threat_indicators),
        )
        .where(Campaign.id == campaign_id)
    )
    res = await db.execute(stmt)
    camp = res.scalar_one_or_none()

    if not camp:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Campaign {campaign_id} not found in intelligence registry",
        )

    emails = [assoc.email for assoc in camp.email_associations if assoc.email]
    return generate_stix21_bundle(camp, emails)


@router.patch("/{campaign_id}/label")
async def label_campaign(
    campaign_id: uuid.UUID,
    payload: CampaignLabelRequest,
    current_user: User = Depends(require_roles([UserRole.ADMIN, UserRole.ANALYST])),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Relabel or annotate a campaign cluster (Admin/Analyst) with hash-chained audit logging."""
    camp = await db.get(Campaign, campaign_id)
    if not camp:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Campaign {campaign_id} not found",
        )

    old_name = camp.name
    camp.name = payload.name
    if payload.description is not None:
        camp.description = payload.description
    if payload.threat_actor is not None:
        meta = dict(camp.campaign_metadata or {})
        meta["threat_actor"] = payload.threat_actor
        camp.campaign_metadata = meta

    await record_chained_audit_log(
        db=db,
        action="CAMPAIGN_LABELED",
        actor=current_user.username,
        evidence_sha256=f"campaign:{camp.id}",
        details={
            "campaign_id": str(camp.id),
            "old_name": old_name,
            "new_name": camp.name,
            "threat_actor": payload.threat_actor,
        },
    )
    await db.commit()
    return camp.to_dict()


@router.post("/{campaign_id}/merge")
async def merge_campaigns(
    campaign_id: uuid.UUID,
    payload: CampaignMergeRequest,
    current_user: User = Depends(require_roles([UserRole.ADMIN, UserRole.ANALYST])),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Merge source campaign into target campaign with full audit trail."""
    source_camp = await db.get(Campaign, campaign_id)
    target_camp = await db.get(Campaign, payload.target_campaign_id)

    if not source_camp or not target_camp:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Source or target campaign not found",
        )

    # Re-link email associations
    stmt = select(CampaignEmail).where(CampaignEmail.campaign_id == source_camp.id)
    assocs = (await db.execute(stmt)).scalars().all()
    for a in assocs:
        a.campaign_id = target_camp.id

    target_camp.total_emails += len(assocs)
    target_camp.last_seen = max(target_camp.last_seen, source_camp.last_seen)

    await record_chained_audit_log(
        db=db,
        action="CAMPAIGN_MERGED",
        actor=current_user.username,
        evidence_sha256=f"campaign:{target_camp.id}",
        details={
            "source_campaign_id": str(source_camp.id),
            "source_name": source_camp.name,
            "target_campaign_id": str(target_camp.id),
            "target_name": target_camp.name,
            "migrated_email_count": len(assocs),
        },
    )

    await db.delete(source_camp)
    await db.commit()
    return target_camp.to_dict()


@router.post("/{campaign_id}/split")
async def split_campaign(
    campaign_id: uuid.UUID,
    payload: CampaignSplitRequest,
    current_user: User = Depends(require_roles([UserRole.ADMIN, UserRole.ANALYST])),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Split specified emails out of a campaign into a newly created cluster."""
    parent_camp = await db.get(Campaign, campaign_id)
    if not parent_camp:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Parent campaign {campaign_id} not found",
        )

    # Create new campaign
    new_camp = Campaign(
        id=uuid.uuid4(),
        name=payload.new_campaign_name,
        cluster_type=parent_camp.cluster_type,
        cluster_key=parent_camp.cluster_key,
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
        total_emails=len(payload.email_ids),
    )
    db.add(new_camp)
    await db.flush()

    # Move selected associations
    stmt = (
        select(CampaignEmail)
        .where(CampaignEmail.campaign_id == parent_camp.id)
        .where(CampaignEmail.email_id.in_(payload.email_ids))
    )
    assocs = (await db.execute(stmt)).scalars().all()
    for a in assocs:
        a.campaign_id = new_camp.id

    parent_camp.total_emails = max(0, parent_camp.total_emails - len(assocs))

    await record_chained_audit_log(
        db=db,
        action="CAMPAIGN_SPLIT",
        actor=current_user.username,
        evidence_sha256=f"campaign:{new_camp.id}",
        details={
            "parent_campaign_id": str(parent_camp.id),
            "new_campaign_id": str(new_camp.id),
            "new_campaign_name": new_camp.name,
            "moved_email_count": len(assocs),
        },
    )

    await db.commit()
    return new_camp.to_dict()
