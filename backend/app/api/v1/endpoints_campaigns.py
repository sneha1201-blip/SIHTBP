"""Campaign Clustering, Graph Telemetry, and STIX 2.1 API Endpoints.

Provides Cytoscape / D3.js compatible nodes and edges for visualizing multi-incident
infrastructure linkages, shared bulletproof ASNs, and SimHash body campaign clusters,
along with RFC-compliant STIX 2.1 threat intelligence bundle exports.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.app.core.security import require_any_authenticated
from backend.app.database.models import Campaign, CampaignEmail, Email, User
from backend.app.database.session import get_db
from backend.app.forensics.campaign_clusterer import generate_stix21_bundle

router = APIRouter()


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
        "spec_version": "2.1",
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
