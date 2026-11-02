"""Campaign Clustering and Graph Relationship API Endpoints.

Provides Cytoscape / D3.js compatible nodes and edges for visualizing multi-incident
infrastructure linkages, shared bulletproof ASNs, and SimHash body campaign clusters.
"""

from __future__ import annotations

from typing import Any, Dict, List
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.app.database.models import Campaign, CampaignEmail, Email, HeaderHop, ThreatIndicator
from backend.app.database.session import get_db

router = APIRouter()


@router.get("/")
async def list_campaigns(db: AsyncSession = Depends(get_db)) -> List[Dict[str, Any]]:
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
async def get_campaign_graph(db: AsyncSession = Depends(get_db)) -> Dict[str, Any]:
    """Return nodes and edges representing threat campaign relationships for graph visualization."""
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
        edges.append({
            "id": f"{source}->{target}",
            "source": source,
            "target": target,
            "relationship": relationship,
            "metadata": metadata or {},
        })

    for camp in campaigns:
        camp_node_id = f"campaign_{camp.id}"
        add_node(
            node_id=camp_node_id,
            label=camp.name[:32] + "...",
            node_type="CAMPAIGN",
            metadata={"cluster_type": camp.cluster_type, "severity": camp.severity, "total": camp.total_emails},
        )

        for assoc in camp.email_associations:
            em = assoc.email
            if not em:
                continue

            email_node_id = f"email_{em.id}"
            add_node(
                node_id=email_node_id,
                label=em.subject[:28] + "..." if em.subject else "Email",
                node_type="EMAIL",
                metadata={"sha256": em.sha256_hash, "sender": em.sender_email},
            )

            # Edge: Email -> Campaign
            add_edge(
                source=email_node_id,
                target=camp_node_id,
                relationship="CLUSTERED_INTO",
                metadata={"similarity": assoc.similarity_score, "criteria": assoc.matched_criteria},
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

