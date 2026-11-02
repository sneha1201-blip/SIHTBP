"""Master API Router for v1 Endpoints."""

from fastapi import APIRouter
from backend.app.api.v1 import endpoints_campaigns, endpoints_forensics, endpoints_reports

api_router = APIRouter()

# Forensics Endpoints: /api/v1/forensics/analyze, /api/v1/forensics/evidence/{id}, etc.
api_router.include_router(
    endpoints_forensics.router,
    prefix="/forensics",
    tags=["Email Forensics & Protocol Inspection"],
)

# Forensic PDF Reports: /api/v1/forensics/evidence/{id}/report
api_router.include_router(
    endpoints_reports.router,
    prefix="/forensics/evidence",
    tags=["Court-Admissible Reports (Section 63 BSA 2023)"],
)

# Threat Campaigns & Graph: /api/v1/campaigns/graph, /api/v1/campaigns/
api_router.include_router(
    endpoints_campaigns.router,
    prefix="/campaigns",
    tags=["Campaign Correlation & Graph Intelligence"],
)

