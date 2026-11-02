"""Database package for AICTE Cyber Security Cell Email Threat Detection Platform."""

from backend.app.database.models import (
    Campaign,
    CampaignEmail,
    Email,
    EvidenceAuditLog,
    ForensicAnalysis,
    HeaderHop,
    ThreatIndicator,
)
from backend.app.database.session import (
    Base,
    async_session_factory,
    close_database,
    create_all_tables,
    drop_all_tables,
    engine,
    get_db,
    get_session,
    reset_database,
)
from backend.app.database.vault import (
    calculate_hashes,
    calculate_stream_hashes,
    canonicalize_audit_payload,
    generate_hmac_signature,
    get_vault_dir,
    read_raw_evidence,
    store_raw_evidence,
    verify_evidence_integrity,
    verify_hmac_signature,
)

__all__ = [
    # Models
    "Email",
    "HeaderHop",
    "ForensicAnalysis",
    "ThreatIndicator",
    "Campaign",
    "CampaignEmail",
    "EvidenceAuditLog",
    # Session & DB Engine
    "Base",
    "engine",
    "async_session_factory",
    "get_session",
    "get_db",
    "create_all_tables",
    "drop_all_tables",
    "reset_database",
    "close_database",
    # Cryptographic Vault
    "get_vault_dir",
    "calculate_hashes",
    "calculate_stream_hashes",
    "generate_hmac_signature",
    "verify_hmac_signature",
    "canonicalize_audit_payload",
    "store_raw_evidence",
    "read_raw_evidence",
    "verify_evidence_integrity",
]

