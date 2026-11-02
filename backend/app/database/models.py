"""Relational & Graph ORM Models for AICTE Forensic Email Threat Intelligence Platform.

Defines the 6 foundational schemas compliant with SQLAlchemy 2.0 asyncio,
providing zero-setup execution on SQLite 3 and enterprise scalability on PostgreSQL 16.

Models:
1. Email: Core email entity, cryptographic hashes, SIMHASH, headers, bodies.
2. HeaderHop: Network transit hop analysis, IP geolocation, ASN intelligence, Tor/VPN/DC flags.
3. ForensicAnalysis: Protocol authentication (SPF/DKIM/DMARC), spoofing detectors, threat scores.
4. ThreatIndicator: Extracted IOCs (URLs, domains, IPs, file hashes) with defanging and reputation.
5. Campaign & CampaignEmail: Cross-incident graph clustering by shared ASN, subnet, domain, or SIMHASH.
6. EvidenceAuditLog: Tamper-evident, HMAC-sealed chain of custody audit trail.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.database.session import Base


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(timezone.utc)


class Email(Base):
    """Core email entity capturing raw metadata, cryptographic fingerprints, and parsed content."""

    __tablename__ = "emails"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    sha256_hash: Mapped[str] = mapped_column(
        String(64), unique=True, index=True, nullable=False, doc="Cryptographic SHA-256 digest"
    )
    md5_hash: Mapped[str] = mapped_column(
        String(32), index=True, nullable=False, doc="Legacy MD5 digest for SIEM correlation"
    )
    file_name: Mapped[str] = mapped_column(
        String(255), nullable=False, doc="Original file name of uploaded evidence"
    )
    file_size_bytes: Mapped[int] = mapped_column(
        Integer, nullable=False, doc="Size of raw evidence file in bytes"
    )
    raw_storage_path: Mapped[str] = mapped_column(
        String(512), nullable=False, doc="Absolute or relative path within immutable storage vault"
    )
    rfc822_msg_id: Mapped[Optional[str]] = mapped_column(
        String(255), index=True, nullable=True, doc="RFC 822 Message-ID header"
    )
    subject: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, doc="Decoded email subject line"
    )
    sender_raw: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, doc="Raw unparsed From: header"
    )
    sender_email: Mapped[Optional[str]] = mapped_column(
        String(255), index=True, nullable=True, doc="Extracted sender email address"
    )
    sender_display: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True, doc="Display name portion of sender header"
    )
    return_path: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True, doc="Envelope Return-Path / bounce address"
    )
    reply_to: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True, doc="Explicit Reply-To address"
    )
    recipient_list: Mapped[List[str]] = mapped_column(
        JSON, default=list, nullable=False, doc="List of To, Cc, Bcc recipient email addresses"
    )
    date_header: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, doc="Timestamp declared in Date: header"
    )
    body_plain: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, doc="Decoded plaintext body"
    )
    body_html: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, doc="Raw HTML body content"
    )
    simhash_body: Mapped[Optional[str]] = mapped_column(
        String(64), index=True, nullable=True, doc="Locality-sensitive SimHash for fuzzy clustering"
    )
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False, doc="Forensic ingestion timestamp"
    )

    # Relationships
    header_hops: Mapped[List["HeaderHop"]] = relationship(
        "HeaderHop",
        back_populates="email",
        cascade="all, delete-orphan",
        order_by="HeaderHop.hop_order",
    )
    forensic_analysis: Mapped[Optional["ForensicAnalysis"]] = relationship(
        "ForensicAnalysis",
        back_populates="email",
        uselist=False,
        cascade="all, delete-orphan",
    )
    threat_indicators: Mapped[List["ThreatIndicator"]] = relationship(
        "ThreatIndicator",
        back_populates="email",
        cascade="all, delete-orphan",
    )
    campaign_associations: Mapped[List["CampaignEmail"]] = relationship(
        "CampaignEmail",
        back_populates="email",
        cascade="all, delete-orphan",
    )
    audit_logs: Mapped[List["EvidenceAuditLog"]] = relationship(
        "EvidenceAuditLog",
        back_populates="email",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Email id={self.id} subject='{self.subject}' sha256={self.sha256_hash[:12]}...>"

    def to_dict(self) -> Dict[str, Any]:
        """Convert email entity to dictionary for API serialization."""
        return {
            "id": str(self.id),
            "sha256_hash": self.sha256_hash,
            "md5_hash": self.md5_hash,
            "file_name": self.file_name,
            "file_size_bytes": self.file_size_bytes,
            "raw_storage_path": self.raw_storage_path,
            "rfc822_msg_id": self.rfc822_msg_id,
            "subject": self.subject,
            "sender_raw": self.sender_raw,
            "sender_email": self.sender_email,
            "sender_display": self.sender_display,
            "return_path": self.return_path,
            "reply_to": self.reply_to,
            "recipient_list": self.recipient_list,
            "date_header": self.date_header.isoformat() if self.date_header else None,
            "simhash_body": self.simhash_body,
            "ingested_at": self.ingested_at.isoformat(),
        }


class HeaderHop(Base):
    """MTA received header hop capturing transport route, geo-coordinates, and network traits."""

    __tablename__ = "header_hops"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    email_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("emails.id", ondelete="CASCADE"), index=True, nullable=False
    )
    hop_order: Mapped[int] = mapped_column(
        Integer, nullable=False, doc="1 = originating hop, ascending towards destination"
    )
    by_mta: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True, doc="Receiving MTA server hostname"
    )
    from_mta: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True, doc="Claimed sender MTA server hostname"
    )
    hop_ip: Mapped[Optional[str]] = mapped_column(
        String(64), index=True, nullable=True, doc="IP address of relaying server"
    )
    is_private_ip: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False, doc="RFC 1918 private / local loopback address flag"
    )
    is_reliable: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False, doc="True if hop wasn't forged by prior untrusted relays"
    )
    protocol: Mapped[Optional[str]] = mapped_column(
        String(32), nullable=True, doc="Transport protocol (ESMTPS, ESMTPA, SMTP)"
    )
    hop_timestamp: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, doc="MTA recorded hop timestamp"
    )
    delay_seconds: Mapped[float] = mapped_column(
        Float, default=0.0, nullable=False, doc="Transit latency from previous hop"
    )
    geo_country: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True, doc="MaxMind GeoIP2 country resolution"
    )
    geo_city: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True, doc="MaxMind GeoIP2 city resolution"
    )
    geo_lat: Mapped[Optional[float]] = mapped_column(
        Float, nullable=True, doc="Geographical latitude"
    )
    geo_lon: Mapped[Optional[float]] = mapped_column(
        Float, nullable=True, doc="Geographical longitude"
    )
    asn_number: Mapped[Optional[int]] = mapped_column(
        Integer, index=True, nullable=True, doc="Autonomous System Number (ASN)"
    )
    asn_org: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True, doc="Autonomous System Organization name"
    )
    node_type: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True, doc="ORIGINATING, INTERNAL, RELAY, TOR_EXIT, DATACENTER_PROXY"
    )
    is_tor: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False, doc="Confirmed Tor exit node flag"
    )
    is_vpn: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False, doc="Commercial VPN anonymizer flag"
    )
    is_datacenter: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False, doc="Hosting / Cloud Datacenter range (non-residential)"
    )

    # Relationships
    email: Mapped["Email"] = relationship("Email", back_populates="header_hops")

    __table_args__ = (
        Index("ix_header_hops_email_order", "email_id", "hop_order"),
    )

    def __repr__(self) -> str:
        return f"<HeaderHop #{self.hop_order} ip={self.hop_ip} asn={self.asn_number} tor={self.is_tor}>"

    def to_dict(self) -> Dict[str, Any]:
        """Convert header hop to dictionary."""
        return {
            "id": str(self.id),
            "email_id": str(self.email_id),
            "hop_order": self.hop_order,
            "by_mta": self.by_mta,
            "from_mta": self.from_mta,
            "hop_ip": self.hop_ip,
            "is_private_ip": self.is_private_ip,
            "is_reliable": self.is_reliable,
            "protocol": self.protocol,
            "hop_timestamp": self.hop_timestamp.isoformat() if self.hop_timestamp else None,
            "delay_seconds": self.delay_seconds,
            "geo_country": self.geo_country,
            "geo_city": self.geo_city,
            "geo_lat": self.geo_lat,
            "geo_lon": self.geo_lon,
            "asn_number": self.asn_number,
            "asn_org": self.asn_org,
            "node_type": self.node_type,
            "is_tor": self.is_tor,
            "is_vpn": self.is_vpn,
            "is_datacenter": self.is_datacenter,
        }


class ForensicAnalysis(Base):
    """Forensic evaluation record storing SPF/DKIM/DMARC statuses, spoof detections, and threat score."""

    __tablename__ = "forensic_analyses"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    email_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("emails.id", ondelete="CASCADE"),
        unique=True,
        index=True,
        nullable=False,
    )
    spf_status: Mapped[str] = mapped_column(
        String(32), default="NONE", nullable=False, doc="PASS, FAIL, SOFTFAIL, NEUTRAL, NONE, TEMPERROR"
    )
    spf_domain: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True, doc="Domain verified under SPF check"
    )
    dkim_status: Mapped[str] = mapped_column(
        String(32), default="NONE", nullable=False, doc="PASS, FAIL, NONE, INVALID"
    )
    dkim_selector: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True, doc="DKIM selector key identifier"
    )
    dkim_domain: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True, doc="Signing domain in d= tag"
    )
    dmarc_status: Mapped[str] = mapped_column(
        String(32), default="NONE", nullable=False, doc="PASS, FAIL, NONE"
    )
    dmarc_policy: Mapped[Optional[str]] = mapped_column(
        String(32), nullable=True, doc="Published policy (reject, quarantine, none)"
    )
    dmarc_alignment_spf: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False, doc="True if RFC 5322 From matches SPF domain"
    )
    dmarc_alignment_dkim: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False, doc="True if RFC 5322 From matches DKIM d= domain"
    )
    display_spoof_flag: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False, doc="True if display name mimics VIP or trusted org"
    )
    lookalike_flag: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False, doc="True if domain mimics trusted brand (typosquatting)"
    )
    homograph_flag: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False, doc="True if Cyrillic or non-ASCII IDN confusable chars detected"
    )
    threat_score: Mapped[float] = mapped_column(
        Float, nullable=False, doc="Comprehensive threat score from 0.0 (benign) to 100.0 (critical)"
    )
    verdict: Mapped[str] = mapped_column(
        String(32),
        index=True,
        nullable=False,
        doc="BENIGN, SUSPICIOUS, PHISHING, BEC, MALICIOUS",
    )
    score_breakdown: Mapped[Dict[str, Any]] = mapped_column(
        JSON, default=dict, nullable=False, doc="Detailed explainable AI risk scoring sub-metrics"
    )

    # Relationships
    email: Mapped["Email"] = relationship("Email", back_populates="forensic_analysis")

    def __repr__(self) -> str:
        return f"<ForensicAnalysis email_id={self.email_id} score={self.threat_score} verdict={self.verdict}>"

    def to_dict(self) -> Dict[str, Any]:
        """Convert forensic analysis to dictionary."""
        return {
            "id": str(self.id),
            "email_id": str(self.email_id),
            "spf_status": self.spf_status,
            "spf_domain": self.spf_domain,
            "dkim_status": self.dkim_status,
            "dkim_selector": self.dkim_selector,
            "dkim_domain": self.dkim_domain,
            "dmarc_status": self.dmarc_status,
            "dmarc_policy": self.dmarc_policy,
            "dmarc_alignment_spf": self.dmarc_alignment_spf,
            "dmarc_alignment_dkim": self.dmarc_alignment_dkim,
            "display_spoof_flag": self.display_spoof_flag,
            "lookalike_flag": self.lookalike_flag,
            "homograph_flag": self.homograph_flag,
            "threat_score": self.threat_score,
            "verdict": self.verdict,
            "score_breakdown": self.score_breakdown,
        }


class ThreatIndicator(Base):
    """Indicators of Compromise (IOCs) extracted from headers, bodies, attachments, and URLs."""

    __tablename__ = "threat_indicators"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    email_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("emails.id", ondelete="CASCADE"), index=True, nullable=False
    )
    ioc_type: Mapped[str] = mapped_column(
        String(32), index=True, nullable=False, doc="URL, DOMAIN, IP, HASH, EMAIL_ADDR"
    )
    ioc_value: Mapped[str] = mapped_column(
        Text, nullable=False, doc="Raw or extracted IOC string"
    )
    context: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True, doc="Where IOC was discovered: EMAIL_BODY, HEADER_RECEIVED, ATTACHMENT, SENDER"
    )
    is_defanged: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False, doc="True if IOC has safe defanged formatting (hxxp, [.])"
    )
    domain_age_days: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True, doc="WHOIS newly registered domain age"
    )
    registrar: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True, doc="Domain registrar name"
    )
    reputation_score: Mapped[Optional[float]] = mapped_column(
        Float, nullable=True, doc="Threat intelligence reputation (0-100 malicious scale)"
    )
    # Note: Named 'metadata' in SQL table, mapped as 'ioc_metadata' in Python to avoid Base.metadata conflict
    ioc_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        "metadata", JSON, default=dict, nullable=True, doc="Auxiliary IOC threat intelligence context"
    )

    # Relationships
    email: Mapped["Email"] = relationship("Email", back_populates="threat_indicators")

    __table_args__ = (
        Index("ix_threat_indicators_type_val", "ioc_type"),
    )

    def __repr__(self) -> str:
        return f"<ThreatIndicator type={self.ioc_type} val='{self.ioc_value[:30]}'>"

    def to_dict(self) -> Dict[str, Any]:
        """Convert threat indicator to dictionary."""
        return {
            "id": str(self.id),
            "email_id": str(self.email_id),
            "ioc_type": self.ioc_type,
            "ioc_value": self.ioc_value,
            "context": self.context,
            "is_defanged": self.is_defanged,
            "domain_age_days": self.domain_age_days,
            "registrar": self.registrar,
            "reputation_score": self.reputation_score,
            "metadata": self.ioc_metadata,
        }


class Campaign(Base):
    """Cluster entity grouping coordinated email threats sharing ASN, subnet, domain, or SimHash."""

    __tablename__ = "campaigns"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(
        String(255), nullable=False, doc="Tactical operation or cluster identifier"
    )
    description: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, doc="Forensic summary of campaign vector and targeting"
    )
    cluster_type: Mapped[str] = mapped_column(
        String(64), index=True, nullable=False, doc="Clustering pivot: ASN, IP_SUBNET, SENDER_DOMAIN, SIMHASH, COMPOSITE"
    )
    cluster_key: Mapped[str] = mapped_column(
        String(255), index=True, nullable=False, doc="Unique clustering key (e.g. AS49870, 194.36.191.0/24, SimHash hash)"
    )
    severity: Mapped[str] = mapped_column(
        String(32), default="MEDIUM", nullable=False, doc="LOW, MEDIUM, HIGH, CRITICAL"
    )
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False, doc="Earliest campaign activity observed"
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False, doc="Latest campaign activity observed"
    )
    total_emails: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False, doc="Aggregated count of attributed victim emails"
    )
    campaign_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        "metadata", JSON, default=dict, nullable=True, doc="Campaign telemetry, infrastructure tags, and threat actor notes"
    )

    # Relationships
    email_associations: Mapped[List["CampaignEmail"]] = relationship(
        "CampaignEmail",
        back_populates="campaign",
        cascade="all, delete-orphan",
    )
    emails: Mapped[List["Email"]] = relationship(
        "Email",
        secondary="campaign_emails",
        viewonly=True,
    )

    def __repr__(self) -> str:
        return f"<Campaign name='{self.name}' type={self.cluster_type} total={self.total_emails}>"

    def to_dict(self) -> Dict[str, Any]:
        """Convert campaign entity to dictionary."""
        return {
            "id": str(self.id),
            "name": self.name,
            "description": self.description,
            "cluster_type": self.cluster_type,
            "cluster_key": self.cluster_key,
            "severity": self.severity,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "total_emails": self.total_emails,
            "metadata": self.campaign_metadata,
        }


class CampaignEmail(Base):
    """Many-to-Many association linking emails to campaign clusters with similarity metrics."""

    __tablename__ = "campaign_emails"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    campaign_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("campaigns.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    email_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("emails.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    similarity_score: Mapped[float] = mapped_column(
        Float, default=1.0, nullable=False, doc="Graph clustering similarity confidence (0.0 - 1.0)"
    )
    matched_criteria: Mapped[Dict[str, Any]] = mapped_column(
        JSON, default=dict, nullable=False, doc="Matching pivot parameters (e.g. hamming distance, shared ASN)"
    )
    associated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False, doc="Timestamp when correlation was established"
    )

    # Relationships
    campaign: Mapped["Campaign"] = relationship("Campaign", back_populates="email_associations")
    email: Mapped["Email"] = relationship("Email", back_populates="campaign_associations")

    __table_args__ = (
        UniqueConstraint("campaign_id", "email_id", name="uq_campaign_email"),
    )

    def __repr__(self) -> str:
        return f"<CampaignEmail campaign_id={self.campaign_id} email_id={self.email_id} score={self.similarity_score}>"

    def to_dict(self) -> Dict[str, Any]:
        """Convert association record to dictionary."""
        return {
            "id": str(self.id),
            "campaign_id": str(self.campaign_id),
            "email_id": str(self.email_id),
            "similarity_score": self.similarity_score,
            "matched_criteria": self.matched_criteria,
            "associated_at": self.associated_at.isoformat(),
        }


class EvidenceAuditLog(Base):
    """Append-only, HMAC-sealed forensic chain of custody ledger."""

    __tablename__ = "evidence_audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    email_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("emails.id", ondelete="CASCADE"),
        index=True,
        nullable=True,
        doc="Associated email ID, or null for general platform evidence logs",
    )
    action_performed: Mapped[str] = mapped_column(
        String(64),
        index=True,
        nullable=False,
        doc="INGESTED, VAULT_SEALED, INTEGRITY_VERIFIED, EXPORTED, CHAIN_OF_CUSTODY_CHECK",
    )
    actor: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        doc="System service account or forensic analyst identifier",
    )
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
        doc="Immutable audit timestamp",
    )
    evidence_sha256: Mapped[str] = mapped_column(
        String(64),
        index=True,
        nullable=False,
        doc="SHA-256 hash of the evidence object being logged",
    )
    integrity_check: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
        doc="True if vault cryptographic hash matches during logging",
    )
    hmac_signature: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        doc="Cryptographic HMAC-SHA256 signature preventing tampering with audit history",
    )
    details: Mapped[Dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
        doc="Structured event metadata, IP, user-agent, or forensic findings",
    )

    # Relationships
    email: Mapped[Optional["Email"]] = relationship("Email", back_populates="audit_logs")

    def __repr__(self) -> str:
        return f"<EvidenceAuditLog action={self.action_performed} actor={self.actor} integrity={self.integrity_check}>"

    def to_dict(self) -> Dict[str, Any]:
        """Convert audit log record to dictionary."""
        return {
            "id": str(self.id),
            "email_id": str(self.email_id) if self.email_id else None,
            "action_performed": self.action_performed,
            "actor": self.actor,
            "recorded_at": self.recorded_at.isoformat(),
            "evidence_sha256": self.evidence_sha256,
            "integrity_check": self.integrity_check,
            "hmac_signature": self.hmac_signature,
            "details": self.details,
        }

