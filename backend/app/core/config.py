"""Application Configuration and Global Settings.

Defines environment variables, forensic parameters, institutional VIP rosters,
and threat scoring weight vectors for the AICTE Cyber Security Platform.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, List

from pydantic import BaseModel

# Absolute directory paths
BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
PROJECT_ROOT = BACKEND_DIR.parent
STORAGE_DIR = PROJECT_ROOT / "storage"
VAULT_DIR = STORAGE_DIR / "vault"
GEOIP_DIR = STORAGE_DIR / "geoip"


class Settings(BaseModel):
    """Core application settings with environment variable override support."""

    # Project Information
    PROJECT_NAME: str = "AICTE Cyber Security Cell - Forensic Email Threat Intelligence Platform"
    PROJECT_VERSION: str = "2.0.0"
    API_V1_STR: str = "/api/v1"
    SIH_PROBLEM_ID: str = "26106"
    DEBUG: bool = os.getenv("DEBUG", "false").lower() in ("true", "1", "yes")

    # Database & Vault
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        f"sqlite+aiosqlite:///{STORAGE_DIR.resolve().as_posix()}/forensic_platform.db",
    )
    VAULT_DIR_PATH: Path = VAULT_DIR
    VAULT_HMAC_SECRET: str = os.getenv("VAULT_HMAC_SECRET", "")

    # Auth & RBAC
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "")
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24

    # Security & Ingestion Limits
    MAX_UPLOAD_SIZE_BYTES: int = int(os.getenv("MAX_UPLOAD_SIZE_BYTES", str(25 * 1024 * 1024)))
    RATE_LIMIT_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))

    def model_post_init(self, __context: Any) -> None:
        is_testing = (
            "pytest" in sys.modules
            or os.getenv("TESTING") == "1"
            or os.getenv("PYTEST_CURRENT_TEST") is not None
            or any("pytest" in arg.lower() for arg in sys.argv)
            or any("verify_system" in arg.lower() for arg in sys.argv)
        )
        if not self.DEBUG and not is_testing:
            if not self.VAULT_HMAC_SECRET or self.VAULT_HMAC_SECRET == "aicte-sih-26106-forensic-vault-secret-key-2026":
                raise RuntimeError(
                    "FATAL SECURITY CONFIGURATION: VAULT_HMAC_SECRET must be explicitly configured "
                    "outside DEBUG mode. Refusing application startup."
                )
            if not self.JWT_SECRET_KEY:
                raise RuntimeError(
                    "FATAL SECURITY CONFIGURATION: JWT_SECRET_KEY must be explicitly configured "
                    "outside DEBUG mode. Refusing application startup."
                )
        else:
            if not self.VAULT_HMAC_SECRET:
                self.VAULT_HMAC_SECRET = "insecure-dev-vault-hmac-secret-only-for-local-testing-32b"
            if not self.JWT_SECRET_KEY:
                self.JWT_SECRET_KEY = "insecure-dev-jwt-secret-only-for-local-testing-key-32b"
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://0.0.0.0:3000",
        "*",
    ]

    # GeoIP & Threat Intel
    MAXMIND_GEOIP_CITY_PATH: Path = GEOIP_DIR / "GeoLite2-City.mmdb"
    MAXMIND_GEOIP_ASN_PATH: Path = GEOIP_DIR / "GeoLite2-ASN.mmdb"
    TOR_EXIT_NODE_CACHE_TTL_HOURS: int = 6
    WHOIS_CACHE_TTL_HOURS: int = 24

    # High-Fanout ASNs (Major hyperscalers, CDNs, and transit providers where shared ASN != threat campaign)
    HIGH_FANOUT_ASNS: set[int] = {
        15169,  # Google LLC
        16509,  # Amazon.com, Inc. / AWS
        14618,  # Amazon.com, Inc. / AWS
        8075,   # Microsoft Corporation
        13335,  # Cloudflare, Inc.
        32934,  # Meta Platforms, Inc. / Facebook
        20940,  # Akamai International B.V.
        54113,  # Fastly, Inc.
        2635,   # Yahoo / Oath
        46484,  # Mimecast
        36351,  # SoftLayer / IBM Cloud
        16276,  # OVH SAS
        24940,  # Hetzner Online GmbH
        63949,  # Linode, LLC / Akamai
    }

    HIGH_FANOUT_ASN_PATTERNS: tuple[str, ...] = (
        "google",
        "amazon",
        "aws",
        "microsoft",
        "cloudflare",
        "facebook",
        "meta",
        "akamai",
        "fastly",
        "yahoo",
        "apple",
        "mimecast",
    )

    PUBLIC_MAIL_DOMAINS: set[str] = {
        "gmail.com",
        "googlemail.com",
        "yahoo.com",
        "yahoo.co.in",
        "outlook.com",
        "hotmail.com",
        "live.com",
        "icloud.com",
        "protonmail.com",
        "proton.me",
        "zoho.com",
        "rediffmail.com",
        "mail.com",
        "aol.com",
    }

    # Scoring Weights (0–100 Composite Formula: Auth 25%, Hop/Geo 20%, NLP 20%, URL 20%, Brand/VIP 15%)
    WEIGHT_AUTH: float = 0.25
    WEIGHT_OSINT: float = 0.20
    WEIGHT_NLP: float = 0.20
    WEIGHT_URL: float = 0.20
    WEIGHT_HEADER: float = 0.15
    WEIGHT_ATTACHMENT: float = 0.10

    # Institutional VIPs for Display Name Impersonation
    VIP_NAMES: List[str] = [
        "Prof. T. G. Sitharam",
        "T. G. Sitharam",
        "Chairman, AICTE",
        "Chairman AICTE",
        "Dr. Abhay Jere",
        "Vice Chairman, AICTE",
        "Prof. Rajive Kumar",
        "Member Secretary, AICTE",
        "Member Secretary AICTE",
        "AICTE Cyber Security Cell",
        "Approval Bureau AICTE",
        "Director, Academic Bureau",
        "Chief Vigilance Officer, AICTE",
        "Ministry of Education",
        "State Bank of India",
        "Reserve Bank of India",
        "Chairman SBI",
        "RBI Fraud Monitoring",
    ]

    # Institutional Protected Domains
    PROTECTED_DOMAINS: List[str] = [
        "aicte-india.org",
        "nic.in",
        "gov.in",
        "ugc.ac.in",
        "education.gov.in",
        "sbi.co.in",
        "rbi.org.in",
        "bankofbaroda.in",
        "icicibank.com",
    ]


settings = Settings()
