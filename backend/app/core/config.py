"""Application Configuration and Global Settings.

Defines environment variables, forensic parameters, institutional VIP rosters,
and threat scoring weight vectors for the AICTE Cyber Security Platform.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List

from pydantic import BaseModel, Field

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
    VAULT_HMAC_SECRET: str = os.getenv(
        "VAULT_HMAC_SECRET", "aicte-sih-26106-forensic-vault-secret-key-2026"
    )
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

    # Scoring Weights (0–100 Composite Formula: Auth 25%, Header 20%, NLP 20%, URL 15%, OSINT 10%, Attach 10%)
    WEIGHT_AUTH: float = 0.25
    WEIGHT_HEADER: float = 0.20
    WEIGHT_NLP: float = 0.20
    WEIGHT_URL: float = 0.15
    WEIGHT_OSINT: float = 0.10
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
    ]

    # Institutional Protected Domains
    PROTECTED_DOMAINS: List[str] = [
        "aicte-india.org",
        "nic.in",
        "gov.in",
        "ugc.ac.in",
        "education.gov.in",
    ]


settings = Settings()
