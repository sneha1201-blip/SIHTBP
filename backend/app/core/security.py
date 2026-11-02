"""Security, Hashing, and Cryptographic Utilities for Core Services."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Union

from backend.app.core.config import settings


def hash_token(token: str) -> str:
    """Generate SHA-256 hash of a session token or API key."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_nonce(length: int = 32) -> str:
    """Generate a cryptographically secure random hexadecimal nonce."""
    return secrets.token_hex(length // 2)


def sign_audit_entry(payload: Union[str, bytes], secret: str | None = None) -> str:
    """Generate HMAC-SHA256 signature for evidence audit logging."""
    key = (secret or settings.VAULT_HMAC_SECRET).encode("utf-8")
    data = payload.encode("utf-8") if isinstance(payload, str) else payload
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def constant_time_compare(val1: str, val2: str) -> bool:
    """Perform constant-time comparison against timing attacks."""
    return hmac.compare_digest(val1.lower(), val2.lower())

