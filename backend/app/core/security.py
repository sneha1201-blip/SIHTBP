"""Security, Hashing, Argon2 Password Hashing, JWT, and RBAC Authentication.

Provides Argon2 password hashing, JWT issuance and verification, Role-Based Access Control
(ADMIN, ANALYST, AUDITOR), and cryptographic utilities for the AICTE Cyber Security Cell.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Union

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.config import settings
from backend.app.database.models import User, UserRole
from backend.app.database.session import get_db

logger = logging.getLogger(__name__)

# Argon2 Password Hasher instance with high memory and iteration parameters
ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)

security_bearer = HTTPBearer(auto_error=False)

# In-memory login failure tracking for account lockout protection
_FAILED_LOGINS: Dict[str, list[float]] = {}
LOCKOUT_WINDOW_SECONDS = 900  # 15 minutes
MAX_FAILED_ATTEMPTS = 5


def record_login_attempt(username: str, success: bool) -> None:
    """Record login attempt timestamp; reset on success."""
    now = datetime.now(timezone.utc).timestamp()
    if username not in _FAILED_LOGINS:
        _FAILED_LOGINS[username] = []
    _FAILED_LOGINS[username] = [t for t in _FAILED_LOGINS[username] if now - t < LOCKOUT_WINDOW_SECONDS]
    if success:
        _FAILED_LOGINS[username] = []
    else:
        _FAILED_LOGINS[username].append(now)


def check_login_lockout(username: str) -> None:
    """Raise HTTP 429 if username has exceeded max consecutive login failures."""
    now = datetime.now(timezone.utc).timestamp()
    recent = [t for t in _FAILED_LOGINS.get(username, []) if now - t < LOCKOUT_WINDOW_SECONDS]
    if len(recent) >= MAX_FAILED_ATTEMPTS:
        remaining = int(LOCKOUT_WINDOW_SECONDS - (now - recent[0]))
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Account temporarily locked out due to {len(recent)} failed login attempts. Try again in {max(1, remaining // 60)} minutes.",
        )


def validate_password_strength(password: str) -> None:
    """Enforce institutional password complexity: minimum 10 chars, uppercase, lowercase, digit, special."""
    if len(password) < 10:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 10 characters long.",
        )
    if not any(c.isupper() for c in password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one uppercase letter.",
        )
    if not any(c.islower() for c in password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one lowercase letter.",
        )
    if not any(c.isdigit() for c in password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one numerical digit.",
        )
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?/~`"
    if not any(c in special_chars for c in password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one special character.",
        )


def hash_token(token: str) -> str:
    """Generate SHA-256 hash of a session token or API key."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_nonce(length: int = 32) -> str:
    """Generate a cryptographically secure random hexadecimal nonce."""
    return secrets.token_hex(length // 2)


def sign_audit_entry(payload: Union[str, bytes], secret: Optional[str] = None) -> str:
    """Generate HMAC-SHA256 signature for evidence audit logging."""
    key = (secret or settings.VAULT_HMAC_SECRET).encode("utf-8")
    data = payload.encode("utf-8") if isinstance(payload, str) else payload
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def constant_time_compare(val1: str, val2: str) -> bool:
    """Perform constant-time comparison against timing attacks."""
    return hmac.compare_digest(val1.lower(), val2.lower())


def hash_password(plain_password: str) -> str:
    """Hash a plaintext password using Argon2."""
    return ph.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against an Argon2 hash in constant time."""
    try:
        return ph.verify(hashed_password, plain_password)
    except VerifyMismatchError:
        return False
    except Exception as exc:
        logger.warning("Error verifying argon2 password: %s", exc)
        return False


def create_access_token(
    subject: str,
    role: str,
    expires_delta: Optional[timedelta] = None,
    extra_claims: Optional[Dict[str, Any]] = None,
) -> str:
    """Issue a signed JWT access token."""
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)

    payload: Dict[str, Any] = {
        "sub": subject,
        "role": role,
        "iat": now,
        "exp": expire,
    }
    if extra_claims:
        payload.update(extra_claims)

    encoded_jwt = jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )
    return encoded_jwt


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decode and cryptographically verify a JWT access token."""
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has expired.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid cryptographic authentication credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Extract authenticated User from Bearer token.
    Raises 401 if unauthenticated or token is invalid.
    """
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    payload = decode_access_token(token)
    username = payload.get("sub")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token payload is missing subject identifier.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    stmt = select(User).where(User.username == username)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if not user:
        if username in ("admin", "analyst", "auditor"):
            from backend.app.database.init_db import seed_default_users

            await seed_default_users(db)
            result = await db.execute(stmt)
            user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account associated with this token no longer exists.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account has been deactivated.",
        )

    return user


def require_roles(allowed_roles: List[str]) -> Callable:
    """Dependency factory enforcing Role-Based Access Control (RBAC)."""

    async def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Role '{current_user.role}' lacks permission for this operation. Required roles: {allowed_roles}",
            )
        return current_user

    return role_checker


# Commonly used RBAC dependencies
require_admin = require_roles([UserRole.ADMIN])
require_analyst = require_roles([UserRole.ADMIN, UserRole.ANALYST])
require_any_authenticated = require_roles([UserRole.ADMIN, UserRole.ANALYST, UserRole.AUDITOR])
