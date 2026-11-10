"""Authentication & RBAC Endpoints.

Provides login, token issuance, user profile, and user registration endpoints.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.config import settings
from backend.app.core.security import (
    create_access_token,
    get_current_user,
    hash_password,
    require_admin,
    verify_password,
)
from backend.app.database.models import User, UserRole
from backend.app.database.session import get_db

router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str
    role: str = UserRole.ANALYST


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    user: Dict[str, Any]


@router.post("/login", response_model=TokenResponse)
async def login(
    payload: LoginRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Authenticate user with username and password, returning a signed JWT access token."""
    stmt = select(User).where(User.username == payload.username)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account has been deactivated.",
        )

    access_token = create_access_token(
        subject=user.username,
        role=user.role,
        expires_delta=timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES),
        extra_claims={"user_id": str(user.id), "email": user.email},
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user=user.to_dict(),
    )


@router.get("/me")
async def get_current_user_profile(
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Return the profile of the currently authenticated user."""
    return current_user.to_dict()


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register_user(
    payload: RegisterRequest,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Register a new user account (Requires ADMIN role)."""
    # Check for existing user
    stmt = select(User).where((User.username == payload.username) | (User.email == payload.email))
    result = await db.execute(stmt)
    existing = result.scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this username or email already exists.",
        )

    valid_roles = [UserRole.ADMIN, UserRole.ANALYST, UserRole.AUDITOR]
    if payload.role.upper() not in valid_roles:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role. Must be one of: {valid_roles}",
        )

    hashed_pw = hash_password(payload.password)
    new_user = User(
        username=payload.username,
        email=payload.email,
        password_hash=hashed_pw,
        role=payload.role.upper(),
        is_active=True,
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return new_user.to_dict()
