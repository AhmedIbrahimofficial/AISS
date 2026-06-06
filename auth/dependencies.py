"""
Auth — FastAPI Dependencies
JWT middleware: validates Bearer token and injects current user.
"""

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from auth.models import AuthUser
from auth.utils.tokens import decode_access_token
from core.database import get_db
from utils.logger import setup_logger

logger = setup_logger("auth.dependencies")

_bearer = HTTPBearer(auto_error=False)


async def get_current_user(
    request:     Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db:          AsyncSession = Depends(get_db),
) -> AuthUser:
    """
    Extract and validate JWT from Authorization: Bearer <token>.
    Raises 401 on any failure — never leaks why.
    """
    if not credentials:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_access_token(credentials.credentials)
        user_id: str = payload.get("sub")
        if not user_id:
            raise JWTError("Missing sub")
    except JWTError:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = await db.scalar(
        select(AuthUser).where(AuthUser.id == user_id)
    )

    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found")
    if not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Account deactivated")

    return user


async def get_current_verified_user(
    user: AuthUser = Depends(get_current_user),
) -> AuthUser:
    """Same as get_current_user but also requires email verification."""
    if not user.is_verified:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Email not verified. Please check your inbox."
        )
    return user


def require_role(*roles: str):
    """
    Role-based access control factory.
    Usage: Depends(require_role("admin", "analyst"))
    """
    def _check(user: AuthUser = Depends(get_current_verified_user)) -> AuthUser:
        if user.role not in roles:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"Access denied. Required role: {' or '.join(roles)}"
            )
        return user
    return _check
