"""
Cybersecurity - Auth Utility
JWT token generation and verification for API + WebSocket security.

Requires:
    pip install python-jose[cryptography] passlib[bcrypt]

Config via .env:
    SECRET_KEY=your-super-secret-key
    ACCESS_TOKEN_EXPIRE_MINUTES=60
"""

import os
import secrets
from datetime import datetime, timedelta
from typing import Optional

from jose import JWTError, jwt
import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from utils.logger import setup_logger

logger = setup_logger("auth")

# ── Config ────────────────────────────────────────────────────────────
SECRET_KEY: str = os.environ.get("SECRET_KEY", "change-this-in-production-please")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))


def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=7)
    to_encode["exp"] = expire
    to_encode["type"] = "refresh"
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def generate_email_token() -> str:
    return secrets.token_urlsafe(32)

# ── Password hashing ──────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


# ── OAuth2 scheme (used by REST endpoints) ────────────────────────────
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode["exp"] = expire
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(token: str, token_type: str = "access") -> Optional[dict]:
    """
    Decode and validate a JWT token.
    Returns the payload dict on success, None on failure.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("sub") is None:
            return None
        if token_type == "refresh" and payload.get("type") != "refresh":
            return None
        return payload
    except JWTError:
        return None


# ── FastAPI dependency — protects REST routes ─────────────────────────

def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    payload = verify_token(token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload
