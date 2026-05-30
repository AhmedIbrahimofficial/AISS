"""Cybersecurity - Authentication Routes"""
from fastapi import APIRouter, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from fastapi import Depends
from pydantic import BaseModel

from core.auth import create_access_token, verify_password, hash_password
from utils.logger import setup_logger

router = APIRouter()
logger = setup_logger("auth_route")

# ── In-memory user store (replace with DB table in production) ────────
# Passwords are bcrypt hashed — never store plain text
_USERS: dict[str, str] = {}


def _seed_default_user():
    """
    Seed a default admin user from .env on startup.
    Set ADMIN_USERNAME and ADMIN_PASSWORD in .env
    """
    import os
    username = os.environ.get("ADMIN_USERNAME", "admin")
    password = os.environ.get("ADMIN_PASSWORD", "admin123")
    if username not in _USERS:
        _USERS[username] = hash_password(password)
        logger.info(f"Default user seeded: {username}")

_seed_default_user()


# ── POST /api/auth/login ──────────────────────────────────────────────
@router.post("/login")
async def login(request: Request, form: OAuth2PasswordRequestForm = Depends()):
    """
    Login with username + password.
    Returns a JWT access token.
    """
    hashed = _USERS.get(form.username)
    if not hashed or not verify_password(form.password, hashed):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = create_access_token(data={"sub": form.username})
    logger.info(f"Login successful: {form.username}")
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": form.username,
    }


# ── POST /api/auth/register ───────────────────────────────────────────
class RegisterRequest(BaseModel):
    username: str
    password: str

@router.post("/register", status_code=201)
async def register(req: RegisterRequest, request: Request):
    """Register a new user (admin only in production — open for now)."""
    if len(req.username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    if len(req.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    if req.username in _USERS:
        raise HTTPException(status_code=409, detail="Username already exists")

    _USERS[req.username] = hash_password(req.password)
    logger.info(f"New user registered: {req.username}")
    return {"status": "registered", "username": req.username}


# ── GET /api/auth/me ──────────────────────────────────────────────────
@router.get("/me")
async def me(user: dict = Depends(__import__("core.auth", fromlist=["get_current_user"]).get_current_user)):
    """Returns current logged-in user info."""
    return {"username": user.get("sub"), "token_valid": True}
