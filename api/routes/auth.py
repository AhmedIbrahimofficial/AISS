"""AISS - Authentication Routes with DB + Email Verification"""

import os
from datetime import datetime, timedelta

from fastapi import APIRouter, HTTPException, status, Depends, BackgroundTasks
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from core.auth import (
    create_access_token, create_refresh_token,
    verify_password, hash_password,
    generate_email_token, verify_token,
)
from core.database import get_db
from core.models import User
from core.email import send_verification_email, send_password_reset_email
from utils.logger import setup_logger

router = APIRouter()
logger = setup_logger("auth_route")

MAX_ATTEMPTS = 5
LOCK_MINUTES = 15


# ── Schemas ───────────────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    username: str
    email:    EmailStr
    password: str
    role:     str = "viewer"


class RefreshRequest(BaseModel):
    refresh_token: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token:        str
    new_password: str


# ── POST /api/auth/register ───────────────────────────────────────────
@router.post("/register", status_code=201)
async def register(
    req:        RegisterRequest,
    background: BackgroundTasks,
    db:         AsyncSession = Depends(get_db),
):
    if len(req.username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    if len(req.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    existing = await db.execute(select(User).where(User.email == req.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Email already registered")

    existing_user = await db.execute(select(User).where(User.username == req.username))
    if existing_user.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Username already taken")

    token   = generate_email_token()
    expires = datetime.utcnow() + timedelta(hours=24)

    user = User(
        username             = req.username,
        email                = req.email,
        hashed_password      = hash_password(req.password),
        role                 = req.role,
        is_verified          = False,
        email_verify_token   = token,
        email_verify_expires = expires,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    background.add_task(send_verification_email, req.email, req.username, token)
    logger.info(f"New user registered: {req.username}")

    return {
        "message":  "Account created! Please check your email to verify your account.",
        "username": req.username,
    }


# ── GET /api/auth/verify-email?token=xxx ─────────────────────────────
@router.get("/verify-email")
async def verify_email(token: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email_verify_token == token))
    user   = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=400, detail="Invalid verification token")

    if user.is_verified:
        return {"message": "Email already verified. You can log in."}

    if user.email_verify_expires and user.email_verify_expires < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Token expired. Request a new one.")

    user.is_verified          = True
    user.email_verify_token   = None
    user.email_verify_expires = None
    await db.commit()

    logger.info(f"Email verified: {user.email}")
    return {"message": "Email verified! You can now log in."}


# ── POST /api/auth/login ──────────────────────────────────────────────
@router.post("/login")
async def login(
    form: OAuth2PasswordRequestForm = Depends(),
    db:   AsyncSession              = Depends(get_db),
):
    result = await db.execute(select(User).where(User.username == form.username))
    user   = result.scalar_one_or_none()

    if not user or not verify_password(form.password, user.hashed_password):
        if user:
            user.login_attempts += 1
            if user.login_attempts >= MAX_ATTEMPTS:
                user.locked_until   = datetime.utcnow() + timedelta(minutes=LOCK_MINUTES)
                user.login_attempts = 0
            await db.commit()
        raise HTTPException(status_code=401, detail="Invalid username or password")

    if user.is_locked():
        raise HTTPException(status_code=403, detail=f"Account locked. Try again in {LOCK_MINUTES} minutes.")

    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Email not verified. Check your inbox.")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is deactivated.")

    user.login_attempts = 0
    user.locked_until   = None
    user.last_login     = datetime.utcnow()
    await db.commit()

    access_token  = create_access_token(data={"sub": user.username})
    refresh_token = create_refresh_token(data={"sub": user.username})

    logger.info(f"Login successful: {user.username}")
    return {
        "access_token":  access_token,
        "refresh_token": refresh_token,
        "token_type":    "bearer",
        "username":      user.username,
        "role":          user.role,
    }


# ── POST /api/auth/refresh ────────────────────────────────────────────
@router.post("/refresh")
async def refresh(req: RefreshRequest, db: AsyncSession = Depends(get_db)):
    payload = verify_token(req.refresh_token, token_type="refresh")
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    result = await db.execute(select(User).where(User.username == payload.get("sub")))
    user   = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}


# ── GET /api/auth/me ──────────────────────────────────────────────────
@router.get("/me")
async def me(
    db:   AsyncSession = Depends(get_db),
    user: dict         = Depends(__import__("core.auth", fromlist=["get_current_user"]).get_current_user),
):
    result  = await db.execute(select(User).where(User.username == user.get("sub")))
    db_user = result.scalar_one_or_none()

    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    return db_user.to_dict()


# ── POST /api/auth/forgot-password ───────────────────────────────────
@router.post("/forgot-password")
async def forgot_password(
    req:        ForgotPasswordRequest,
    background: BackgroundTasks,
    db:         AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.email == req.email))
    user   = result.scalar_one_or_none()

    if user and user.is_verified:
        token                    = generate_email_token()
        user.reset_token         = token
        user.reset_token_expires = datetime.utcnow() + timedelta(hours=1)
        await db.commit()
        background.add_task(send_password_reset_email, user.email, user.username, token)

    return {"message": "If that email is registered, a reset link has been sent."}


# ── POST /api/auth/reset-password ────────────────────────────────────
@router.post("/reset-password")
async def reset_password(req: ResetPasswordRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.reset_token == req.token))
    user   = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=400, detail="Invalid reset token")

    if user.reset_token_expires and user.reset_token_expires < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Reset token expired. Request a new one.")

    user.hashed_password     = hash_password(req.new_password)
    user.reset_token         = None
    user.reset_token_expires = None
    await db.commit()

    logger.info(f"Password reset: {user.email}")
    return {"message": "Password reset successful. You can now log in."}
