"""
AISS — Onboarding + Device Pairing API
Real endpoints backed by the database.
"""
import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from core.database import get_db
from auth.dependencies import get_current_user
from auth.models import AuthUser, AuthOnboarding, RegisteredDevice, AuthSession
from auth.utils.tokens import (
    create_access_token, generate_refresh_token,
    hash_refresh_token, refresh_token_expiry,
)
from utils.logger import setup_logger

logger = setup_logger("auth_guard")

router = APIRouter(prefix="/auth", tags=["Onboarding & Devices"])

PAIRING_TOKEN_EXPIRE_MINUTES = 15   # Pairing tokens expire in 15 minutes


# ──────────────────────────────────────────────────────────────────────
# ONBOARDING
# ──────────────────────────────────────────────────────────────────────

@router.get("/onboarding")
async def get_onboarding_status(
    current_user: AuthUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return the current user's onboarding state from the database."""
    # Ensure onboarding record exists
    ob = await db.scalar(
        select(AuthOnboarding).where(AuthOnboarding.user_id == current_user.id)
    )
    if not ob:
        ob = AuthOnboarding(user_id=current_user.id)
        db.add(ob)
        await db.commit()
        await db.refresh(ob)

    import json
    return {
        "is_completed":      ob.is_completed,
        "completed_at":      ob.completed_at.isoformat() if ob.completed_at else None,
        "completed_steps":   json.loads(ob.completed_steps) if ob.completed_steps else [],
        "reset_at":          ob.reset_at.isoformat() if ob.reset_at else None,
    }


class CompleteOnboardingRequest(BaseModel):
    completed_steps: list[str] = []


@router.post("/onboarding/complete")
async def complete_onboarding(
    body: CompleteOnboardingRequest,
    current_user: AuthUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Mark onboarding as complete. This state persists across restarts."""
    import json
    ob = await db.scalar(
        select(AuthOnboarding).where(AuthOnboarding.user_id == current_user.id)
    )
    if not ob:
        ob = AuthOnboarding(user_id=current_user.id)
        db.add(ob)

    ob.is_completed      = True
    ob.completed_at      = datetime.utcnow()
    ob.completed_steps   = json.dumps(body.completed_steps)
    await db.commit()

    logger.info(f"Onboarding completed for user {current_user.email}")
    return {"status": "completed", "completed_at": ob.completed_at.isoformat()}


@router.post("/onboarding/reset")
async def reset_onboarding(
    current_user: AuthUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Admin-only: reset onboarding so it shows again on next login."""
    if current_user.role != "admin":
        raise HTTPException(403, "Admin only")
    ob = await db.scalar(
        select(AuthOnboarding).where(AuthOnboarding.user_id == current_user.id)
    )
    if ob:
        ob.reset()
        await db.commit()
    return {"status": "reset"}


# ──────────────────────────────────────────────────────────────────────
# DEVICE PAIRING
# ──────────────────────────────────────────────────────────────────────

class GeneratePairingRequest(BaseModel):
    device_name: str = "New Device"
    device_type: str = "desktop"


@router.post("/devices/pairing-token")
async def generate_pairing_token(
    body: GeneratePairingRequest,
    current_user: AuthUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Generate a cryptographically random, single-use, time-limited pairing token.
    The plaintext token is returned ONCE — only the hash is stored in the DB.
    """
    # Generate a 32-byte random token (64 hex chars) — not guessable
    raw_token   = secrets.token_hex(32)
    token_hash  = hashlib.sha256(raw_token.encode()).hexdigest()
    expires_at  = datetime.utcnow() + timedelta(minutes=PAIRING_TOKEN_EXPIRE_MINUTES)

    device = RegisteredDevice(
        user_id            = current_user.id,
        device_name        = body.device_name,
        device_type        = body.device_type,
        pairing_token_hash = token_hash,
        pairing_expires_at = expires_at,
        status             = "pending",
    )
    db.add(device)
    await db.commit()
    await db.refresh(device)

    logger.info(f"Pairing token generated for user {current_user.email}, device '{body.device_name}'")
    return {
        "device_id":    device.id,
        "pairing_token": raw_token,      # shown to user ONCE — never stored again
        "expires_at":   expires_at.isoformat(),
        "expires_in_seconds": PAIRING_TOKEN_EXPIRE_MINUTES * 60,
        "instructions": (
            "On the remote machine, run AISS and enter this pairing token. "
            "Token expires in 15 minutes and is single-use."
        ),
    }


class PairDeviceRequest(BaseModel):
    pairing_token:  str
    device_name:    Optional[str] = None
    device_type:    str           = "desktop"
    platform:       Optional[str] = None
    hostname:       Optional[str] = None
    os_info:        Optional[str] = None


@router.post("/devices/pair")
async def pair_device(
    body: PairDeviceRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Validate a pairing token and complete device registration.
    Returns a long-lived device secret for the newly paired device.
    No authentication required — the pairing token IS the credential.
    """
    token_hash = hashlib.sha256(body.pairing_token.encode()).hexdigest()

    device = await db.scalar(
        select(RegisteredDevice).where(
            RegisteredDevice.pairing_token_hash == token_hash,
            RegisteredDevice.is_paired == False,
            RegisteredDevice.is_revoked == False,
        )
    )

    if not device:
        raise HTTPException(404, "Invalid pairing token")

    if not device.is_pairing_valid():
        raise HTTPException(410, "Pairing token has expired or already been used")

    # Invalidate the one-time pairing token
    device.pairing_token_hash = None
    device.pairing_used_at    = datetime.utcnow()
    device.is_paired          = True
    device.paired_at          = datetime.utcnow()
    device.status             = "paired"

    # Update device metadata from the connecting machine
    if body.device_name:  device.device_name = body.device_name
    device.device_type = body.device_type
    device.platform    = body.platform
    device.hostname    = body.hostname
    device.os_info     = body.os_info
    device.last_seen_ip = request.client.host if request.client else None
    device.last_seen_at = datetime.utcnow()

    # Issue long-lived device secret (used for subsequent device auth)
    raw_secret  = secrets.token_hex(48)
    device.device_secret_hash    = hashlib.sha256(raw_secret.encode()).hexdigest()
    device.device_secret_expires = datetime.utcnow() + timedelta(days=365)

    # Also create a user session for the device so it can call APIs
    user = await db.get(AuthUser, device.user_id)
    raw_refresh = generate_refresh_token()
    session = AuthSession(
        user_id            = device.user_id,
        refresh_token_hash = hash_refresh_token(raw_refresh),
        ip_address         = device.last_seen_ip,
        user_agent         = request.headers.get("User-Agent", ""),
        device_info        = f"device:{device.id}",
        expires_at         = refresh_token_expiry(),
    )
    db.add(session)
    await db.commit()

    access_token = create_access_token(
        user_id = user.id,
        email   = user.email,
        role    = user.role,
        extra   = {"device_id": device.id},
    )

    logger.info(f"Device paired: '{device.device_name}' for user {user.email} from {device.last_seen_ip}")
    return {
        "status":         "paired",
        "device_id":      device.id,
        "device_name":    device.device_name,
        "device_secret":  raw_secret,        # store this securely on the device
        "access_token":   access_token,
        "refresh_token":  raw_refresh,
        "user_email":     user.email,
        "message":        "Device successfully paired. Store the device_secret securely.",
    }


@router.get("/devices")
async def list_devices(
    current_user: AuthUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all devices registered to the current user."""
    devices = await db.scalars(
        select(RegisteredDevice).where(
            RegisteredDevice.user_id    == current_user.id,
            RegisteredDevice.is_revoked == False,
        ).order_by(RegisteredDevice.created_at.desc())
    )
    return {"devices": [d.to_dict() for d in devices]}


class RevokeDeviceRequest(BaseModel):
    reason: str = "Revoked by user"


@router.post("/devices/{device_id}/revoke")
async def revoke_device(
    device_id: str,
    body: RevokeDeviceRequest,
    current_user: AuthUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Revoke a device — user can only revoke their own devices."""
    device = await db.scalar(
        select(RegisteredDevice).where(
            RegisteredDevice.id      == device_id,
            RegisteredDevice.user_id == current_user.id,   # ownership check
        )
    )
    if not device:
        raise HTTPException(404, "Device not found")

    device.is_revoked     = True
    device.revoked_at     = datetime.utcnow()
    device.revoke_reason  = body.reason
    device.status         = "revoked"
    device.device_secret_hash = None   # invalidate credential
    await db.commit()

    logger.info(f"Device revoked: {device_id} for user {current_user.email} — {body.reason}")
    return {"status": "revoked", "device_id": device_id}


@router.get("/devices/{device_id}/status")
async def device_status(
    device_id: str,
    current_user: AuthUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get real-time status of a specific device."""
    device = await db.scalar(
        select(RegisteredDevice).where(
            RegisteredDevice.id      == device_id,
            RegisteredDevice.user_id == current_user.id,
        )
    )
    if not device:
        raise HTTPException(404, "Device not found")

    return {
        **device.to_dict(),
        "pairing_still_valid": device.is_pairing_valid(),
    }
