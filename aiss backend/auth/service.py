"""
Auth — Service Layer
All business logic lives here. Routers are thin wrappers.
"""

import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import HTTPException, Request, status
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from auth.models import AuthUser, AuthSession, VerificationToken, OtpVerification
from auth.schemas import RegisterRequest, LoginRequest
from auth.utils.password import hash_password, verify_password, needs_rehash
from auth.utils.tokens import (
    create_access_token, generate_refresh_token, hash_refresh_token,
    refresh_token_expiry, generate_verification_token, generate_otp, hash_otp,
    ACCESS_TOKEN_EXPIRE_MIN,
)
from auth.utils.email import (
    send_verification_email, send_otp_email, send_password_reset_email,
)
from utils.logger import setup_logger

logger = setup_logger("auth.service")

# ── Config ────────────────────────────────────────────────────────────
MAX_FAILED_ATTEMPTS  = int(os.environ.get("MAX_FAILED_LOGIN_ATTEMPTS", "5"))
LOCKOUT_MINUTES      = int(os.environ.get("LOCKOUT_MINUTES", "30"))
VERIFY_TOKEN_MINUTES = int(os.environ.get("VERIFY_TOKEN_MINUTES", "60"))
OTP_EXPIRE_MINUTES   = int(os.environ.get("OTP_EXPIRE_MINUTES", "10"))
RESET_TOKEN_MINUTES  = int(os.environ.get("RESET_TOKEN_MINUTES", "30"))


def _now() -> datetime:
    return datetime.utcnow()


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ─────────────────────────────────────────────────────────────────────
# REGISTER
# ─────────────────────────────────────────────────────────────────────
async def register_user(data: RegisterRequest, db: AsyncSession) -> AuthUser:
    # Check duplicate email
    existing = await db.scalar(
        select(AuthUser).where(AuthUser.email == data.email.lower())
    )
    if existing:
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")

    # Check duplicate username
    existing_u = await db.scalar(
        select(AuthUser).where(AuthUser.username == data.username)
    )
    if existing_u:
        raise HTTPException(status.HTTP_409_CONFLICT, "Username already taken")

    user = AuthUser(
        username        = data.username,
        email           = data.email.lower(),
        hashed_password = hash_password(data.password),
        phone_number    = data.phone_number,
        is_verified     = False,
    )
    db.add(user)
    await db.flush()  # get user.id before sending email

    # Create email verification token
    token = generate_verification_token()
    vt = VerificationToken(
        user_id    = user.id,
        token      = token,
        token_type = "email_verify",
        expires_at = _now() + timedelta(minutes=VERIFY_TOKEN_MINUTES),
    )
    db.add(vt)
    await db.commit()
    await db.refresh(user)

    # Send verification email (best-effort — don't fail registration)
    try:
        await send_verification_email(user.email, user.username, token)
    except Exception as e:
        logger.error(f"Verification email failed for {user.email}: {e}")

    logger.info(f"New user registered: {user.email}")
    return user


# ─────────────────────────────────────────────────────────────────────
# LOGIN
# ─────────────────────────────────────────────────────────────────────
async def login_user(
    data: LoginRequest,
    request: Request,
    db: AsyncSession,
) -> dict:
    ip = _client_ip(request)
    ua = request.headers.get("User-Agent", "")

    user = await db.scalar(
        select(AuthUser).where(AuthUser.email == data.email.lower())
    )

    # Timing-safe: always run verify_password even if user not found
    _dummy_hash = "$argon2id$v=19$m=65536,t=2,p=2$dGVzdA$dGVzdA"
    stored_hash = user.hashed_password if user else _dummy_hash

    password_ok = verify_password(data.password, stored_hash)

    if not user or not password_ok:
        if user:
            await _handle_failed_login(user, ip, db)
        logger.warning(f"Failed login attempt for {data.email} from {ip}")
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Invalid email or password",
        )

    if not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Account is deactivated")

    if user.is_locked():
        raise HTTPException(
            status.HTTP_423_LOCKED,
            f"Account locked. Try again after {user.locked_until.strftime('%H:%M UTC')}",
        )

    # Reset failed attempts on successful login
    user.failed_login_attempts = 0
    user.locked_until          = None
    user.last_login_at         = _now()
    user.last_login_ip         = ip

    # Upgrade hash if needed (transparent rehash)
    if needs_rehash(user.hashed_password):
        user.hashed_password = hash_password(data.password)
        logger.info(f"Password rehashed for {user.email}")

    # Create session + tokens
    raw_refresh = generate_refresh_token()
    session = AuthSession(
        user_id            = user.id,
        refresh_token_hash = hash_refresh_token(raw_refresh),
        ip_address         = ip,
        user_agent         = ua,
        device_info        = _parse_device(ua),
        expires_at         = refresh_token_expiry(),
    )
    db.add(session)
    await db.commit()

    access_token = create_access_token(
        user_id = user.id,
        email   = user.email,
        role    = user.role,
    )

    logger.info(f"Successful login: {user.email} from {ip}")
    return {
        "access_token":  access_token,
        "refresh_token": raw_refresh,
        "expires_in":    ACCESS_TOKEN_EXPIRE_MIN * 60,
    }


async def _handle_failed_login(user: AuthUser, ip: str, db: AsyncSession) -> None:
    user.failed_login_attempts += 1
    user.last_failed_ip = ip

    if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
        user.locked_until = _now() + timedelta(minutes=LOCKOUT_MINUTES)
        logger.warning(
            f"Account locked: {user.email} after {user.failed_login_attempts} "
            f"failed attempts from {ip}"
        )
    await db.commit()


# ─────────────────────────────────────────────────────────────────────
# REFRESH TOKEN ROTATION
# ─────────────────────────────────────────────────────────────────────
async def refresh_tokens(raw_token: str, request: Request, db: AsyncSession) -> dict:
    token_hash = hash_refresh_token(raw_token)

    session = await db.scalar(
        select(AuthSession).where(AuthSession.refresh_token_hash == token_hash)
    )

    if not session or not session.is_valid():
        if session:
            # Possible token theft — revoke all sessions for this user
            await _revoke_all_sessions(session.user_id, db)
            logger.warning(
                f"Refresh token reuse detected for user {session.user_id} "
                f"from {_client_ip(request)} — all sessions revoked"
            )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired refresh token")

    user = await db.get(AuthUser, session.user_id)
    if not user or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found or inactive")

    # Rotate: invalidate old token, issue new one
    session.is_revoked = True

    new_raw     = generate_refresh_token()
    new_session = AuthSession(
        user_id            = user.id,
        refresh_token_hash = hash_refresh_token(new_raw),
        ip_address         = _client_ip(request),
        user_agent         = request.headers.get("User-Agent", ""),
        device_info        = session.device_info,
        expires_at         = refresh_token_expiry(),
    )
    db.add(new_session)
    await db.commit()

    new_access = create_access_token(user.id, user.email, user.role)
    return {
        "access_token":  new_access,
        "refresh_token": new_raw,
        "expires_in":    ACCESS_TOKEN_EXPIRE_MIN * 60,
    }


async def _revoke_all_sessions(user_id: str, db: AsyncSession) -> None:
    sessions = await db.scalars(
        select(AuthSession).where(
            AuthSession.user_id == user_id,
            AuthSession.is_revoked == False,
        )
    )
    for s in sessions:
        s.is_revoked = True
    await db.commit()


# ─────────────────────────────────────────────────────────────────────
# LOGOUT
# ─────────────────────────────────────────────────────────────────────
async def logout_user(raw_token: str, db: AsyncSession) -> None:
    token_hash = hash_refresh_token(raw_token)
    session = await db.scalar(
        select(AuthSession).where(AuthSession.refresh_token_hash == token_hash)
    )
    if session:
        session.is_revoked = True
        await db.commit()
    logger.info("Session revoked on logout")


# ─────────────────────────────────────────────────────────────────────
# EMAIL VERIFICATION
# ─────────────────────────────────────────────────────────────────────
async def verify_email(token: str, db: AsyncSession) -> AuthUser:
    vt = await db.scalar(
        select(VerificationToken).where(
            VerificationToken.token      == token,
            VerificationToken.token_type == "email_verify",
        )
    )

    if not vt or not vt.is_valid():
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Invalid or expired verification link"
        )

    user = await db.get(AuthUser, vt.user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")

    user.is_verified = True
    vt.used_at       = _now()
    await db.commit()
    logger.info(f"Email verified: {user.email}")
    return user


# ─────────────────────────────────────────────────────────────────────
# OTP
# ─────────────────────────────────────────────────────────────────────
async def send_otp(user: AuthUser, purpose: str, db: AsyncSession) -> None:
    # Invalidate previous OTPs for same user+purpose
    old_otps = await db.scalars(
        select(OtpVerification).where(
            OtpVerification.user_id     == user.id,
            OtpVerification.purpose     == purpose,
            OtpVerification.verified_at == None,
        )
    )
    for o in old_otps:
        o.expires_at = _now()  # expire immediately

    otp      = generate_otp()
    otp_rec  = OtpVerification(
        user_id    = user.id,
        otp_hash   = hash_otp(otp),
        purpose    = purpose,
        expires_at = _now() + timedelta(minutes=OTP_EXPIRE_MINUTES),
    )
    db.add(otp_rec)
    await db.commit()

    await send_otp_email(user.email, user.username, otp)
    logger.info(f"OTP sent to {user.email} for {purpose}")


async def verify_otp(user: AuthUser, otp_code: str, purpose: str, db: AsyncSession) -> None:
    otp_rec = await db.scalar(
        select(OtpVerification).where(
            OtpVerification.user_id     == user.id,
            OtpVerification.purpose     == purpose,
            OtpVerification.verified_at == None,
        ).order_by(OtpVerification.expires_at.desc())
    )

    if not otp_rec:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No active OTP found. Request a new one.")

    otp_rec.attempts += 1

    if not otp_rec.is_valid():
        await db.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "OTP expired or too many attempts")

    if otp_rec.otp_hash != hash_otp(otp_code):
        await db.commit()
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Incorrect OTP. {otp_rec.MAX_ATTEMPTS - otp_rec.attempts} attempts remaining"
        )

    otp_rec.verified_at = _now()

    if purpose == "phone_verify":
        user.is_phone_verified = True

    await db.commit()
    logger.info(f"OTP verified for {user.email} ({purpose})")


# ─────────────────────────────────────────────────────────────────────
# PASSWORD RESET
# ─────────────────────────────────────────────────────────────────────
async def forgot_password(email: str, db: AsyncSession) -> None:
    user = await db.scalar(
        select(AuthUser).where(AuthUser.email == email.lower())
    )
    # Always succeed — don't reveal if email exists
    if not user:
        return

    token = generate_verification_token()
    vt = VerificationToken(
        user_id    = user.id,
        token      = token,
        token_type = "password_reset",
        expires_at = _now() + timedelta(minutes=RESET_TOKEN_MINUTES),
    )
    db.add(vt)
    await db.commit()
    await send_password_reset_email(user.email, user.username, token)


async def reset_password(token: str, new_password: str, db: AsyncSession) -> None:
    vt = await db.scalar(
        select(VerificationToken).where(
            VerificationToken.token      == token,
            VerificationToken.token_type == "password_reset",
        )
    )
    if not vt or not vt.is_valid():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid or expired reset link")

    user = await db.get(AuthUser, vt.user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")

    user.hashed_password  = hash_password(new_password)
    user.failed_login_attempts = 0
    user.locked_until     = None
    vt.used_at            = _now()

    # Revoke all existing sessions after password reset
    await _revoke_all_sessions(user.id, db)
    await db.commit()
    logger.info(f"Password reset completed for {user.email}")


# ── Helpers ───────────────────────────────────────────────────────────
def _parse_device(ua: str) -> str:
    ua_lower = ua.lower()
    if "mobile" in ua_lower or "android" in ua_lower or "iphone" in ua_lower:
        return "mobile"
    if "tablet" in ua_lower or "ipad" in ua_lower:
        return "tablet"
    return "desktop"


# ─────────────────────────────────────────────────────────────────────
# RESEND VERIFICATION
# ─────────────────────────────────────────────────────────────────────
async def resend_verification_email(user: AuthUser, db: AsyncSession) -> None:
    token = generate_verification_token()
    vt = VerificationToken(
        user_id    = user.id,
        token      = token,
        token_type = "email_verify",
        expires_at = _now() + timedelta(minutes=VERIFY_TOKEN_MINUTES),
    )
    db.add(vt)
    await db.commit()
    await send_verification_email(user.email, user.username, token)


# ─────────────────────────────────────────────────────────────────────
# SESSION MANAGEMENT
# ─────────────────────────────────────────────────────────────────────
async def get_user_sessions(user_id: str, db: AsyncSession) -> list[dict]:
    sessions = await db.scalars(
        select(AuthSession).where(
            AuthSession.user_id    == user_id,
            AuthSession.is_revoked == False,
        ).order_by(AuthSession.created_at.desc())
    )
    return [
        {
            "id":          s.id,
            "device_info": s.device_info,
            "ip_address":  s.ip_address,
            "created_at":  s.created_at.isoformat(),
            "expires_at":  s.expires_at.isoformat(),
            "last_used_at": s.last_used_at.isoformat() if s.last_used_at else None,
        }
        for s in sessions
    ]


async def revoke_session(session_id: str, user_id: str, db: AsyncSession) -> None:
    session = await db.scalar(
        select(AuthSession).where(
            AuthSession.id      == session_id,
            AuthSession.user_id == user_id,     # users can only revoke their own
        )
    )
    if not session:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found")
    session.is_revoked = True
    await db.commit()
