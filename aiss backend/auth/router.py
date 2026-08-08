"""
Auth — API Router
All endpoints are thin: validate input → call service → return response.
Rate limiting applied on sensitive endpoints via slowapi.
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.ext.asyncio import AsyncSession

from auth import service
from auth.dependencies import get_current_user, get_current_verified_user
from auth.schemas import (
    RegisterRequest, RegisterResponse,
    LoginRequest, TokenResponse,
    RefreshRequest, LogoutRequest,
    VerifyEmailResponse, SendOtpRequest, VerifyOtpRequest,
    ForgotPasswordRequest, ResetPasswordRequest,
    UserProfile, MessageResponse,
)
from core.database import get_db

router  = APIRouter(prefix="/auth", tags=["Authentication"])
limiter = Limiter(key_func=get_remote_address)


# ── POST /auth/register ───────────────────────────────────────────────
@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
)
@limiter.limit("5/minute")
async def register(
    request: Request,
    data:    RegisterRequest,
    db:      AsyncSession = Depends(get_db),
):
    user = await service.register_user(data, db)
    return RegisterResponse(
        user_id  = user.id,
        username = user.username,
        email    = user.email,
        message  = "Registration successful. Please verify your email.",
    )


# ── POST /auth/login ──────────────────────────────────────────────────
@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Login and receive access + refresh tokens",
)
@limiter.limit("10/minute")
async def login(
    request: Request,
    data:    LoginRequest,
    db:      AsyncSession = Depends(get_db),
):
    tokens = await service.login_user(data, request, db)
    return TokenResponse(**tokens)


# ── POST /auth/refresh ────────────────────────────────────────────────
@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Rotate refresh token and get new access token",
)
async def refresh(
    data:    RefreshRequest,
    request: Request,
    db:      AsyncSession = Depends(get_db),
):
    tokens = await service.refresh_tokens(data.refresh_token, request, db)
    return TokenResponse(**tokens)


# ── POST /auth/logout ─────────────────────────────────────────────────
@router.post(
    "/logout",
    response_model=MessageResponse,
    summary="Revoke refresh token / end session",
)
async def logout(
    data: LogoutRequest,
    db:   AsyncSession = Depends(get_db),
):
    await service.logout_user(data.refresh_token, db)
    return MessageResponse(message="Logged out successfully")


# ── GET /auth/verify-email ────────────────────────────────────────────
@router.get(
    "/verify-email",
    response_model=VerifyEmailResponse,
    summary="Verify email using token from link",
)
async def verify_email(
    token: str,
    db:    AsyncSession = Depends(get_db),
):
    user = await service.verify_email(token, db)
    return VerifyEmailResponse(
        message = "Email verified successfully. You can now log in.",
        email   = user.email,
    )


# ── POST /auth/resend-verification ───────────────────────────────────
@router.post(
    "/resend-verification",
    response_model=MessageResponse,
    summary="Resend email verification link",
)
async def resend_verification(
    current_user = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if current_user.is_verified:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Email already verified")
    await service.resend_verification_email(current_user, db)
    return MessageResponse(message="Verification email sent")


# ── POST /auth/send-otp ───────────────────────────────────────────────
@router.post(
    "/send-otp",
    response_model=MessageResponse,
    summary="Send OTP for 2FA or phone verification",
)
async def send_otp(
    data:         SendOtpRequest,
    current_user = Depends(get_current_user),
    db:           AsyncSession = Depends(get_db),
):
    valid_purposes = {"phone_verify", "login_2fa", "email_otp"}
    if data.purpose not in valid_purposes:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Invalid purpose. Choose: {valid_purposes}")
    await service.send_otp(current_user, data.purpose, db)
    return MessageResponse(message=f"OTP sent to {current_user.email}")


# ── POST /auth/verify-otp ─────────────────────────────────────────────
@router.post(
    "/verify-otp",
    response_model=MessageResponse,
    summary="Verify OTP code",
)
async def verify_otp(
    data:         VerifyOtpRequest,
    current_user = Depends(get_current_user),
    db:           AsyncSession = Depends(get_db),
):
    await service.verify_otp(current_user, data.otp, data.purpose, db)
    return MessageResponse(message="OTP verified successfully")


# ── GET /auth/me ──────────────────────────────────────────────────────
@router.get(
    "/me",
    response_model=UserProfile,
    summary="Get current user profile",
)
async def me(current_user = Depends(get_current_user)):
    return UserProfile(
        id                = current_user.id,
        username          = current_user.username,
        email             = current_user.email,
        role              = current_user.role,
        is_verified       = current_user.is_verified,
        is_phone_verified = current_user.is_phone_verified,
        created_at        = current_user.created_at,
        last_login_at     = current_user.last_login_at,
    )


# ── POST /auth/forgot-password ────────────────────────────────────────
@router.post(
    "/forgot-password",
    response_model=MessageResponse,
    summary="Request password reset email",
)
@limiter.limit("3/minute")
async def forgot_password(
    request: Request,
    data:    ForgotPasswordRequest,
    db:      AsyncSession = Depends(get_db),
):
    await service.forgot_password(data.email, db)
    # Always return same message — don't reveal if email exists
    return MessageResponse(
        message="If that email is registered, a reset link has been sent."
    )


# ── POST /auth/reset-password ─────────────────────────────────────────
@router.post(
    "/reset-password",
    response_model=MessageResponse,
    summary="Reset password using token from email",
)
async def reset_password(
    data: ResetPasswordRequest,
    db:   AsyncSession = Depends(get_db),
):
    await service.reset_password(data.token, data.new_password, db)
    return MessageResponse(
        message="Password reset successful. All sessions have been revoked. Please log in again."
    )


# ── GET /auth/sessions ────────────────────────────────────────────────
@router.get(
    "/sessions",
    summary="List all active sessions for current user",
)
async def list_sessions(
    current_user = Depends(get_current_user),
    db:   AsyncSession = Depends(get_db),
):
    sessions = await service.get_user_sessions(current_user.id, db)
    return {"sessions": sessions}


# ── DELETE /auth/sessions/{session_id} ───────────────────────────────
@router.delete(
    "/sessions/{session_id}",
    response_model=MessageResponse,
    summary="Revoke a specific session",
)
async def revoke_session(
    session_id:   str,
    current_user = Depends(get_current_user),
    db:           AsyncSession = Depends(get_db),
):
    await service.revoke_session(session_id, current_user.id, db)
    return MessageResponse(message="Session revoked")
