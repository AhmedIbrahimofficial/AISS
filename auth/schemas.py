"""
Auth — Pydantic request/response schemas
Strict validation at the API boundary.
"""

import re
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, field_validator, model_validator


# ── Register ──────────────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    username: str
    email:    EmailStr
    password: str
    phone_number: Optional[str] = None

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 3 or len(v) > 32:
            raise ValueError("Username must be 3–32 characters")
        if not re.match(r"^[a-zA-Z0-9_.-]+$", v):
            raise ValueError("Username can only contain letters, numbers, _, -, .")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        from auth.utils.password import validate_password_strength
        violations = validate_password_strength(v)
        if violations:
            raise ValueError(f"Password must contain: {', '.join(violations)}")
        return v

    @field_validator("phone_number")
    @classmethod
    def validate_phone(cls, v: Optional[str]) -> Optional[str]:
        if v and not re.match(r"^\+?[1-9]\d{7,14}$", v):
            raise ValueError("Invalid phone number format (use E.164: +923001234567)")
        return v


class RegisterResponse(BaseModel):
    user_id:  str
    username: str
    email:    str
    message:  str


# ── Login ─────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    email:    EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token:  str
    refresh_token: str
    token_type:    str = "bearer"
    expires_in:    int             # seconds until access token expiry


# ── Refresh ───────────────────────────────────────────────────────────
class RefreshRequest(BaseModel):
    refresh_token: str


# ── Logout ────────────────────────────────────────────────────────────
class LogoutRequest(BaseModel):
    refresh_token: str


# ── Email verification ────────────────────────────────────────────────
class VerifyEmailResponse(BaseModel):
    message: str
    email:   str


# ── OTP ───────────────────────────────────────────────────────────────
class SendOtpRequest(BaseModel):
    purpose: str = "login_2fa"   # "phone_verify" | "login_2fa" | "email_otp"


class VerifyOtpRequest(BaseModel):
    otp:     str
    purpose: str = "login_2fa"

    @field_validator("otp")
    @classmethod
    def validate_otp(cls, v: str) -> str:
        if not re.match(r"^\d{6}$", v):
            raise ValueError("OTP must be a 6-digit number")
        return v


# ── Me ────────────────────────────────────────────────────────────────
class UserProfile(BaseModel):
    id:               str
    username:         str
    email:            str
    role:             str
    is_verified:      bool
    is_phone_verified: bool
    created_at:       datetime
    last_login_at:    Optional[datetime]

    class Config:
        from_attributes = True


# ── Password reset ────────────────────────────────────────────────────
class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token:        str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        from auth.utils.password import validate_password_strength
        violations = validate_password_strength(v)
        if violations:
            raise ValueError(f"Password must contain: {', '.join(violations)}")
        return v


# ── Generic message ───────────────────────────────────────────────────
class MessageResponse(BaseModel):
    message: str
