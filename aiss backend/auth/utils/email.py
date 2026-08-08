"""
Email sending via fastapi-mail.
All SMTP config is read from .env — never hardcoded.
"""

import os
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType
from utils.logger import setup_logger

logger = setup_logger("auth.email")

# ── SMTP config from .env ─────────────────────────────────────────────
_conf = ConnectionConfig(
    MAIL_USERNAME   = os.environ.get("MAIL_USERNAME", ""),
    MAIL_PASSWORD   = os.environ.get("MAIL_PASSWORD", ""),
    MAIL_FROM       = os.environ.get("MAIL_FROM", "noreply@aiss.dev"),
    MAIL_FROM_NAME  = os.environ.get("MAIL_FROM_NAME", "AISS Platform"),
    MAIL_PORT       = int(os.environ.get("MAIL_PORT", "587")),
    MAIL_SERVER     = os.environ.get("MAIL_SERVER", "smtp.gmail.com"),
    MAIL_STARTTLS   = os.environ.get("MAIL_STARTTLS", "true").lower() == "true",
    MAIL_SSL_TLS    = os.environ.get("MAIL_SSL_TLS", "false").lower() == "true",
    USE_CREDENTIALS = True,
    VALIDATE_CERTS  = True,
)

_mailer = FastMail(_conf)
APP_URL = os.environ.get("APP_URL", "http://localhost:8000")


async def send_verification_email(to_email: str, username: str, token: str) -> None:
    """Send email verification link."""
    verify_url = f"{APP_URL}/auth/verify-email?token={token}"

    html = f"""
    <div style="font-family:sans-serif;max-width:480px;margin:auto;padding:32px">
      <h2 style="color:#00ff88">Verify your AISS account</h2>
      <p>Hi <strong>{username}</strong>,</p>
      <p>Click the link below to verify your email address.
         The link expires in <strong>60 minutes</strong>.</p>
      <a href="{verify_url}"
         style="display:inline-block;margin:16px 0;padding:12px 28px;
                background:#00ff88;color:#000;border-radius:8px;
                text-decoration:none;font-weight:600">
        Verify Email
      </a>
      <p style="color:#888;font-size:12px">
        If you did not create an account, you can ignore this email.
      </p>
    </div>
    """
    message = MessageSchema(
        subject    = "Verify your AISS account",
        recipients = [to_email],
        body       = html,
        subtype    = MessageType.html,
    )
    try:
        await _mailer.send_message(message)
        logger.info(f"Verification email sent to {to_email}")
    except Exception as e:
        logger.error(f"Failed to send verification email to {to_email}: {e}")


async def send_otp_email(to_email: str, username: str, otp: str) -> None:
    """Send OTP for phone/email 2FA."""
    html = f"""
    <div style="font-family:sans-serif;max-width:480px;margin:auto;padding:32px">
      <h2 style="color:#00ff88">Your AISS verification code</h2>
      <p>Hi <strong>{username}</strong>,</p>
      <p>Your one-time verification code is:</p>
      <div style="font-size:36px;font-weight:700;letter-spacing:8px;
                  color:#00ff88;margin:16px 0;font-family:monospace">
        {otp}
      </div>
      <p>This code expires in <strong>10 minutes</strong>.</p>
      <p style="color:#888;font-size:12px">
        If you did not request this code, your account may be at risk.
        Contact support immediately.
      </p>
    </div>
    """
    message = MessageSchema(
        subject    = "Your AISS verification code",
        recipients = [to_email],
        body       = html,
        subtype    = MessageType.html,
    )
    try:
        await _mailer.send_message(message)
        logger.info(f"OTP email sent to {to_email}")
    except Exception as e:
        logger.error(f"Failed to send OTP email to {to_email}: {e}")


async def send_password_reset_email(to_email: str, username: str, token: str) -> None:
    """Send password reset link."""
    reset_url = f"{APP_URL}/auth/reset-password?token={token}"
    html = f"""
    <div style="font-family:sans-serif;max-width:480px;margin:auto;padding:32px">
      <h2 style="color:#00ff88">Reset your AISS password</h2>
      <p>Hi <strong>{username}</strong>,</p>
      <p>Click the link below to reset your password.
         The link expires in <strong>30 minutes</strong>.</p>
      <a href="{reset_url}"
         style="display:inline-block;margin:16px 0;padding:12px 28px;
                background:#00ff88;color:#000;border-radius:8px;
                text-decoration:none;font-weight:600">
        Reset Password
      </a>
      <p style="color:#888;font-size:12px">
        If you did not request a password reset, ignore this email.
      </p>
    </div>
    """
    message = MessageSchema(
        subject    = "Reset your AISS password",
        recipients = [to_email],
        body       = html,
        subtype    = MessageType.html,
    )
    try:
        await _mailer.send_message(message)
        logger.info(f"Password reset email sent to {to_email}")
    except Exception as e:
        logger.error(f"Failed to send reset email to {to_email}: {e}")
