"""
Email sending via fastapi-mail (optional).
If fastapi-mail is not installed, emails are silently skipped and
accounts are auto-verified so the app works without SMTP config.
"""

import os
from utils.logger import setup_logger

logger = setup_logger("auth.email")

# ── Optional fastapi-mail ─────────────────────────────────────────────
try:
    from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType
    _FM_AVAILABLE = True
except ImportError:
    _FM_AVAILABLE = False
    logger.warning("fastapi-mail not installed — email sending disabled (auto-verify enabled)")

# ── SMTP config from .env ─────────────────────────────────────────────
_mail_configured = _FM_AVAILABLE and bool(os.environ.get("MAIL_USERNAME", "").strip())

_mailer = None
if _mail_configured:
    try:
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
    except Exception as e:
        logger.warning(f"SMTP config failed: {e} — email sending disabled")
        _mail_configured = False

APP_URL = os.environ.get("APP_URL", "http://localhost:8000")

if not _mail_configured:
    logger.info("SMTP not configured — accounts will be auto-verified on registration")


def is_mail_configured() -> bool:
    return _mail_configured


async def send_verification_email(to_email: str, username: str, token: str) -> None:
    if not _mail_configured or _mailer is None:
        logger.info(f"Auto-verify (no SMTP): {to_email}")
        return
    verify_url = f"{APP_URL}/auth/verify-email?token={token}"
    html = f"""
    <div style="font-family:sans-serif;max-width:480px;margin:auto;padding:32px">
      <h2 style="color:#00ff88">Verify your AISS account</h2>
      <p>Hi <strong>{username}</strong>,</p>
      <p>Click below to verify your email. Expires in <strong>60 minutes</strong>.</p>
      <a href="{verify_url}"
         style="display:inline-block;margin:16px 0;padding:12px 28px;
                background:#00ff88;color:#000;border-radius:8px;
                text-decoration:none;font-weight:600">
        Verify Email
      </a>
    </div>
    """
    try:
        msg = MessageSchema(subject="Verify your AISS account",
                            recipients=[to_email], body=html, subtype=MessageType.html)
        await _mailer.send_message(msg)
        logger.info(f"Verification email sent to {to_email}")
    except Exception as e:
        logger.error(f"Failed to send verification email: {e}")


async def send_otp_email(to_email: str, username: str, otp: str) -> None:
    if not _mail_configured or _mailer is None:
        logger.info(f"Auto-skip OTP email (no SMTP): {to_email}")
        return
    html = f"""
    <div style="font-family:sans-serif;max-width:480px;margin:auto;padding:32px">
      <h2 style="color:#00ff88">Your AISS verification code</h2>
      <p>Hi <strong>{username}</strong>, your code is:</p>
      <div style="font-size:36px;font-weight:700;letter-spacing:8px;
                  color:#00ff88;margin:16px 0;font-family:monospace">{otp}</div>
      <p>Expires in <strong>10 minutes</strong>.</p>
    </div>
    """
    try:
        msg = MessageSchema(subject="Your AISS verification code",
                            recipients=[to_email], body=html, subtype=MessageType.html)
        await _mailer.send_message(msg)
    except Exception as e:
        logger.error(f"Failed to send OTP email: {e}")


async def send_password_reset_email(to_email: str, username: str, token: str) -> None:
    if not _mail_configured or _mailer is None:
        logger.info(f"Auto-skip reset email (no SMTP): {to_email}")
        return
    reset_url = f"{APP_URL}/auth/reset-password?token={token}"
    html = f"""
    <div style="font-family:sans-serif;max-width:480px;margin:auto;padding:32px">
      <h2 style="color:#00ff88">Reset your AISS password</h2>
      <p>Hi <strong>{username}</strong>,</p>
      <p>Click below to reset your password. Expires in <strong>30 minutes</strong>.</p>
      <a href="{reset_url}"
         style="display:inline-block;margin:16px 0;padding:12px 28px;
                background:#00ff88;color:#000;border-radius:8px;
                text-decoration:none;font-weight:600">Reset Password</a>
    </div>
    """
    try:
        msg = MessageSchema(subject="Reset your AISS password",
                            recipients=[to_email], body=html, subtype=MessageType.html)
        await _mailer.send_message(msg)
    except Exception as e:
        logger.error(f"Failed to send reset email: {e}")
