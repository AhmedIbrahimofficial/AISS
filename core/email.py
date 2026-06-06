"""
core/email.py — Send verification & password-reset emails via SMTP

Set these in your .env file:
SMTP_HOST      = smtp.gmail.com
SMTP_PORT      = 587
SMTP_USER      = youremail@gmail.com
SMTP_PASSWORD  = your-gmail-app-password
FRONTEND_URL   = http://localhost:3000
"""

import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from utils.logger import setup_logger

logger = setup_logger("email")

SMTP_HOST    = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT    = int(os.environ.get("SMTP_PORT", 587))
SMTP_USER    = os.environ.get("SMTP_USER", "")
SMTP_PASS    = os.environ.get("SMTP_PASSWORD", "")
FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:3000")


def _send(to: str, subject: str, html: str) -> None:
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = f"CyberSentinel <{SMTP_USER}>"
    msg["To"]      = to
    msg.attach(MIMEText(html, "html"))

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.ehlo()
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_USER, to, msg.as_string())


def send_verification_email(to_email: str, username: str, token: str) -> None:
    link = f"{FRONTEND_URL}/verify-email?token={token}"
    html = f"""
<div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;background:#0d1117;color:#e6edf3;padding:32px;border-radius:12px;">
  <h1 style="color:#58a6ff;">🛡️ CyberSentinel</h1>
  <h2>Verify Your Email</h2>
  <p>Hi <strong>{username}</strong>,</p>
  <p>Click below to verify your email and activate your account.</p>
  <a href="{link}"
     style="display:inline-block;margin:24px 0;padding:14px 28px;background:#238636;color:#fff;border-radius:8px;text-decoration:none;font-weight:bold;">
    Verify Email
  </a>
  <p style="color:#8b949e;font-size:12px;">Link expires in 24 hours. If you did not register, ignore this email.</p>
</div>"""
    try:
        _send(to_email, "Verify your CyberSentinel account", html)
        logger.info(f"Verification email sent to {to_email}")
    except Exception as e:
        logger.error(f"Failed to send verification email: {e}")
        raise


def send_password_reset_email(to_email: str, username: str, token: str) -> None:
    link = f"{FRONTEND_URL}/reset-password?token={token}"
    html = f"""
<div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;background:#0d1117;color:#e6edf3;padding:32px;border-radius:12px;">
  <h1 style="color:#58a6ff;">🛡️ CyberSentinel</h1>
  <h2>Reset Your Password</h2>
  <p>Hi <strong>{username}</strong>,</p>
  <p>Click below to reset your password.</p>
  <a href="{link}"
     style="display:inline-block;margin:24px 0;padding:14px 28px;background:#da3633;color:#fff;border-radius:8px;text-decoration:none;font-weight:bold;">
    Reset Password
  </a>
  <p style="color:#8b949e;font-size:12px;">Link expires in 1 hour. If you did not request this, ignore this email.</p>
</div>"""
    try:
        _send(to_email, "Reset your CyberSentinel password", html)
        logger.info(f"Password reset email sent to {to_email}")
    except Exception as e:
        logger.error(f"Failed to send reset email: {e}")
        raise
