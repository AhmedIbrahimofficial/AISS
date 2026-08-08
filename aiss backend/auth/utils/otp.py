"""OTP helpers — re-exported from tokens for convenience."""
from auth.utils.tokens import generate_otp, hash_otp

__all__ = ["generate_otp", "hash_otp"]
