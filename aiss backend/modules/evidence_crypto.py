"""AISS - Evidence Encryption Module
Encrypts evidence files before writing to disk using Fernet symmetric encryption.
Key is loaded from EVIDENCE_ENCRYPTION_KEY env var (or auto-generated on first run).

Usage:
    from modules.evidence_crypto import write_encrypted, read_encrypted, get_key_status
    write_encrypted("/path/to/evidence/file.json.enc", b"raw data")
    data = read_encrypted("/path/to/evidence/file.json.enc")

Environment:
    EVIDENCE_ENCRYPTION_KEY — Base64-encoded Fernet key (44 chars)
    If not set, a key is auto-generated and logged once at startup.
    Set EVIDENCE_ENCRYPT=false to disable encryption entirely.
"""

import base64
import os
from typing import Optional
from utils.logger import setup_logger

logger = setup_logger("evidence_crypto")

ENCRYPT_ENABLED = os.environ.get("EVIDENCE_ENCRYPT", "true").lower() != "false"
_fernet = None
_key_source = ""


def _get_fernet():
    """Lazy-load Fernet instance from env key or auto-generate."""
    global _fernet, _key_source

    if _fernet is not None:
        return _fernet

    if not ENCRYPT_ENABLED:
        return None

    try:
        from cryptography.fernet import Fernet
    except ImportError:
        logger.warning("cryptography not installed — evidence encryption disabled")
        return None

    raw_key = os.environ.get("EVIDENCE_ENCRYPTION_KEY", "")

    if raw_key:
        try:
            _fernet = Fernet(raw_key.encode() if isinstance(raw_key, str) else raw_key)
            _key_source = "env:EVIDENCE_ENCRYPTION_KEY"
            logger.info("✅ Evidence encryption: key loaded from EVIDENCE_ENCRYPTION_KEY")
        except Exception as e:
            logger.error(f"Invalid EVIDENCE_ENCRYPTION_KEY: {e} — generating new key")
            raw_key = ""

    if not raw_key:
        from cryptography.fernet import Fernet
        new_key = Fernet.generate_key()
        _fernet = Fernet(new_key)
        _key_source = "auto-generated"
        logger.warning(
            "⚠️  EVIDENCE_ENCRYPTION_KEY not set — auto-generated key in use.\n"
            f"   Set this in .env to persist across restarts:\n"
            f"   EVIDENCE_ENCRYPTION_KEY={new_key.decode()}"
        )

    return _fernet


def write_encrypted(filepath: str, data: bytes) -> str:
    """
    Write data to filepath, encrypted with Fernet if encryption is enabled.
    Returns the actual path written (may have .enc appended).
    """
    fernet = _get_fernet()

    if fernet is None:
        # Write plaintext
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "wb") as f:
            f.write(data)
        return filepath

    # Encrypt and write
    enc_path = filepath if filepath.endswith(".enc") else filepath + ".enc"
    os.makedirs(os.path.dirname(enc_path), exist_ok=True)
    try:
        encrypted = fernet.encrypt(data)
        with open(enc_path, "wb") as f:
            f.write(encrypted)
        return enc_path
    except Exception as e:
        logger.error(f"Evidence encryption failed: {e} — writing plaintext")
        with open(filepath, "wb") as f:
            f.write(data)
        return filepath


def read_encrypted(filepath: str) -> Optional[bytes]:
    """
    Read and decrypt an encrypted evidence file.
    Returns decrypted bytes, or None on error.
    """
    if not os.path.exists(filepath):
        return None

    fernet = _get_fernet()
    try:
        with open(filepath, "rb") as f:
            raw = f.read()

        if fernet is None or not filepath.endswith(".enc"):
            return raw

        return fernet.decrypt(raw)
    except Exception as e:
        logger.error(f"Evidence decryption failed for {filepath}: {e}")
        return None


def write_json_encrypted(filepath: str, data: dict) -> str:
    """
    Serialize dict to JSON and write encrypted.
    Convenience wrapper for evidence collection.
    """
    import json
    raw = json.dumps(data, indent=2, default=str).encode("utf-8")
    return write_encrypted(filepath, raw)


def read_json_encrypted(filepath: str) -> Optional[dict]:
    """Read and decrypt a JSON evidence file."""
    import json
    raw = read_encrypted(filepath)
    if raw is None:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception as e:
        logger.error(f"JSON parse failed for decrypted file {filepath}: {e}")
        return None


def get_key_status() -> dict:
    """Return encryption status (safe to expose via API — no key values)."""
    _get_fernet()  # ensure initialized
    return {
        "encryption_enabled": ENCRYPT_ENABLED,
        "fernet_ready":       _fernet is not None,
        "key_source":         _key_source or "not initialized",
    }
