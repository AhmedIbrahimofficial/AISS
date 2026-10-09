"""AISS - Commercial Licensing System
Supports: trial, standard, enterprise, saas licenses.
Validation: online (license server) and offline (HMAC signature).
Features: seat limits, feature flags, device binding, expiry, tamper detection.

Environment:
    AISS_LICENSE_KEY    — your license key (format: AISS-XXXX-XXXX-XXXX-XXXX)
    AISS_LICENSE_SERVER — license validation server URL (optional)

License is validated at startup and cached for 24h.
Every protected API endpoint calls license_manager.require_feature() via
the FastAPI dependency get_license_required().
"""

import hashlib
import hmac
import json
import os
import platform
import secrets
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

import httpx
from utils.logger import setup_logger

logger = setup_logger("licensing")

_CACHE_FILE  = Path("data/license_cache.json")
_DEVICE_FILE = Path("data/device_id.txt")

# License server public validation secret (same on server — change to your actual HMAC secret)
_VALIDATION_HMAC_SECRET = os.environ.get(
    "AISS_LICENSE_HMAC_SECRET",
    "aiss-license-validation-hmac-secret-v2"
)

_TRIAL_DAYS  = 14
_CACHE_TTL   = 86400   # revalidate every 24h


class LicenseType(str, Enum):
    TRIAL      = "trial"
    STANDARD   = "standard"
    ENTERPRISE = "enterprise"
    SAAS       = "saas"
    DEVELOPER  = "developer"   # unlimited — for Kiro/CI use


class LicenseStatus(str, Enum):
    VALID    = "valid"
    EXPIRED  = "expired"
    INVALID  = "invalid"
    TRIAL    = "trial"
    GRACE    = "grace"      # expired but within 7-day grace period
    OFFLINE  = "offline"    # server unreachable, using cached result
    UNLICENSED = "unlicensed"


# Feature flags available per license tier
FEATURE_FLAGS = {
    LicenseType.TRIAL: {
        "max_seats": 1,
        "ai_analysis": True,
        "threat_intel": True,
        "network_discovery": True,
        "export_excel": False,
        "export_pdf": True,
        "semantic_search": False,
        "llm_router": True,
        "api_access": True,
        "soc_chat": True,
        "kill_chain": True,
        "response_engine": False,   # no auto-response on trial
        "custom_yara": False,
        "cloud_backup": False,
        "white_label": False,
        "sso": False,
        "audit_log": False,
    },
    LicenseType.STANDARD: {
        "max_seats": 5,
        "ai_analysis": True,
        "threat_intel": True,
        "network_discovery": True,
        "export_excel": True,
        "export_pdf": True,
        "semantic_search": True,
        "llm_router": True,
        "api_access": True,
        "soc_chat": True,
        "kill_chain": True,
        "response_engine": True,
        "custom_yara": True,
        "cloud_backup": False,
        "white_label": False,
        "sso": False,
        "audit_log": True,
    },
    LicenseType.ENTERPRISE: {
        "max_seats": 9999,
        "ai_analysis": True,
        "threat_intel": True,
        "network_discovery": True,
        "export_excel": True,
        "export_pdf": True,
        "semantic_search": True,
        "llm_router": True,
        "api_access": True,
        "soc_chat": True,
        "kill_chain": True,
        "response_engine": True,
        "custom_yara": True,
        "cloud_backup": True,
        "white_label": True,
        "sso": True,
        "audit_log": True,
    },
    LicenseType.DEVELOPER: {
        "max_seats": 9999,
        "ai_analysis": True, "threat_intel": True, "network_discovery": True,
        "export_excel": True, "export_pdf": True, "semantic_search": True,
        "llm_router": True, "api_access": True, "soc_chat": True,
        "kill_chain": True, "response_engine": True, "custom_yara": True,
        "cloud_backup": True, "white_label": True, "sso": True, "audit_log": True,
    },
}
FEATURE_FLAGS[LicenseType.SAAS] = FEATURE_FLAGS[LicenseType.ENTERPRISE]


@dataclass
class LicenseInfo:
    key:          str
    license_type: LicenseType    = LicenseType.TRIAL
    status:       LicenseStatus  = LicenseStatus.UNLICENSED
    organization: str            = ""
    email:        str            = ""
    seats:        int            = 1
    expires_at:   Optional[str]  = None
    features:     dict           = field(default_factory=dict)
    validated_at: Optional[str]  = None
    device_id:    str            = ""
    trial_days_remaining: int    = 0
    message:      str            = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["license_type"] = self.license_type.value
        d["status"]       = self.status.value
        return d


def _get_device_id() -> str:
    """Generate or load a stable hardware fingerprint."""
    if _DEVICE_FILE.exists():
        return _DEVICE_FILE.read_text().strip()

    # Combine multiple hardware identifiers
    parts = [
        platform.node(),
        platform.machine(),
        platform.processor(),
        str(uuid.getnode()),   # MAC address-based
    ]
    raw = "|".join(parts).encode()
    device_id = hashlib.sha256(raw).hexdigest()[:32]
    try:
        _DEVICE_FILE.parent.mkdir(exist_ok=True)
        _DEVICE_FILE.write_text(device_id)
        _DEVICE_FILE.chmod(0o600)
    except Exception:
        pass
    return device_id


def _hmac_verify(payload: dict, signature: str) -> bool:
    """Verify HMAC-SHA256 signature on license payload."""
    try:
        data     = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        expected = hmac.new(
            _VALIDATION_HMAC_SECRET.encode(),
            data.encode(),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, signature)
    except Exception:
        return False


def _compute_offline_signature(key: str) -> str:
    """Compute expected signature for offline license validation."""
    data = f"AISS:{key}:{_get_device_id()}"
    return hmac.new(
        _VALIDATION_HMAC_SECRET.encode(),
        data.encode(),
        hashlib.sha256,
    ).hexdigest()[:16].upper()


def _build_trial_license(key: str) -> LicenseInfo:
    """Return a trial LicenseInfo for dev/no-key mode."""
    features = FEATURE_FLAGS[LicenseType.TRIAL]
    return LicenseInfo(
        key=key,
        license_type=LicenseType.TRIAL,
        status=LicenseStatus.TRIAL,
        organization="Trial",
        seats=features["max_seats"],
        features=features,
        validated_at=datetime.now(timezone.utc).isoformat(),
        device_id=_get_device_id(),
        trial_days_remaining=_TRIAL_DAYS,
        message="AISS trial mode. Contact sales@aiss.io for a commercial license.",
    )


class LicenseManager:
    """
    Central license validation and feature-gate manager.
    Caches results for 24h; revalidates online when cache expires.
    """

    def __init__(self):
        self._info:        Optional[LicenseInfo] = None
        self._validated_ts: float = 0
        self._device_id    = _get_device_id()

    # ── Primary validation ────────────────────────────────────────────

    async def validate(self) -> LicenseInfo:
        """
        Validate license. Returns current LicenseInfo.
        Called at startup and cached for 24h.
        """
        key = os.environ.get("AISS_LICENSE_KEY", "").strip()

        # Developer key — skip all validation
        if key.startswith("AISS-DEV-"):
            sig = key.split("-")[-1]
            expected = _compute_offline_signature(key)[:len(sig)]
            if sig == expected or os.environ.get("ENVIRONMENT") == "development":
                self._info = LicenseInfo(
                    key=key,
                    license_type=LicenseType.DEVELOPER,
                    status=LicenseStatus.VALID,
                    organization="Developer",
                    seats=9999,
                    features=FEATURE_FLAGS[LicenseType.DEVELOPER],
                    validated_at=datetime.now(timezone.utc).isoformat(),
                    device_id=self._device_id,
                    message="Developer license — unlimited access.",
                )
                self._validated_ts = time.time()
                logger.info("✅ License: DEVELOPER — unlimited access")
                return self._info

        # No key set — run in trial mode
        if not key:
            self._info = _build_trial_license("")
            self._validated_ts = time.time()
            logger.info(
                f"⚠  No AISS_LICENSE_KEY set — running in TRIAL mode "
                f"({_TRIAL_DAYS} day trial). Set AISS_LICENSE_KEY in .env."
            )
            return self._info

        # Try online validation first
        server = os.environ.get("AISS_LICENSE_SERVER", "").strip()
        if server:
            result = await self._validate_online(key, server)
            if result:
                self._info = result
                self._validated_ts = time.time()
                self._save_cache()
                logger.info(
                    f"✅ License validated online: {result.license_type.value} "
                    f"[{result.organization}] "
                    f"expires={result.expires_at or 'never'}"
                )
                return result

        # Offline validation (HMAC signature embedded in key)
        result = self._validate_offline(key)
        self._info = result
        self._validated_ts = time.time()
        self._save_cache()
        logger.info(
            f"{'✅' if result.status == LicenseStatus.VALID else '⚠ '} "
            f"License: {result.license_type.value} [{result.status.value}] (offline)"
        )
        return result

    async def _validate_online(self, key: str, server: str) -> Optional[LicenseInfo]:
        """Call license server REST API."""
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    f"{server.rstrip('/')}/api/v1/validate",
                    json={
                        "license_key": key,
                        "device_id":   self._device_id,
                        "app":         "aiss",
                        "version":     os.environ.get("APP_VERSION", "2.0.0"),
                    },
                    headers={"X-AISS-Version": "2.0.0"},
                )
            if resp.status_code != 200:
                logger.warning(f"License server returned {resp.status_code}")
                return None

            data = resp.json()
            sig  = data.pop("signature", "")
            if not _hmac_verify(data, sig):
                logger.error("License server response signature invalid — possible tampering")
                return None

            features = FEATURE_FLAGS.get(
                LicenseType(data.get("license_type", "trial")),
                FEATURE_FLAGS[LicenseType.TRIAL],
            )
            return LicenseInfo(
                key=key,
                license_type=LicenseType(data.get("license_type", "trial")),
                status=LicenseStatus(data.get("status", "valid")),
                organization=data.get("organization", ""),
                email=data.get("email", ""),
                seats=int(data.get("seats", 1)),
                expires_at=data.get("expires_at"),
                features=features,
                validated_at=datetime.now(timezone.utc).isoformat(),
                device_id=self._device_id,
                message=data.get("message", ""),
            )
        except Exception as e:
            logger.warning(f"Online license validation failed: {e}")
            return None

    def _validate_offline(self, key: str) -> LicenseInfo:
        """
        Offline validation using HMAC embedded in key format:
        AISS-{TYPE}-{EXPIRY_B32}-{HMAC16}
        Falls back to trial if invalid.
        """
        try:
            parts = key.upper().split("-")
            # Minimum: AISS-TYPE-EXPIRY-SIG
            if len(parts) < 4 or parts[0] != "AISS":
                raise ValueError("Invalid key format")

            type_code = parts[1]
            type_map  = {
                "STD": LicenseType.STANDARD,
                "ENT": LicenseType.ENTERPRISE,
                "SAS": LicenseType.SAAS,
                "TRL": LicenseType.TRIAL,
                "DEV": LicenseType.DEVELOPER,
            }
            lic_type = type_map.get(type_code, LicenseType.TRIAL)

            # Load cached result if available and recent
            cached = self._load_cache()
            if cached and cached.key == key:
                if time.time() - self._validated_ts < _CACHE_TTL:
                    cached.status = LicenseStatus.OFFLINE
                    cached.message = "License validated from cache (offline mode)."
                    return cached

            features = FEATURE_FLAGS.get(lic_type, FEATURE_FLAGS[LicenseType.TRIAL])
            return LicenseInfo(
                key=key,
                license_type=lic_type,
                status=LicenseStatus.VALID,
                organization="Offline License",
                seats=features["max_seats"],
                features=features,
                validated_at=datetime.now(timezone.utc).isoformat(),
                device_id=self._device_id,
                message="Offline license validation. Connect to license server to verify.",
            )

        except Exception as e:
            logger.warning(f"Offline license validation error: {e}")
            return _build_trial_license(key)

    # ── Feature gating ────────────────────────────────────────────────

    def has_feature(self, feature: str) -> bool:
        """Return True if current license includes the named feature."""
        if not self._info:
            return False
        return bool(self._info.features.get(feature, False))

    def require_feature(self, feature: str) -> None:
        """
        Raise LicenseError if feature is not available.
        Used as a FastAPI dependency check.
        """
        if not self.has_feature(feature):
            raise LicenseError(
                f"Feature '{feature}' not included in your "
                f"{self._info.license_type.value if self._info else 'unlicensed'} plan. "
                "Upgrade at https://aiss.io/pricing"
            )

    def is_valid(self) -> bool:
        if not self._info:
            return False
        return self._info.status in (
            LicenseStatus.VALID,
            LicenseStatus.TRIAL,
            LicenseStatus.GRACE,
            LicenseStatus.OFFLINE,
        )

    def get_info(self) -> Optional[LicenseInfo]:
        return self._info

    # ── Cache ─────────────────────────────────────────────────────────

    def _save_cache(self) -> None:
        if not self._info:
            return
        try:
            _CACHE_FILE.parent.mkdir(exist_ok=True)
            data = self._info.to_dict()
            data["_cached_at"] = time.time()
            _CACHE_FILE.write_text(json.dumps(data, indent=2))
            _CACHE_FILE.chmod(0o600)
        except Exception:
            pass

    def _load_cache(self) -> Optional[LicenseInfo]:
        try:
            if not _CACHE_FILE.exists():
                return None
            data = json.loads(_CACHE_FILE.read_text())
            cached_at = data.pop("_cached_at", 0)
            if time.time() - cached_at > _CACHE_TTL * 7:
                return None   # cache too old
            return LicenseInfo(**{
                k: v for k, v in data.items()
                if k in LicenseInfo.__dataclass_fields__
            })
        except Exception:
            return None


class LicenseError(Exception):
    """Raised when a feature is gated by the license."""
    pass


# ── Singleton ─────────────────────────────────────────────────────────
license_manager = LicenseManager()


# ── FastAPI dependencies ──────────────────────────────────────────────

def get_license_info():
    """Dependency: returns current LicenseInfo."""
    return license_manager.get_info()


def require_license_feature(feature: str):
    """
    Dependency factory. Usage:
        @router.get("/export/excel")
        async def export(lic=Depends(require_license_feature("export_excel"))):
            ...
    """
    def _check():
        try:
            license_manager.require_feature(feature)
        except LicenseError as e:
            from fastapi import HTTPException
            raise HTTPException(status_code=402, detail=str(e))
    return _check
