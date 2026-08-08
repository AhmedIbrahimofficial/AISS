"""AISS — Licensing System Tests"""
import os
import pytest

os.environ.setdefault("ENVIRONMENT", "development")


# ── Trial mode (no key) ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_trial_mode_when_no_key():
    """No license key → trial mode, still valid."""
    os.environ.pop("AISS_LICENSE_KEY", None)
    from core.licensing import LicenseManager, LicenseType, LicenseStatus
    mgr = LicenseManager()
    info = await mgr.validate()
    assert info.license_type == LicenseType.TRIAL
    assert mgr.is_valid() is True
    assert info.trial_days_remaining > 0


@pytest.mark.asyncio
async def test_trial_features_limited():
    """Trial should not have enterprise features."""
    os.environ.pop("AISS_LICENSE_KEY", None)
    from core.licensing import LicenseManager
    mgr = LicenseManager()
    await mgr.validate()
    assert mgr.has_feature("soc_chat") is True
    assert mgr.has_feature("white_label") is False
    assert mgr.has_feature("cloud_backup") is False
    assert mgr.has_feature("response_engine") is False


# ── Developer key ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_developer_key_unlimited_access():
    """Developer key must grant all features."""
    os.environ["ENVIRONMENT"] = "development"
    os.environ["AISS_LICENSE_KEY"] = "AISS-DEV-TESTKEY"
    from core.licensing import LicenseManager, LicenseType, LicenseStatus
    mgr = LicenseManager()
    info = await mgr.validate()
    assert info.license_type == LicenseType.DEVELOPER
    assert mgr.is_valid() is True
    assert mgr.has_feature("white_label") is True
    assert mgr.has_feature("response_engine") is True
    assert info.seats == 9999
    os.environ.pop("AISS_LICENSE_KEY")


# ── Offline key ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_offline_standard_key():
    """Standard offline key should enable standard features."""
    os.environ["AISS_LICENSE_KEY"] = "AISS-STD-2024-TESTKEY"
    os.environ.pop("AISS_LICENSE_SERVER", None)
    from core.licensing import LicenseManager, LicenseType
    mgr = LicenseManager()
    info = await mgr.validate()
    assert info.license_type == LicenseType.STANDARD
    assert mgr.has_feature("response_engine") is True
    assert mgr.has_feature("white_label") is False
    os.environ.pop("AISS_LICENSE_KEY")


@pytest.mark.asyncio
async def test_offline_enterprise_key():
    """Enterprise offline key should have all features."""
    os.environ["AISS_LICENSE_KEY"] = "AISS-ENT-2024-TESTKEY"
    os.environ.pop("AISS_LICENSE_SERVER", None)
    from core.licensing import LicenseManager, LicenseType
    mgr = LicenseManager()
    info = await mgr.validate()
    assert info.license_type == LicenseType.ENTERPRISE
    assert mgr.has_feature("white_label") is True
    assert mgr.has_feature("sso") is True
    assert info.seats == 9999
    os.environ.pop("AISS_LICENSE_KEY")


# ── Feature gating ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_require_feature_raises_on_missing():
    """require_feature should raise LicenseError if feature not available."""
    os.environ.pop("AISS_LICENSE_KEY", None)
    from core.licensing import LicenseManager, LicenseError
    mgr = LicenseManager()
    await mgr.validate()
    with pytest.raises(LicenseError):
        mgr.require_feature("white_label")


@pytest.mark.asyncio
async def test_require_feature_passes_on_included():
    """require_feature should not raise for an included feature."""
    os.environ.pop("AISS_LICENSE_KEY", None)
    from core.licensing import LicenseManager
    mgr = LicenseManager()
    await mgr.validate()
    # Should not raise (soc_chat is in trial)
    mgr.require_feature("soc_chat")


# ── Invalid key ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_invalid_key_falls_back_to_trial():
    """Completely invalid key should fall back to trial."""
    os.environ["AISS_LICENSE_KEY"] = "NOT-A-VALID-KEY"
    os.environ.pop("AISS_LICENSE_SERVER", None)
    from core.licensing import LicenseManager, LicenseType
    mgr = LicenseManager()
    info = await mgr.validate()
    assert info.license_type == LicenseType.TRIAL
    assert mgr.is_valid() is True
    os.environ.pop("AISS_LICENSE_KEY")


# ── Device ID ─────────────────────────────────────────────────────────

def test_device_id_stable():
    """Device ID should be the same on consecutive calls."""
    from core.licensing import _get_device_id
    id1 = _get_device_id()
    id2 = _get_device_id()
    assert id1 == id2
    assert len(id1) == 32


def test_device_id_format():
    """Device ID should be 32 hex characters."""
    import re
    from core.licensing import _get_device_id
    device_id = _get_device_id()
    assert re.match(r"^[0-9a-f]{32}$", device_id)
