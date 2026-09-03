"""AISS - GeoIP2 Lookup Module
Provides real lat/lon/country/city for IP addresses using MaxMind GeoLite2.

Setup:
  1. Register at https://www.maxmind.com/en/geolite2/signup
  2. Download GeoLite2-City.mmdb
  3. Place at data/GeoLite2-City.mmdb (or set GEOIP_DB_PATH in .env)

If the DB file is not found, gracefully returns empty geo data (app still starts).
"""

import os
from typing import Optional
from utils.logger import setup_logger

logger = setup_logger("geo_lookup")

# Path to MaxMind DB — configurable via env
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_env_path     = os.environ.get("GEOIP_DB_PATH", "").strip()
GEOIP_DB_PATH = _env_path if _env_path else os.path.join(_PROJECT_ROOT, "data", "GeoLite2-City.mmdb")

_reader = None
_db_available = False


def _auto_download_db() -> bool:
    """
    Auto-download GeoLite2-City.mmdb from MaxMind if MAXMIND_LICENSE_KEY is set
    and the database file does not already exist.
    Returns True if download succeeded.
    """
    license_key = os.environ.get("MAXMIND_LICENSE_KEY", "").strip()
    if not license_key:
        return False
    if os.path.exists(GEOIP_DB_PATH):
        return True  # already have it

    import urllib.request
    import gzip
    import shutil

    os.makedirs(os.path.dirname(GEOIP_DB_PATH), exist_ok=True)
    url = (
        f"https://download.maxmind.com/app/geoip_download"
        f"?edition_id=GeoLite2-City&license_key={license_key}&suffix=tar.gz"
    )
    logger.info("Downloading GeoLite2-City.mmdb from MaxMind (auto-download)...")
    try:
        tmp_path = GEOIP_DB_PATH + ".tmp.tar.gz"
        urllib.request.urlretrieve(url, tmp_path)

        # Extract .mmdb from .tar.gz
        import tarfile
        with tarfile.open(tmp_path, "r:gz") as tf:
            for member in tf.getmembers():
                if member.name.endswith("GeoLite2-City.mmdb"):
                    member_file = tf.extractfile(member)
                    if member_file:
                        with open(GEOIP_DB_PATH, "wb") as out:
                            shutil.copyfileobj(member_file, out)
                        break
            else:
                logger.error("GeoLite2-City.mmdb not found inside archive")
                return False

        # Clean up temp file
        try:
            os.remove(tmp_path)
        except OSError:
            pass

        logger.info(f"✅ GeoLite2-City.mmdb downloaded to {GEOIP_DB_PATH}")
        return True
    except Exception as e:
        logger.error(f"Failed to auto-download GeoLite2-City.mmdb: {e}")
        return False


def _get_reader():
    """Lazy-load the GeoIP2 reader. Returns None if DB not available."""
    global _reader, _db_available

    if _reader is not None:
        return _reader
    if _db_available is False and _reader is None:
        # Already tried and failed — don't re-try on every call
        pass

    # Try auto-download if DB missing and license key is set
    if not os.path.exists(GEOIP_DB_PATH):
        _auto_download_db()

    if not os.path.exists(GEOIP_DB_PATH):
        if not hasattr(_get_reader, "_warned"):
            logger.warning(
                f"GeoLite2-City.mmdb not found at {GEOIP_DB_PATH}. "
                "Download from https://www.maxmind.com/en/geolite2/signup "
                "and set GEOIP_DB_PATH in .env to enable geo enrichment."
            )
            _get_reader._warned = True
        return None

    try:
        import geoip2.database
        _reader = geoip2.database.Reader(GEOIP_DB_PATH)
        _db_available = True
        logger.info(f"✅ GeoIP2 reader loaded: {GEOIP_DB_PATH}")
        return _reader
    except Exception as e:
        logger.error(f"GeoIP2 reader init failed: {e}")
        return None


def lookup_ip(ip: str) -> dict:
    """
    Look up geographic information for an IP address.

    Returns dict with: country_code, country_name, city, latitude, longitude
    Returns empty dict if IP is private, lookup fails, or DB not available.
    """
    if not ip or _is_private(ip):
        return {}

    reader = _get_reader()
    if not reader:
        return {}

    try:
        response = reader.city(ip)
        return {
            "country_code": response.country.iso_code or "",
            "country_name": response.country.name or "",
            "city":         response.city.name or "",
            "latitude":     response.location.latitude or 0.0,
            "longitude":    response.location.longitude or 0.0,
            "continent":    response.continent.name or "",
            "asn":          "",  # requires separate GeoLite2-ASN.mmdb
        }
    except Exception as e:
        logger.debug(f"GeoIP2 lookup failed for {ip}: {e}")
        return {}


def enrich_threat(threat_dict: dict) -> dict:
    """
    Enrich a threat dict with geo data based on its source IP.
    Adds 'geo' key to metadata if source looks like an IP.
    Returns the threat dict (mutated in place).
    """
    source = threat_dict.get("source", "")
    # Only look up real IPs (not PID:xxx, file paths, etc.)
    if not _is_ip_like(source):
        return threat_dict

    geo = lookup_ip(source)
    if geo:
        meta = threat_dict.get("metadata") or {}
        meta["geo"] = geo
        threat_dict["metadata"] = meta

    return threat_dict


def _is_ip_like(s: str) -> bool:
    """Return True if string looks like an IPv4 address."""
    import re
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", str(s)))


def _is_private(ip: str) -> bool:
    """Return True if IP is private/loopback/reserved."""
    try:
        parts = [int(x) for x in ip.split(".")]
        if len(parts) != 4:
            return True
        a, b = parts[0], parts[1]
        return (
            a == 10
            or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168)
            or a == 127
            or a == 0
            or ip.startswith("169.254.")
        )
    except Exception:
        return True


def is_available() -> bool:
    """Return True if the GeoIP2 database is loaded and ready."""
    return _get_reader() is not None
