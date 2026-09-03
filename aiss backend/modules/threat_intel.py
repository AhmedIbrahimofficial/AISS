"""AISS - Threat Intelligence Module
Enriches threat events with reputation data from VirusTotal and Shodan.
Results are cached in-memory (with TTL) to avoid API rate limits.

Environment variables required:
  VIRUSTOTAL_API_KEY  — from https://www.virustotal.com/gui/my-apikey
  SHODAN_API_KEY      — from https://account.shodan.io/

Both services degrade gracefully if keys are not configured.
"""

import asyncio
import os
import time
from typing import Optional

import httpx

from utils.logger import setup_logger

logger = setup_logger("threat_intel")

# ── API Keys ───────────────────────────────────────────────────────────
VT_API_KEY     = os.environ.get("VIRUSTOTAL_API_KEY", "")
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")

VT_BASE_URL     = "https://www.virustotal.com/api/v3"
SHODAN_BASE_URL = "https://api.shodan.io"

# ── In-memory cache: {key → (timestamp, data)} ────────────────────────
_CACHE: dict[str, tuple[float, dict]] = {}
CACHE_TTL_SECS = 3600  # 1 hour


def _cache_get(key: str) -> Optional[dict]:
    entry = _CACHE.get(key)
    if entry and (time.time() - entry[0]) < CACHE_TTL_SECS:
        return entry[1]
    return None


def _cache_set(key: str, data: dict) -> None:
    _CACHE[key] = (time.time(), data)


def _prune_cache() -> None:
    """Remove expired cache entries."""
    now = time.time()
    expired = [k for k, (ts, _) in _CACHE.items() if now - ts > CACHE_TTL_SECS]
    for k in expired:
        del _CACHE[k]


# ── VirusTotal ────────────────────────────────────────────────────────

async def vt_check_ip(ip: str) -> dict:
    """Check an IP reputation via VirusTotal API v3."""
    if not VT_API_KEY:
        return {"source": "virustotal", "available": False, "reason": "API key not configured"}

    cache_key = f"vt:ip:{ip}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                f"{VT_BASE_URL}/ip_addresses/{ip}",
                headers={"x-apikey": VT_API_KEY},
            )
        if r.status_code == 404:
            result = {"source": "virustotal", "ip": ip, "found": False}
        elif r.status_code == 429:
            logger.warning("VirusTotal rate limit hit")
            return {"source": "virustotal", "available": False, "reason": "rate_limit"}
        else:
            r.raise_for_status()
            data = r.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            result = {
                "source":      "virustotal",
                "ip":          ip,
                "found":       True,
                "malicious":   stats.get("malicious", 0),
                "suspicious":  stats.get("suspicious", 0),
                "harmless":    stats.get("harmless", 0),
                "undetected":  stats.get("undetected", 0),
                "country":     data.get("country", ""),
                "asn":         data.get("asn", ""),
                "reputation":  data.get("reputation", 0),
                "categories":  data.get("categories", {}),
            }
        _cache_set(cache_key, result)
        return result
    except Exception as e:
        logger.warning(f"VT IP check failed for {ip}: {e}")
        return {"source": "virustotal", "available": False, "reason": str(e)}


async def vt_check_hash(file_hash: str) -> dict:
    """Check a file hash (MD5/SHA1/SHA256) reputation via VirusTotal."""
    if not VT_API_KEY:
        return {"source": "virustotal", "available": False, "reason": "API key not configured"}

    cache_key = f"vt:hash:{file_hash}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                f"{VT_BASE_URL}/files/{file_hash}",
                headers={"x-apikey": VT_API_KEY},
            )
        if r.status_code == 404:
            result = {"source": "virustotal", "hash": file_hash, "found": False}
        elif r.status_code == 429:
            logger.warning("VirusTotal rate limit hit")
            return {"source": "virustotal", "available": False, "reason": "rate_limit"}
        else:
            r.raise_for_status()
            data = r.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            result = {
                "source":       "virustotal",
                "hash":         file_hash,
                "found":        True,
                "malicious":    stats.get("malicious", 0),
                "suspicious":   stats.get("suspicious", 0),
                "harmless":     stats.get("harmless", 0),
                "name":         data.get("meaningful_name", ""),
                "type":         data.get("type_description", ""),
                "size":         data.get("size", 0),
                "threat_label": data.get("popular_threat_classification", {})
                                    .get("suggested_threat_label", ""),
            }
        _cache_set(cache_key, result)
        return result
    except Exception as e:
        logger.warning(f"VT hash check failed for {file_hash}: {e}")
        return {"source": "virustotal", "available": False, "reason": str(e)}


async def vt_check_domain(domain: str) -> dict:
    """Check a domain reputation via VirusTotal API v3."""
    if not VT_API_KEY:
        return {"source": "virustotal", "available": False, "reason": "API key not configured"}

    cache_key = f"vt:domain:{domain}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                f"{VT_BASE_URL}/domains/{domain}",
                headers={"x-apikey": VT_API_KEY},
            )
        if r.status_code == 404:
            result = {"source": "virustotal", "domain": domain, "found": False}
        elif r.status_code == 429:
            logger.warning("VirusTotal rate limit hit")
            return {"source": "virustotal", "available": False, "reason": "rate_limit"}
        else:
            r.raise_for_status()
            data = r.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            result = {
                "source":      "virustotal",
                "domain":      domain,
                "found":       True,
                "malicious":   stats.get("malicious", 0),
                "suspicious":  stats.get("suspicious", 0),
                "harmless":    stats.get("harmless", 0),
                "reputation":  data.get("reputation", 0),
                "categories":  data.get("categories", {}),
                "registrar":   data.get("registrar", ""),
                "creation_date": data.get("creation_date"),
            }
        _cache_set(cache_key, result)
        return result
    except Exception as e:
        logger.warning(f"VT domain check failed for {domain}: {e}")
        return {"source": "virustotal", "available": False, "reason": str(e)}


async def vt_check_url(url: str) -> dict:
    """Check a URL reputation via VirusTotal API v3."""
    if not VT_API_KEY:
        return {"source": "virustotal", "available": False, "reason": "API key not configured"}

    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    cache_key = f"vt:url:{url}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                f"{VT_BASE_URL}/urls/{url_id}",
                headers={"x-apikey": VT_API_KEY},
            )
        if r.status_code == 404:
            result = {"source": "virustotal", "url": url, "found": False}
        elif r.status_code == 429:
            logger.warning("VirusTotal rate limit hit")
            return {"source": "virustotal", "available": False, "reason": "rate_limit"}
        else:
            r.raise_for_status()
            data = r.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            result = {
                "source":      "virustotal",
                "url":         url,
                "found":       True,
                "malicious":   stats.get("malicious", 0),
                "suspicious":  stats.get("suspicious", 0),
                "harmless":    stats.get("harmless", 0),
                "reputation":  data.get("reputation", 0),
                "categories":  data.get("categories", {}),
                "title":       data.get("title", ""),
            }
        _cache_set(cache_key, result)
        return result
    except Exception as e:
        logger.warning(f"VT URL check failed for {url}: {e}")
        return {"source": "virustotal", "available": False, "reason": str(e)}


# ── Shodan ────────────────────────────────────────────────────────────

async def shodan_check_ip(ip: str) -> dict:
    """Check an IP against Shodan for open ports and banners."""
    if not SHODAN_API_KEY:
        return {"source": "shodan", "available": False, "reason": "API key not configured"}

    cache_key = f"shodan:ip:{ip}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(
                f"{SHODAN_BASE_URL}/shodan/host/{ip}",
                params={"key": SHODAN_API_KEY},
            )
        if r.status_code == 404:
            result = {"source": "shodan", "ip": ip, "found": False}
        elif r.status_code == 401:
            return {"source": "shodan", "available": False, "reason": "invalid_api_key"}
        else:
            r.raise_for_status()
            data = r.json()
            result = {
                "source":       "shodan",
                "ip":           ip,
                "found":        True,
                "org":          data.get("org", ""),
                "isp":          data.get("isp", ""),
                "country":      data.get("country_name", ""),
                "city":         data.get("city", ""),
                "open_ports":   data.get("ports", []),
                "hostnames":    data.get("hostnames", []),
                "tags":         data.get("tags", []),
                "vulns":        list(data.get("vulns", {}).keys())[:10],
                "os":           data.get("os", ""),
                "last_update":  data.get("last_update", ""),
            }
        _cache_set(cache_key, result)
        return result
    except Exception as e:
        logger.warning(f"Shodan check failed for {ip}: {e}")
        return {"source": "shodan", "available": False, "reason": str(e)}


# ── Combined enrichment ───────────────────────────────────────────────

async def enrich_ip(ip: str) -> dict:
    """
    Enrich an IP with both VirusTotal and Shodan data concurrently.
    Returns combined dict with 'vt' and 'shodan' keys.
    """
    if not ip or _is_private(ip):
        return {}

    _prune_cache()

    vt_result, shodan_result = await asyncio.gather(
        vt_check_ip(ip),
        shodan_check_ip(ip),
        return_exceptions=True,
    )

    enrichment = {}
    if isinstance(vt_result, dict):
        enrichment["vt"] = vt_result
    if isinstance(shodan_result, dict):
        enrichment["shodan"] = shodan_result

    # Derive risk score
    malicious = 0
    if isinstance(vt_result, dict):
        malicious = vt_result.get("malicious", 0)
    enrichment["risk_score"] = min(100, malicious * 5)

    return enrichment


def _is_private(ip: str) -> bool:
    """Return True if IP is private/loopback."""
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
        )
    except Exception:
        return True


def get_cache_stats() -> dict:
    """Return cache statistics (safe to expose via API)."""
    _prune_cache()
    return {
        "cached_entries": len(_CACHE),
        "vt_configured":     bool(VT_API_KEY),
        "shodan_configured": bool(SHODAN_API_KEY),
        "cache_ttl_secs":    CACHE_TTL_SECS,
    }
