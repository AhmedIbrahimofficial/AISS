"""AISS - STIX2 / TAXII2 Threat Intelligence Feeds
Ingests STIX indicator objects from a TAXII 2.x server into the local
threat intelligence cache.

Configuration (.env):
  TAXII_SERVER_URL   — e.g. https://cti-taxii.mitre.org/taxii/
  TAXII_USERNAME     — leave blank for anonymous
  TAXII_PASSWORD     — leave blank for anonymous
  TAXII_COLLECTION   — collection ID or title to fetch (default: all)

Gracefully optional:
  - If TAXII_SERVER_URL is not set, does nothing.
  - If the server is unreachable, logs a warning and continues.
"""

import os
import asyncio
import json
from datetime import datetime
from typing import Optional

from utils.logger import setup_logger

logger = setup_logger("threat_intel_feeds")

TAXII_SERVER_URL  = os.environ.get("TAXII_SERVER_URL", "")
TAXII_USERNAME    = os.environ.get("TAXII_USERNAME", "")
TAXII_PASSWORD    = os.environ.get("TAXII_PASSWORD", "")
TAXII_COLLECTION  = os.environ.get("TAXII_COLLECTION", "")

# Local STIX indicator cache: {indicator_id → indicator_dict}
_stix_cache: dict[str, dict] = {}
_loaded_at: Optional[datetime] = None


def _is_configured() -> bool:
    return bool(TAXII_SERVER_URL)


async def ingest_from_taxii() -> int:
    """
    Connect to configured TAXII server and ingest STIX indicators.
    Returns count of indicators loaded.
    Gracefully returns 0 if not configured or server unreachable.
    """
    global _loaded_at

    if not _is_configured():
        logger.info("TAXII feed not configured (TAXII_SERVER_URL not set) — skipping")
        return 0

    try:
        from taxii2client.v21 import Server as TaxiiServer21
        from taxii2client.v20 import Server as TaxiiServer20
        import stix2

        loop = asyncio.get_event_loop()
        count = await loop.run_in_executor(None, _fetch_stix_blocking)
        _loaded_at = datetime.utcnow()
        logger.info(f"TAXII feed: ingested {count} STIX indicators")
        return count

    except Exception as e:
        logger.warning(f"TAXII feed ingestion failed (graceful): {e}")
        return 0


def _fetch_stix_blocking() -> int:
    """Synchronous TAXII fetch — runs in executor thread."""
    try:
        from taxii2client.v21 import Server
        import stix2

        kwargs = {"url": TAXII_SERVER_URL, "verify": True}
        if TAXII_USERNAME:
            kwargs["user"] = TAXII_USERNAME
            kwargs["password"] = TAXII_PASSWORD

        server = Server(**kwargs)
        count = 0

        for api_root in server.api_roots:
            for collection in api_root.collections:
                # Filter by title if configured
                if TAXII_COLLECTION and collection.title != TAXII_COLLECTION:
                    continue

                try:
                    bundle = collection.get_objects()
                    for obj in bundle.get("objects", []):
                        if obj.get("type") == "indicator":
                            _stix_cache[obj["id"]] = {
                                "id":          obj["id"],
                                "name":        obj.get("name", ""),
                                "description": obj.get("description", ""),
                                "pattern":     obj.get("pattern", ""),
                                "labels":      obj.get("labels", []),
                                "valid_from":  obj.get("valid_from", ""),
                                "collection":  collection.title,
                            }
                            count += 1
                except Exception as e:
                    logger.debug(f"Collection {collection.title} fetch error: {e}")

        return count

    except Exception as e:
        raise RuntimeError(f"TAXII fetch failed: {e}") from e


def get_indicator_by_ip(ip: str) -> list[dict]:
    """
    Check if an IP matches any cached STIX indicator pattern.
    Returns matching indicators.
    """
    matches = []
    for ind in _stix_cache.values():
        pattern = ind.get("pattern", "")
        # Simple STIX pattern check: [ipv4-addr:value = 'x.x.x.x']
        if ip in pattern:
            matches.append(ind)
    return matches


def get_indicator_by_hash(file_hash: str) -> list[dict]:
    """Check if a file hash matches any cached STIX indicator."""
    matches = []
    for ind in _stix_cache.values():
        if file_hash.lower() in ind.get("pattern", "").lower():
            matches.append(ind)
    return matches


def get_cache_stats() -> dict:
    """Return STIX cache statistics."""
    return {
        "configured":       _is_configured(),
        "server_url":       TAXII_SERVER_URL or "not configured",
        "indicators_cached": len(_stix_cache),
        "last_ingested":    _loaded_at.isoformat() if _loaded_at else None,
    }


def get_all_indicators() -> list[dict]:
    """Return all cached STIX indicators."""
    return list(_stix_cache.values())
