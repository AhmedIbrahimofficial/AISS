"""AISS - Alert Manager
Multi-channel notification system powered by Apprise.

Supports 90+ services via a single API:
  - Slack, Discord, Telegram, Email, SMS (Twilio/Vonage)
  - Teams, PagerDuty, Pushover, Gotify, Ntfy, etc.

Configuration is driven entirely by APPRISE_URLS in .env:
  APPRISE_URLS=slack://token1/channel,discord://webhook_id/webhook_token

Severity gating via ALERT_MIN_SEVERITY (default: high):
  ALERT_MIN_SEVERITY=high   → only HIGH + CRITICAL fire alerts
  ALERT_MIN_SEVERITY=medium → MEDIUM and above
  ALERT_MIN_SEVERITY=low    → everything

Usage:
    from modules.alert_manager import alert_manager
    await alert_manager.send_threat_alert(threat)
    await alert_manager.send_message("Custom message", title="AISS Alert")
"""

import asyncio
import os
from datetime import datetime
from typing import Optional

from utils.logger import setup_logger

logger = setup_logger("alert_manager")

# ── Severity ordering ─────────────────────────────────────────────────
_SEVERITY_RANK = {
    "low":      1,
    "medium":   2,
    "high":     3,
    "critical": 4,
}

# ── Emoji prefixes per severity ───────────────────────────────────────
_SEVERITY_EMOJI = {
    "critical": "🔴",
    "high":     "⚠️",
    "medium":   "🟡",
    "low":      "🔵",
}


class AlertManager:
    """
    Apprise-backed multi-channel alert dispatcher.

    Lazy-initialises the Apprise instance on first use so that startup
    is not blocked if apprise is not installed or no URLs are configured.
    """

    def __init__(self) -> None:
        self._apprise = None          # initialised on first call
        self._ready   = False         # True once loaded without errors
        self._urls: list[str] = []

        # Minimum severity that triggers an external alert
        min_sev = os.environ.get("ALERT_MIN_SEVERITY", "high").lower().strip()
        self._min_rank = _SEVERITY_RANK.get(min_sev, 3)

    # ── Lazy init ─────────────────────────────────────────────────────

    def _init_apprise(self) -> bool:
        """
        Initialise Apprise with URLs from APPRISE_URLS env var.
        Returns True if at least one URL was loaded successfully.
        """
        if self._ready:
            return True

        try:
            import apprise  # lazy import — no hard dependency at startup
        except ImportError:
            logger.warning(
                "apprise not installed. Run: pip install apprise\n"
                "Multi-channel alerts are DISABLED."
            )
            return False

        raw = os.environ.get("APPRISE_URLS", "").strip()
        if not raw:
            logger.info(
                "APPRISE_URLS not set — multi-channel alerts disabled. "
                "Add URLs to .env to enable (e.g. discord://..., slack://...)."
            )
            return False

        self._apprise = apprise.Apprise()
        loaded = 0
        for url in raw.split(","):
            url = url.strip()
            if not url:
                continue
            if self._apprise.add(url):
                loaded += 1
                # Log scheme only — never the full URL (it contains credentials)
                scheme = url.split("://")[0] if "://" in url else url[:20]
                logger.info(f"  📡 Alert channel registered: {scheme}://...")
            else:
                logger.warning(f"  ⚠️  Invalid apprise URL (scheme): {url[:30]}...")

        if loaded == 0:
            logger.warning("No valid apprise URLs loaded — alerts disabled.")
            return False

        logger.info(f"✅ AlertManager ready — {loaded} channel(s) active")
        self._ready = True
        return True

    # ── Core send ─────────────────────────────────────────────────────

    async def send_message(
        self,
        body: str,
        title: str = "AISS Security Alert",
        notify_type: str = "warning",   # info | success | warning | failure
    ) -> bool:
        """
        Send a free-form message to all configured channels.

        Returns True if at least one notification was dispatched.
        Failures are logged but never raise exceptions.
        """
        if not self._init_apprise():
            return False

        try:
            loop   = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: self._apprise.notify(
                    title=title,
                    body=body,
                    notify_type=notify_type,
                ),
            )
            if result:
                logger.debug(f"Alert dispatched: {title}")
            else:
                logger.warning(f"Alert dispatch returned False: {title}")
            return bool(result)

        except Exception as e:
            logger.error(f"Alert dispatch failed: {e}")
            return False

    # ── Threat alert ──────────────────────────────────────────────────

    async def send_threat_alert(self, threat) -> bool:
        """
        Send a structured threat alert.

        Accepts either a Threat object or a plain dict (from threat.to_dict()).
        Respects ALERT_MIN_SEVERITY gating.
        """
        # Normalise to dict
        if hasattr(threat, "to_dict"):
            t = threat.to_dict()
        elif isinstance(threat, dict):
            t = threat
        else:
            logger.warning(f"send_threat_alert received unknown type: {type(threat)}")
            return False

        # Severity gate
        severity = str(t.get("severity", "low")).lower()
        rank     = _SEVERITY_RANK.get(severity, 1)
        if rank < self._min_rank:
            return False  # below threshold — skip silently

        # Apprise notify_type mapping
        notify_type_map = {
            "critical": "failure",
            "high":     "warning",
            "medium":   "warning",
            "low":      "info",
        }
        notify_type = notify_type_map.get(severity, "warning")

        # Build message
        emoji    = _SEVERITY_EMOJI.get(severity, "⚠️")
        t_type   = t.get("type",        "Unknown")
        source   = t.get("source",      "—")
        desc     = t.get("description", "No description")
        tid      = t.get("id",          "")[:8]
        ts       = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        title = f"{emoji} AISS [{severity.upper()}] {t_type}"
        body  = (
            f"Threat ID : {tid}\n"
            f"Type      : {t_type}\n"
            f"Severity  : {severity.upper()}\n"
            f"Source    : {source}\n"
            f"Detected  : {ts}\n"
            f"\n"
            f"{desc}"
        )

        # Append metadata highlights if present
        meta = t.get("metadata") or {}
        if meta:
            highlights = []
            for key in ("remote_ip", "remote_port", "pid", "process", "path", "domain"):
                if meta.get(key):
                    highlights.append(f"{key}: {meta[key]}")
            if highlights:
                body += "\n\nContext:\n" + "\n".join(f"  • {h}" for h in highlights)

        return await self.send_message(body, title=title, notify_type=notify_type)

    # ── Campaign / APT alert ──────────────────────────────────────────

    async def send_campaign_alert(self, campaign: dict) -> bool:
        """Send a high-priority alert for correlated campaign detection."""
        source = campaign.get("source", "unknown")
        meta   = campaign.get("metadata", {}) or {}
        types  = meta.get("types", [])
        count  = len(meta.get("linked_threats", []))

        title = "🔗 AISS CAMPAIGN DETECTED"
        body  = (
            f"Correlated threat campaign from: {source}\n"
            f"Linked threats  : {count}\n"
            f"Threat types    : {', '.join(types)}\n"
            f"Detected at     : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
            f"\n"
            f"{campaign.get('description', '')}"
        )
        return await self.send_message(body, title=title, notify_type="failure")

    async def send_apt_chain_alert(self, threat: dict) -> bool:
        """Send a critical alert for APT attack chain detection."""
        meta  = threat.get("metadata", {}) or {}
        chain = meta.get("apt_chain", [])
        src   = threat.get("source", "unknown")

        title = "⚡ AISS APT ATTACK CHAIN"
        body  = (
            f"Multi-stage APT pattern confirmed!\n"
            f"Source     : {src}\n"
            f"Chain      : {' → '.join(chain)}\n"
            f"Detected at: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
            f"\nImmediate investigation required."
        )
        return await self.send_message(body, title=title, notify_type="failure")

    async def send_emergency_alert(self, threat_type: str, source: str, notes: str) -> bool:
        """Send an emergency alert (e.g. ransomware response triggered)."""
        title = f"🚨 AISS EMERGENCY: {threat_type}"
        body  = (
            f"Emergency response triggered!\n"
            f"Threat type : {threat_type}\n"
            f"Source      : {source}\n"
            f"Timestamp   : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
            f"\nActions taken:\n{notes}"
        )
        return await self.send_message(body, title=title, notify_type="failure")

    # ── Status / heartbeat ────────────────────────────────────────────

    async def send_heartbeat(self, stats: dict) -> bool:
        """
        Periodic heartbeat / status summary.
        Useful for confirming AISS is alive without a flood of threat alerts.
        """
        title = "💓 AISS Heartbeat"
        body  = (
            f"System status at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
            f"  Active threats  : {stats.get('active', 0)}\n"
            f"  Total threats   : {stats.get('total', 0)}\n"
            f"  Critical        : {stats.get('critical', 0)}\n"
            f"  High            : {stats.get('high', 0)}\n"
            f"  Resolved        : {stats.get('resolved', 0)}\n"
        )
        return await self.send_message(body, title=title, notify_type="info")

    # ── Health check ──────────────────────────────────────────────────

    def is_configured(self) -> bool:
        """Return True if apprise is installed and at least one URL is loaded."""
        return self._init_apprise()

    def get_status(self) -> dict:
        """Return current configuration status (safe — no credentials)."""
        raw      = os.environ.get("APPRISE_URLS", "")
        channels = len([u for u in raw.split(",") if u.strip()]) if raw else 0
        min_sev  = os.environ.get("ALERT_MIN_SEVERITY", "high")
        return {
            "enabled":            self._ready,
            "channels_configured": channels,
            "min_severity":       min_sev,
        }


# ── Module-level singleton ────────────────────────────────────────────
alert_manager = AlertManager()
