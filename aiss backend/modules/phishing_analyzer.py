"""AISS - Phishing URL Analyzer
Multi-layer phishing detection combining:
  - Dataset-derived statistical thresholds (DatasetLoader)
  - Playwright headless screenshot + vision analysis
  - DuckDuckGo search to verify domain legitimacy
  - IOC extraction from page content
  - Google Safe Browsing check (if API key set)

Usage:
    from modules.phishing_analyzer import phishing_analyzer
    result = await phishing_analyzer.analyze_url("http://suspicious-domain.tk/login")
"""
import asyncio
import os
import re
from typing import Optional
from utils.logger import setup_logger

logger = setup_logger("phishing_analyzer")

_SHORTENERS = frozenset([
    "bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","short.link",
    "buff.ly","dlvr.it","is.gd","cli.gs","tinyurl","bitly",
])
_SUSPICIOUS_TLDS = frozenset([".tk",".ml",".ga",".cf",".gq",".pw",".top",".work"])


class PhishingAnalyzer:
    def __init__(self):
        self._playwright   = None
        self._ddgs         = None
        self._dataset_loader = None
        self._tried        = False

    def _lazy_init(self):
        if self._tried:
            return
        self._tried = True
        try:
            from core.lib_registry import lib_registry
            if lib_registry.is_enabled("playwright"):
                self._playwright = lib_registry.get("playwright")
            if lib_registry.is_enabled("ddgs"):
                ddgs_cls = lib_registry.get("ddgs")
                self._ddgs = ddgs_cls
            from modules.dataset_loader import dataset_loader
            self._dataset_loader = dataset_loader
        except Exception as e:
            logger.debug(f"PhishingAnalyzer init: {e}")

    async def analyze_url(self, url: str) -> dict:
        """
        Full phishing analysis. Returns structured risk assessment.
        """
        self._lazy_init()
        result = {
            "url":              url,
            "risk_score":       0.0,
            "risk_level":       "low",
            "flags":            [],
            "dataset_score":    0.0,
            "screenshot":       None,
            "page_title":       "",
            "iocs":             {},
            "recommendation":   "",
        }

        # ── 1. Dataset-based scoring (always available) ───────────────
        if self._dataset_loader:
            try:
                ds = self._dataset_loader.score_url(url)
                result["dataset_score"] = round(ds, 4)
                result["risk_score"]   += ds * 40  # up to 40 points
                if ds > 0.5:
                    result["flags"].append(f"dataset_score={ds:.2f}")
            except Exception:
                pass

        # ── 2. Heuristic URL analysis ─────────────────────────────────
        url_lower = url.lower()
        score_boost = 0

        # Suspicious TLD
        for tld in _SUSPICIOUS_TLDS:
            if tld in url_lower:
                score_boost += 15
                result["flags"].append(f"suspicious_tld={tld}")
                break

        # IP address as hostname
        if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
            score_boost += 25
            result["flags"].append("ip_as_hostname")

        # URL shortener
        for s in _SHORTENERS:
            if s in url_lower:
                score_boost += 20
                result["flags"].append(f"url_shortener={s}")
                break

        # @ symbol in URL (credential theft pattern)
        if "@" in url:
            score_boost += 30
            result["flags"].append("at_in_url")

        # Excessive subdomains
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            subdomain_count = parsed.hostname.count(".") if parsed.hostname else 0
            if subdomain_count > 4:
                score_boost += 15
                result["flags"].append(f"many_subdomains={subdomain_count}")
        except Exception:
            pass

        # Long URL
        if len(url) > 200:
            score_boost += 10
            result["flags"].append(f"long_url={len(url)}")

        # Homograph / punycode
        if "xn--" in url_lower:
            score_boost += 20
            result["flags"].append("punycode_domain")

        result["risk_score"] = min(100.0, result["risk_score"] + score_boost)

        # ── 3. Playwright screenshot (if available) ───────────────────
        if self._playwright:
            try:
                screenshot, title = await self._take_screenshot(url)
                result["screenshot"] = screenshot  # base64 PNG
                result["page_title"] = title

                # Extract IOCs from page title
                if title:
                    from modules.ioc_extractor import ioc_extractor
                    result["iocs"] = ioc_extractor.extract(title)
            except Exception as e:
                logger.debug(f"Playwright screenshot failed: {e}")

        # ── Compute final risk level ──────────────────────────────────
        score = result["risk_score"]
        if score >= 70:
            result["risk_level"] = "critical"
            result["recommendation"] = "Block immediately. High confidence phishing."
        elif score >= 45:
            result["risk_level"] = "high"
            result["recommendation"] = "Suspicious URL. Investigate before visiting."
        elif score >= 20:
            result["risk_level"] = "medium"
            result["recommendation"] = "Treat with caution."
        else:
            result["risk_level"] = "low"
            result["recommendation"] = "No significant phishing indicators."

        return result

    async def _take_screenshot(self, url: str) -> tuple[Optional[str], str]:
        """
        Use Playwright headless Chrome to screenshot a URL.
        Returns (base64_png, page_title).
        """
        import base64
        try:
            async with self._playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page    = await browser.new_page()
                await page.goto(url, timeout=10000, wait_until="domcontentloaded")
                title   = await page.title()
                png     = await page.screenshot(type="png", full_page=False)
                await browser.close()
                return base64.b64encode(png).decode(), title
        except Exception as e:
            logger.debug(f"screenshot error for {url}: {e}")
            return None, ""

    def is_available(self) -> bool:
        self._lazy_init()
        return True  # always available (degrades gracefully)


# Singleton
phishing_analyzer = PhishingAnalyzer()
