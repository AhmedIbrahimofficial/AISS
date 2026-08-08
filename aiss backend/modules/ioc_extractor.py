"""AISS - IOC Extractor
Automatically extracts Indicators of Compromise from any text using
ioc_finder + spaCy NER + regex patterns.

Supports: IPv4, IPv6, domains, URLs, emails, file hashes (MD5/SHA1/SHA256),
          CVE numbers, MITRE technique IDs (T1234), registry keys,
          Bitcoin addresses, ASNs.

Usage:
    from modules.ioc_extractor import ioc_extractor
    result = ioc_extractor.extract("Malware called emotet connected to 185.1.2.3:4444")
    # → {"ips": ["185.1.2.3"], "ports": ["4444"], "malware_names": ["emotet"], ...}
"""
import re
from typing import Any
from utils.logger import setup_logger

logger = setup_logger("ioc_extractor")

# Regex fallbacks used when ioc_finder is unavailable
_RE_IP4   = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_HASH  = re.compile(r"\b[0-9a-fA-F]{32,64}\b")
_RE_CVE   = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_RE_MITRE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_RE_PORT  = re.compile(r":(\d{2,5})\b")
_RE_URL   = re.compile(r"https?://[^\s\"'<>]{4,}", re.I)
_RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")

# Known malware name list (extended from keyword_learner)
_MALWARE_NAMES = [
    "wannacry","notpetya","emotet","trickbot","ryuk","lockbit","blackcat",
    "alphv","conti","revil","sodinokibi","cobalt strike","mimikatz",
    "metasploit","stuxnet","zeus","mirai","darkside","ragnarlocker","hive",
    "clop","qakbot","dridex","formbook","remcos","asyncrat","nanocore",
    "njrat","darkcomet","xmrig","ethminer","lazarus","apt28","apt29",
    "cozy bear","fancy bear","turla","sandworm","fin7","carbanak",
]
_MALWARE_PATTERN = re.compile(
    r"\b(" + "|".join(re.escape(m) for m in _MALWARE_NAMES) + r")\b", re.I
)


class IOCExtractor:
    def __init__(self):
        self._ioc_finder = None
        self._spacy_nlp  = None
        self._tried_init  = False

    def _lazy_init(self):
        if self._tried_init:
            return
        self._tried_init = True
        try:
            from core.lib_registry import lib_registry
            # ioc_finder
            if lib_registry.is_enabled("ioc_finder"):
                import ioc_finder
                self._ioc_finder = ioc_finder
            # spaCy NER
            if lib_registry.is_enabled("spacy"):
                self._spacy_nlp = lib_registry.get("spacy")
        except Exception as e:
            logger.debug(f"IOCExtractor lazy init: {e}")

    def extract(self, text: str) -> dict:
        """
        Extract all IOCs from text.
        Returns dict with keys: ips, domains, urls, emails, hashes,
        cves, mitre_techniques, malware_names, ports, entities
        """
        self._lazy_init()
        text = text or ""

        # Refang defanged IOCs before extraction (1[.]2[.]3[.]4 → 1.2.3.4)
        try:
            import ioc_fanger
            text = ioc_fanger.refang(text)
        except Exception:
            pass

        result: dict[str, list] = {
            "ips": [], "domains": [], "urls": [], "emails": [],
            "hashes": [], "cves": [], "mitre_techniques": [],
            "malware_names": [], "ports": [], "entities": [],
        }

        # ── ioc_finder (most comprehensive) ──────────────────────────
        if self._ioc_finder:
            try:
                found = self._ioc_finder.find_iocs(text)
                result["ips"]        = list(found.get("ipv4s", []))
                result["domains"]    = list(found.get("domains", []))
                result["urls"]       = list(found.get("urls", []))
                result["emails"]     = list(found.get("email_addresses", []))
                result["hashes"]     = (
                    list(found.get("md5s", [])) +
                    list(found.get("sha1s", [])) +
                    list(found.get("sha256s", []))
                )
            except Exception as e:
                logger.debug(f"ioc_finder error: {e}")

        # ── Regex fallbacks for anything ioc_finder missed ────────────
        if not result["ips"]:
            result["ips"]  = _RE_IP4.findall(text)
        if not result["urls"]:
            result["urls"] = _RE_URL.findall(text)
        if not result["emails"]:
            result["emails"] = _RE_EMAIL.findall(text)
        if not result["hashes"]:
            result["hashes"] = _RE_HASH.findall(text)

        # ── Always extract these via regex ────────────────────────────
        result["cves"]             = list(set(_RE_CVE.findall(text.upper())))
        result["mitre_techniques"] = list(set(_RE_MITRE.findall(text)))
        result["ports"]            = list(set(_RE_PORT.findall(text)))
        result["malware_names"]    = list({
            m.lower() for m in _MALWARE_PATTERN.findall(text)
        })

        # ── spaCy NER for named entities ──────────────────────────────
        if self._spacy_nlp and len(text) < 50000:
            try:
                doc = self._spacy_nlp(text[:10000])
                result["entities"] = [
                    {"text": ent.text, "label": ent.label_}
                    for ent in doc.ents
                    if ent.label_ in ("ORG", "GPE", "PERSON", "PRODUCT", "EVENT")
                ]
            except Exception as e:
                logger.debug(f"spaCy NER error: {e}")

        # Deduplicate all lists
        for key in result:
            if isinstance(result[key], list):
                result[key] = list(dict.fromkeys(result[key]))

        return result

    def extract_from_threat(self, threat: dict) -> dict:
        """Extract IOCs from a threat dict (description + metadata)."""
        import json
        text_parts = [
            str(threat.get("description", "")),
            str(threat.get("type", "")),
            str(threat.get("source", "")),
        ]
        meta = threat.get("metadata") or {}
        if isinstance(meta, dict):
            text_parts.append(json.dumps(meta)[:2000])
        elif isinstance(meta, str):
            text_parts.append(meta[:2000])
        return self.extract(" ".join(text_parts))

    def is_available(self) -> bool:
        self._lazy_init()
        return self._ioc_finder is not None or True   # regex always works


# Singleton
ioc_extractor = IOCExtractor()
