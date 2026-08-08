"""AISS - Sigma Rule Loader
Loads Sigma-format detection rules from rules/sigma_rules.yml and
converts them into patterns usable by auth_monitor and network_monitor.

pySigma is used for parsing. Since full backend conversion requires
pipeline plugins, we implement a lightweight parser for the subset
of Sigma rules used by AISS detection modules.
"""

import os
import re
import yaml
from typing import Optional
from utils.logger import setup_logger

logger = setup_logger("sigma_loader")

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules")

# ── Parsed rule registry ──────────────────────────────────────────────
_sigma_rules: list[dict] = []
_loaded = False


def load_sigma_rules(rules_file: Optional[str] = None) -> list[dict]:
    """
    Load and parse Sigma rules from YAML file.
    Returns list of parsed rule dicts.
    """
    global _sigma_rules, _loaded

    if _loaded:
        return _sigma_rules

    path = rules_file or os.path.join(RULES_DIR, "sigma_rules.yml")
    if not os.path.exists(path):
        logger.warning(f"Sigma rules file not found: {path}")
        _loaded = True
        return []

    try:
        # pySigma for validation/parsing
        try:
            from sigma.rule import SigmaRule
            from sigma.collection import SigmaCollection
            _use_pysigma = True
        except ImportError:
            _use_pysigma = False

        # YAML multi-document parse
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        documents = list(yaml.safe_load_all(content))
        rules = []

        for doc in documents:
            if not doc or not isinstance(doc, dict):
                continue
            try:
                rule = _parse_sigma_doc(doc)
                if rule:
                    rules.append(rule)
            except Exception as e:
                logger.debug(f"Sigma rule parse error: {e}")

        _sigma_rules = rules
        _loaded = True
        logger.info(f"✅ Sigma: loaded {len(rules)} rule(s) from {path}")
        return rules

    except Exception as e:
        logger.error(f"Sigma rule loading failed: {e}")
        _loaded = True
        return []


def _parse_sigma_doc(doc: dict) -> Optional[dict]:
    """Convert a Sigma YAML document into an AISS detection pattern."""
    title  = doc.get("title", "Unknown")
    level  = doc.get("level", "medium").lower()
    tags   = doc.get("tags", [])
    detect = doc.get("detection", {})

    # Extract string patterns from detection
    patterns = []
    for key, value in detect.items():
        if key in ("condition", "timeframe"):
            continue
        if isinstance(value, dict):
            for field, patterns_raw in value.items():
                if isinstance(patterns_raw, list):
                    for p in patterns_raw:
                        if isinstance(p, str):
                            # Convert Sigma modifiers to regex
                            regex = _sigma_to_regex(p, field)
                            if regex:
                                patterns.append(regex)
                elif isinstance(patterns_raw, str):
                    regex = _sigma_to_regex(patterns_raw, field)
                    if regex:
                        patterns.append(regex)

    if not patterns:
        return None

    return {
        "title":    title,
        "level":    level,
        "tags":     tags,
        "patterns": patterns,
        "description": doc.get("description", title),
    }


def _sigma_to_regex(pattern: str, field: str = "") -> Optional[re.Pattern]:
    """Convert a Sigma string pattern into a compiled regex."""
    try:
        # Handle Sigma wildcards: * → .*, ? → .
        p = re.escape(pattern)
        p = p.replace(r"\*", ".*").replace(r"\?", ".")
        return re.compile(p, re.IGNORECASE | re.DOTALL)
    except Exception:
        return None


def get_rules() -> list[dict]:
    """Return loaded Sigma rules, loading on first call."""
    return load_sigma_rules()


def match_event(event_text: str) -> list[dict]:
    """
    Check event text against all loaded Sigma rules.
    Returns list of matching rules.
    """
    rules = get_rules()
    if not rules:
        return []

    matched = []
    for rule in rules:
        for pattern in rule.get("patterns", []):
            if pattern and pattern.search(event_text):
                matched.append(rule)
                break  # one match per rule is enough
    return matched


def reload_rules() -> int:
    """Force reload of Sigma rules from disk."""
    global _loaded
    _loaded = False
    _sigma_rules.clear()
    rules = load_sigma_rules()
    return len(rules)
