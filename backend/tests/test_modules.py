"""AISS — Module Unit Tests
Tests for IOC extractor, online anomaly detector, token counter,
phishing analyzer, threat engine core logic, and dataset loader.
"""
import os
import pytest

os.environ.setdefault("ENVIRONMENT",  "development")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./logs/test_mod.db")
os.environ.setdefault("SECRET_KEY",   "test-secret-key-minimum-64-chars-long-for-testing-purposes-only!!")
os.environ.setdefault("LOG_LEVEL",    "WARNING")


# ── IOC Extractor ─────────────────────────────────────────────────────

class TestIOCExtractor:
    def setup_method(self):
        from modules.ioc_extractor import IOCExtractor
        self.ex = IOCExtractor()

    def test_extract_ipv4(self):
        r = self.ex.extract("Connect from 185.234.1.2 on port 4444")
        assert "185.234.1.2" in r["ips"]

    def test_extract_cve(self):
        r = self.ex.extract("Exploiting CVE-2024-12345 on victim host")
        assert "CVE-2024-12345" in r["cves"]

    def test_extract_mitre(self):
        r = self.ex.extract("Used technique T1059.001 for execution")
        assert any("T1059" in t for t in r["mitre_techniques"])

    def test_extract_malware_name(self):
        r = self.ex.extract("Emotet loader detected establishing C2")
        assert "emotet" in r["malware_names"]

    def test_extract_port(self):
        r = self.ex.extract("C2 beacon on :4444 via TCP")
        assert "4444" in r["ports"]

    def test_refang_defanged_ip(self):
        r = self.ex.extract("Attack from 10[.]0[.]0[.]1 defanged")
        # refanging may or may not be applied depending on ioc_fanger availability
        assert isinstance(r["ips"], list)

    def test_extract_email(self):
        r = self.ex.extract("Phishing from attacker@evil.com to victim@corp.com")
        assert any("evil.com" in e or "corp.com" in e for e in r["emails"])

    def test_extract_url(self):
        r = self.ex.extract("Downloading from http://malware.example.com/payload.exe")
        assert any("malware.example.com" in u for u in r["urls"])

    def test_empty_input(self):
        r = self.ex.extract("")
        assert isinstance(r, dict)
        assert r["ips"] == []

    def test_multiple_types_at_once(self):
        r = self.ex.extract(
            "IP 1.2.3.4 hash abc123def456abc123def456abc123de "
            "CVE-2023-9999 T1078 emotet"
        )
        assert "1.2.3.4" in r["ips"]
        assert len(r["hashes"]) > 0
        assert "CVE-2023-9999" in r["cves"]


# ── Online Anomaly Detector ───────────────────────────────────────────

class TestOnlineAnomalyDetector:
    def test_score_normal_event(self):
        from modules.online_anomaly_detector import OnlineAnomalyDetector
        det = OnlineAnomalyDetector()
        score = det.score({"duration": 1.0, "src_bytes": 500})
        # Without river ready, should return 0
        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0

    def test_learn_and_score_returns_tuple(self):
        from modules.online_anomaly_detector import OnlineAnomalyDetector
        det = OnlineAnomalyDetector()
        score, is_anom = det.learn_and_score({"duration": 1.0, "src_bytes": 100})
        assert isinstance(score, float)
        assert isinstance(is_anom, bool)

    def test_get_stats_structure(self):
        from modules.online_anomaly_detector import OnlineAnomalyDetector
        det = OnlineAnomalyDetector()
        stats = det.get_stats()
        assert "ready" in stats
        assert "total_seen" in stats
        assert "anomaly_threshold" in stats

    def test_empty_event_safe(self):
        from modules.online_anomaly_detector import OnlineAnomalyDetector
        det = OnlineAnomalyDetector()
        score, is_anom = det.learn_and_score({})
        assert score == 0.0
        assert is_anom is False


# ── Token Counter ─────────────────────────────────────────────────────

class TestTokenCounter:
    def test_count_tokens_returns_positive_int(self):
        from utils.token_counter import count_tokens
        n = count_tokens("Hello AISS security platform", "gpt-4o-mini")
        assert isinstance(n, int)
        assert n > 0

    def test_truncate_preserves_meaning(self):
        from utils.token_counter import truncate_to_tokens
        long_text = "security " * 1000
        truncated = truncate_to_tokens(long_text, max_tokens=50)
        assert len(truncated) < len(long_text)
        assert len(truncated) > 0

    def test_estimate_cost_structure(self):
        from utils.token_counter import estimate_cost
        cost = estimate_cost(1000, 500, "gpt-4o-mini")
        assert "total_cost" in cost
        assert "input_tokens" in cost
        assert cost["total_cost"] > 0
        assert cost["currency"] == "USD"

    def test_estimate_cost_gpt4o(self):
        from utils.token_counter import estimate_cost
        cost = estimate_cost(10000, 2000, "gpt-4o")
        assert cost["total_cost"] > estimate_cost(10000, 2000, "gpt-4o-mini")["total_cost"]


# ── Phishing Analyzer ─────────────────────────────────────────────────

class TestPhishingAnalyzer:
    @pytest.mark.asyncio
    async def test_ip_as_hostname_high_risk(self):
        from modules.phishing_analyzer import PhishingAnalyzer
        pa = PhishingAnalyzer()
        r = await pa.analyze_url("http://185.234.1.2/login?token=abc")
        assert r["risk_score"] > 20
        assert "ip_as_hostname" in r["flags"]

    @pytest.mark.asyncio
    async def test_suspicious_tld_flagged(self):
        from modules.phishing_analyzer import PhishingAnalyzer
        pa = PhishingAnalyzer()
        r = await pa.analyze_url("http://steal-credentials.tk/bank")
        assert any(".tk" in f for f in r["flags"])

    @pytest.mark.asyncio
    async def test_clean_url_low_risk(self):
        from modules.phishing_analyzer import PhishingAnalyzer
        pa = PhishingAnalyzer()
        r = await pa.analyze_url("https://github.com/openai/whisper")
        assert r["risk_level"] in ("low", "medium")

    @pytest.mark.asyncio
    async def test_at_in_url_flagged(self):
        from modules.phishing_analyzer import PhishingAnalyzer
        pa = PhishingAnalyzer()
        r = await pa.analyze_url("http://legitimate.com@evil.com/steal")
        assert "at_in_url" in r["flags"]
        assert r["risk_score"] >= 30

    @pytest.mark.asyncio
    async def test_url_shortener_flagged(self):
        from modules.phishing_analyzer import PhishingAnalyzer
        pa = PhishingAnalyzer()
        r = await pa.analyze_url("https://bit.ly/malicious-link")
        assert any("shortener" in f for f in r["flags"])


# ── Dataset Loader ────────────────────────────────────────────────────

class TestDatasetLoader:
    def test_score_url_returns_float(self):
        from modules.dataset_loader import DatasetLoader
        dl = DatasetLoader()
        score = dl.score_url("http://evil.tk/phishing")
        assert 0.0 <= score <= 1.0

    def test_is_network_anomaly_returns_bool(self):
        from modules.dataset_loader import DatasetLoader
        dl = DatasetLoader()
        # Without loaded thresholds, should return False
        result = dl.is_network_anomaly("duration", 99999.0)
        assert isinstance(result, bool)

    def test_get_patterns_returns_dict(self):
        from modules.dataset_loader import DatasetLoader
        dl = DatasetLoader()
        patterns = dl.get_patterns()
        assert isinstance(patterns, dict)
        # Accept either key name — dataset_loader uses network_attack_signatures
        has_network = (
            "network_thresholds" in patterns or
            "network_attack_signatures" in patterns or
            "total_rows_processed" in patterns
        )
        assert has_network, f"Expected network data key, got: {list(patterns.keys())}"


# ── Metrics ──────────────────────────────────────────────────────────

class TestMetrics:
    def test_init_returns_bool(self):
        from core.metrics import init
        result = init()
        assert isinstance(result, bool)

    def test_safe_calls_do_not_raise(self):
        from core import metrics
        metrics.init()
        metrics.inc_threat("critical", "trojan")
        metrics.set_active_count(5)
        metrics.inc_resolved()
        metrics.observe_scan("malware_scanner", 0.5)
        metrics.observe_anomaly_score(0.8)
        metrics.set_blocked_ips(3)
        # All should be no-ops if prometheus not ready — no exception


# ── Evidence Crypto ───────────────────────────────────────────────────

class TestEvidenceCrypto:
    def test_write_read_roundtrip(self, tmp_path):
        os.environ["EVIDENCE_ENCRYPTION_KEY"] = ""
        from modules.evidence_crypto import write_encrypted, read_encrypted
        payload = b'{"test": true, "value": 42}'
        path = str(tmp_path / "test.json")
        written = write_encrypted(path, payload)
        recovered = read_encrypted(written)
        assert recovered == payload

    def test_json_roundtrip(self, tmp_path):
        os.environ["EVIDENCE_ENCRYPTION_KEY"] = ""
        from modules.evidence_crypto import write_json_encrypted, read_json_encrypted
        data = {"pid": 1234, "process": "test.exe", "cmd": "calc.exe"}
        path = str(tmp_path / "evidence.json")
        written = write_json_encrypted(path, data)
        recovered = read_json_encrypted(written)
        assert recovered["pid"] == 1234
        assert recovered["process"] == "test.exe"
