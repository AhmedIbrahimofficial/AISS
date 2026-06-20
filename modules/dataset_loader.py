"""AISS - Dataset Loader & Pattern Extractor
Loads real cybersecurity datasets and extracts statistical thresholds
that are used by NetworkMonitor, MalwareScanner, and FileMonitor
for data-driven detection (instead of pure hardcoded rules).
"""

import json
import statistics
from pathlib import Path
from datetime import datetime

DATASET_DIR   = Path("datasets")
PATTERNS_FILE = Path("data/dataset_patterns.json")
PATTERNS_FILE.parent.mkdir(exist_ok=True)


class DatasetLoader:
    def __init__(self):
        self.patterns = self._load_saved_patterns()

    # ── Load saved patterns on startup ───────────────────────────────

    def _load_saved_patterns(self) -> dict:
        if PATTERNS_FILE.exists():
            try:
                with open(PATTERNS_FILE) as f:
                    data = json.load(f)
                    print(f"\033[92m[AISS DATASET] Loaded saved patterns "
                          f"({data.get('total_rows_processed', 0)} rows)\033[0m")
                    return data
            except Exception:
                pass
        return {
            "network_thresholds":    {},
            "phishing_thresholds":   {},
            "malware_features":      [],
            "network_attack_signatures": [],
            "phishing_indicators":   [],
            "loaded_at":             None,
            "total_rows_processed":  0,
        }

    # ── Network intrusion dataset ─────────────────────────────────────

    def load_network_intrusion(self, filename="network_intrusion.csv") -> dict:
        """
        Load NSL-KDD style dataset and extract statistical thresholds.
        Computes per-feature mean/std for anomaly vs normal traffic.
        """
        filepath = DATASET_DIR / filename
        if not filepath.exists():
            print(f"\033[93m[AISS DATASET] Not found: {filepath}\033[0m")
            return {"status": "not_found"}

        try:
            import pandas as pd
            df = pd.read_csv(filepath)

            # Find label column
            label_col = next(
                (c for c in ["label", "attack_type", "class", "Label", "attack", "Class"]
                 if c in df.columns), None
            )

            thresholds = {}
            attack_types = []

            if label_col:
                attack_types = df[label_col].unique().tolist()
                normal_mask  = df[label_col].astype(str).str.lower().isin(["normal", "0", "benign"])
                anomaly_mask = ~normal_mask

                normal_df  = df[normal_mask]
                anomaly_df = df[anomaly_mask]

                # Key features from NSL-KDD that map to our network monitor
                key_features = [
                    "duration", "src_bytes", "dst_bytes",
                    "count", "srv_count",
                    "serror_rate", "srv_serror_rate",
                    "rerror_rate", "srv_rerror_rate",
                    "dst_host_count", "dst_host_srv_count",
                    "num_failed_logins", "num_compromised",
                    "wrong_fragment", "urgent",
                ]

                for feat in key_features:
                    if feat not in df.columns:
                        continue
                    try:
                        normal_vals  = normal_df[feat].dropna().tolist()
                        anomaly_vals = anomaly_df[feat].dropna().tolist()

                        if not normal_vals:
                            continue

                        normal_mean = statistics.mean(normal_vals)
                        normal_std  = statistics.stdev(normal_vals) if len(normal_vals) > 1 else 0

                        thresholds[feat] = {
                            "normal_mean":   round(normal_mean, 4),
                            "normal_std":    round(normal_std, 4),
                            # Flag if > mean + 3*std (3-sigma rule)
                            "alert_above":   round(normal_mean + 3 * normal_std, 4),
                            "anomaly_mean":  round(statistics.mean(anomaly_vals), 4) if anomaly_vals else None,
                        }
                    except Exception:
                        pass

            self.patterns["network_thresholds"]      = thresholds
            self.patterns["network_attack_signatures"] = [{
                "total_rows":        len(df),
                "attack_types_found": attack_types[:20],
                "columns":           df.columns.tolist(),
                "thresholds_computed": list(thresholds.keys()),
            }]
            self.patterns["total_rows_processed"] += len(df)

            print(f"\033[92m[AISS DATASET] Network data: {len(df)} rows, "
                  f"{len(thresholds)} thresholds computed\033[0m")
            print(f"\033[96m[AISS DATASET] Attack types: {attack_types[:5]}\033[0m")
            return {"status": "success", "rows": len(df), "thresholds": len(thresholds)}

        except Exception as e:
            print(f"\033[91m[AISS DATASET] Network load error: {e}\033[0m")
            return {"status": "error", "error": str(e)}

    # ── Phishing URL dataset ──────────────────────────────────────────

    def load_phishing_urls(self, filename="phishing_urls.csv") -> dict:
        """
        Load phishing URL dataset and extract feature thresholds.
        Features like url_length, nb_dots, nb_hyphens etc. are used
        to score URLs in real-time detection.
        """
        filepath = DATASET_DIR / filename
        if not filepath.exists():
            print(f"\033[93m[AISS DATASET] Not found: {filepath}\033[0m")
            return {"status": "not_found"}

        try:
            import pandas as pd
            df = pd.read_csv(filepath)

            label_col = next(
                (c for c in ["status", "Result", "class", "Class", "label", "phishing"]
                 if c in df.columns), None
            )

            thresholds = {}

            if label_col:
                phishing_mask  = df[label_col].astype(str).str.lower().isin(
                    ["phishing", "-1", "1"])
                legit_mask     = ~phishing_mask

                phishing_df = df[phishing_mask]
                legit_df    = df[legit_mask]

                # URL features that indicate phishing
                url_features = [
                    "length_url", "length_hostname", "nb_dots", "nb_hyphens",
                    "nb_at", "nb_qm", "nb_and", "nb_eq", "nb_underscore",
                    "nb_slash", "nb_percent", "nb_colon",
                    "ip",  # IP address as hostname = suspicious
                    "https_token", "ratio_digits_url", "ratio_digits_host",
                    "punycode", "port", "tld_in_path", "tld_in_subdomain",
                    "abnormal_subdomain", "nb_subdomains",
                    "shortening_service", "nb_external_redirection",
                ]

                for feat in url_features:
                    if feat not in df.columns:
                        continue
                    try:
                        legit_vals    = legit_df[feat].dropna().tolist()
                        phishing_vals = phishing_df[feat].dropna().tolist()

                        if not legit_vals:
                            continue

                        legit_mean    = statistics.mean(legit_vals)
                        legit_std     = statistics.stdev(legit_vals) if len(legit_vals) > 1 else 0
                        phish_mean    = statistics.mean(phishing_vals) if phishing_vals else 0

                        thresholds[feat] = {
                            "legit_mean":   round(legit_mean, 4),
                            "legit_std":    round(legit_std, 4),
                            "alert_above":  round(legit_mean + 2 * legit_std, 4),
                            "phish_mean":   round(phish_mean, 4),
                        }
                    except Exception:
                        pass

            phishing_count = int(phishing_mask.sum()) if label_col else 0
            legit_count    = int(legit_mask.sum()) if label_col else 0

            self.patterns["phishing_thresholds"] = thresholds
            self.patterns["phishing_indicators"] = [{
                "total_urls":      len(df),
                "phishing_urls":   phishing_count,
                "legitimate_urls": legit_count,
                "feature_columns": df.columns.tolist()[:20],
                "thresholds_computed": list(thresholds.keys()),
            }]
            self.patterns["total_rows_processed"] += len(df)

            print(f"\033[92m[AISS DATASET] Phishing data: {len(df)} URLs, "
                  f"{len(thresholds)} feature thresholds\033[0m")
            return {"status": "success", "rows": len(df), "thresholds": len(thresholds)}

        except Exception as e:
            print(f"\033[91m[AISS DATASET] Phishing load error: {e}\033[0m")
            return {"status": "error", "error": str(e)}

    # ── Malware detection dataset ─────────────────────────────────────

    def load_malware_detection(self, filename="malware_detection.csv") -> dict:
        """
        Load malware detection dataset.
        Extracts feature importance ranking for malware vs benign files.
        """
        filepath = DATASET_DIR / filename
        if not filepath.exists():
            print(f"\033[93m[AISS DATASET] Not found: {filepath}\033[0m")
            return {"status": "not_found"}

        try:
            import pandas as pd
            df = pd.read_csv(filepath)

            label_col = next(
                (c for c in ["legitimate", "malware", "label", "Class", "class", "anomaly", "class"]
                 if c in df.columns), None
            )

            feature_thresholds = {}

            if label_col:
                malware_mask = df[label_col].astype(str).str.lower().isin(
                    ["0", "malware", "anomaly", "malicious"])
                benign_mask  = ~malware_mask

                malware_df = df[malware_mask]
                benign_df  = df[benign_mask]

                numeric_cols = df.select_dtypes(include=["number"]).columns.tolist()
                if label_col in numeric_cols:
                    numeric_cols.remove(label_col)

                for feat in numeric_cols[:30]:
                    try:
                        benign_vals  = benign_df[feat].dropna().tolist()
                        malware_vals = malware_df[feat].dropna().tolist()
                        if not benign_vals or not malware_vals:
                            continue

                        benign_mean  = statistics.mean(benign_vals)
                        benign_std   = statistics.stdev(benign_vals) if len(benign_vals) > 1 else 0
                        malware_mean = statistics.mean(malware_vals)

                        # Only keep features with significant difference
                        if benign_std > 0 and abs(malware_mean - benign_mean) > 2 * benign_std:
                            feature_thresholds[feat] = {
                                "benign_mean":  round(benign_mean, 4),
                                "benign_std":   round(benign_std, 4),
                                "malware_mean": round(malware_mean, 4),
                                "alert_above":  round(benign_mean + 2 * benign_std, 4),
                            }
                    except Exception:
                        pass

            malware_count = int(malware_mask.sum()) if label_col else 0
            benign_count  = int(benign_mask.sum()) if label_col else 0

            self.patterns["malware_features"] = [{
                "total_samples":   len(df),
                "malware_samples": malware_count,
                "benign_samples":  benign_count,
                "feature_thresholds": feature_thresholds,
                "feature_columns": df.columns.tolist()[:20],
            }]
            self.patterns["total_rows_processed"] += len(df)

            print(f"\033[92m[AISS DATASET] Malware data: {len(df)} samples, "
                  f"{len(feature_thresholds)} discriminating features\033[0m")
            return {"status": "success", "rows": len(df),
                    "discriminating_features": len(feature_thresholds)}

        except Exception as e:
            print(f"\033[91m[AISS DATASET] Malware load error: {e}\033[0m")
            return {"status": "error", "error": str(e)}

    # ── Load all ──────────────────────────────────────────────────────

    def load_all_datasets(self) -> dict:
        print(f"\033[96m[AISS DATASET] Loading all datasets...\033[0m")
        self.patterns["total_rows_processed"] = 0  # reset counter

        results = {
            "network":  self.load_network_intrusion(),
            "malware":  self.load_malware_detection(),
            "phishing": self.load_phishing_urls(),
        }
        self.patterns["loaded_at"] = datetime.now().isoformat()

        with open(PATTERNS_FILE, "w") as f:
            json.dump(self.patterns, f, indent=2, default=str)

        print(f"\033[92m[AISS DATASET] Done! {self.patterns['total_rows_processed']} rows "
              f"→ {PATTERNS_FILE}\033[0m")
        return results

    # ── Public accessors used by detection modules ────────────────────

    def get_patterns(self) -> dict:
        if PATTERNS_FILE.exists():
            try:
                with open(PATTERNS_FILE) as f:
                    return json.load(f)
            except Exception:
                pass
        return self.patterns

    def get_network_threshold(self, feature: str) -> dict:
        """Return computed threshold for a network feature."""
        return self.patterns.get("network_thresholds", {}).get(feature, {})

    def get_phishing_threshold(self, feature: str) -> dict:
        """Return computed threshold for a URL feature."""
        return self.patterns.get("phishing_thresholds", {}).get(feature, {})

    def is_network_anomaly(self, feature: str, value: float) -> bool:
        """Return True if value exceeds the 3-sigma alert threshold."""
        t = self.get_network_threshold(feature)
        if not t or "alert_above" not in t:
            return False
        return value > t["alert_above"]

    def score_url(self, url: str) -> float:
        """
        Score a URL for phishing likelihood (0.0 = clean, 1.0 = very suspicious).
        Uses dataset-derived thresholds.
        """
        score = 0.0
        checks = 0
        thresholds = self.patterns.get("phishing_thresholds", {})
        if not thresholds:
            return 0.0

        def _check(feat, value):
            nonlocal score, checks
            t = thresholds.get(feat, {})
            if t and "alert_above" in t and value > t["alert_above"]:
                score += 1.0
            checks += 1

        _check("length_url",      len(url))
        _check("nb_dots",         url.count("."))
        _check("nb_hyphens",      url.count("-"))
        _check("nb_at",           url.count("@"))
        _check("nb_percent",      url.count("%"))
        _check("nb_slash",        url.count("/"))
        _check("nb_underscore",   url.count("_"))

        # IP address as hostname
        import re
        if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
            score += 2.0
            checks += 1

        # Shortening services
        shorteners = ["bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly", "short.link"]
        if any(s in url.lower() for s in shorteners):
            score += 1.5
            checks += 1

        return min(score / max(checks, 1), 1.0)


# ── Global singleton used by all modules ──────────────────────────────
dataset_loader = DatasetLoader()
