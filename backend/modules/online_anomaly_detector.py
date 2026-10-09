"""AISS - Online Anomaly Detector
Streaming ML anomaly detection using River (online learning).

Instead of static 3-sigma thresholds, this trains continuously on
every network event so the model adapts to the real traffic baseline.

Features:
  - HalfSpaceTrees — online anomaly detection (no batch retraining)
  - StandardScaler — running normalisation
  - Per-feature rolling stats (polars / plain dict fallback)
  - Persists model state to data/online_model.pkl between restarts
  - Gracefully disabled if river is not installed

Usage:
    from modules.online_anomaly_detector import online_detector
    score = online_detector.score({"duration": 12.5, "src_bytes": 1024})
    is_anomaly = online_detector.learn_and_score(event_dict)  # train + score
"""
import asyncio
import json
import os
import pickle
from pathlib import Path
from typing import Any
from utils.logger import setup_logger

logger = setup_logger("online_anomaly")

_MODEL_FILE = Path("data/online_model.pkl")
_STATS_FILE = Path("data/online_stats.json")

# Anomaly score threshold (0-1): above this = anomaly
ANOMALY_THRESHOLD = float(os.environ.get("ONLINE_ANOMALY_THRESHOLD", "0.7"))

# Features to track (subset of NSL-KDD + custom AISS events)
FEATURES = [
    "duration", "src_bytes", "dst_bytes",
    "src_port", "dst_port", "packets_per_sec",
    "bytes_per_sec", "failed_logins", "conn_count",
]


class OnlineAnomalyDetector:
    def __init__(self):
        self._ready = False
        self._model = None
        self._total_seen = 0

    def _ensure_ready(self) -> bool:
        if self._ready:
            return True
        try:
            from core.lib_registry import lib_registry
            if not lib_registry.is_enabled("river"):
                return False

            if _MODEL_FILE.exists():
                with open(_MODEL_FILE, "rb") as f:
                    saved = pickle.load(f)
                self._model     = saved["model"]
                self._total_seen= saved.get("total_seen", 0)
                logger.info(f"[online_anomaly] Loaded model (seen={self._total_seen})")
            else:
                from river import anomaly, preprocessing, compose
                self._model = (
                    preprocessing.StandardScaler() |
                    anomaly.HalfSpaceTrees(n_trees=25, height=15, window_size=250, seed=42)
                )
                logger.info("[online_anomaly] New HalfSpaceTrees model created")

            self._ready = True
            return True
        except Exception as e:
            logger.debug(f"OnlineAnomalyDetector init error: {e}")
            return False

    def _to_features(self, event: dict) -> dict:
        out = {}
        for f in FEATURES:
            v = event.get(f)
            if v is not None:
                try:
                    out[f] = float(v)
                except (ValueError, TypeError):
                    pass
        return out

    def score(self, event: dict) -> float:
        """
        Score an event for anomalousness WITHOUT updating the model.
        Returns float 0.0–1.0 (higher = more anomalous).
        """
        if not self._ensure_ready():
            return 0.0
        x = self._to_features(event)
        if not x:
            return 0.0
        try:
            return float(self._model.score_one(x))
        except Exception:
            return 0.0

    def learn_and_score(self, event: dict) -> tuple[float, bool]:
        """
        Score then train on the event (online learning).
        Returns (score, is_anomaly).
        """
        if not self._ensure_ready():
            return 0.0, False
        x = self._to_features(event)
        if not x:
            return 0.0, False
        try:
            score = float(self._model.score_one(x))
            self._model.learn_one(x)
            self._total_seen += 1
            is_anomaly = score > ANOMALY_THRESHOLD
            # Push score to Prometheus histogram
            try:
                from core.metrics import observe_anomaly_score
                observe_anomaly_score(score)
            except Exception:
                pass
            # Persist every 500 events
            if self._total_seen % 500 == 0:
                self._save()
            return score, is_anomaly
        except Exception as e:
            logger.debug(f"learn_and_score error: {e}")
            return 0.0, False

    def _save(self):
        try:
            with open(_MODEL_FILE, "wb") as f:
                pickle.dump({"model": self._model, "total_seen": self._total_seen}, f)
        except Exception as e:
            logger.debug(f"online model save error: {e}")

    async def learn_batch_async(self, events: list[dict]) -> int:
        """Train on a batch of historical events in a thread executor."""
        if not self._ensure_ready():
            return 0
        loop  = asyncio.get_event_loop()
        count = await loop.run_in_executor(None, lambda: self._learn_batch_sync(events))
        return count

    def _learn_batch_sync(self, events: list[dict]) -> int:
        n = 0
        for ev in events:
            x = self._to_features(ev)
            if x:
                try:
                    self._model.learn_one(x)
                    n += 1
                except Exception:
                    pass
        self._total_seen += n
        self._save()
        return n

    def get_stats(self) -> dict:
        return {
            "ready":           self._ready,
            "total_seen":      self._total_seen,
            "anomaly_threshold": ANOMALY_THRESHOLD,
            "model_file":      str(_MODEL_FILE),
            "model_saved":     _MODEL_FILE.exists(),
        }

    def is_available(self) -> bool:
        return self._ensure_ready()


# Singleton
online_detector = OnlineAnomalyDetector()
