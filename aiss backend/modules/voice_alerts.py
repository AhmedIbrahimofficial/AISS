"""AISS - Voice Alert System
Speaks critical security alerts aloud using pyttsx3 / edge-tts.
Only fires for CRITICAL severity to avoid alert fatigue.

Libraries used: pyttsx3 (offline), edge-tts (online, better quality)
Gracefully disabled when unavailable or DISABLE_TTS=true.

Usage:
    from modules.voice_alerts import voice_alerts
    await voice_alerts.speak_threat(threat_dict)
"""
import asyncio
import os
from utils.logger import setup_logger

logger = setup_logger("voice_alerts")

_ENABLED = os.environ.get("DISABLE_TTS", "").lower() not in ("1", "true")
_MIN_SEVERITY = os.environ.get("VOICE_ALERT_MIN_SEVERITY", "critical").lower()

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


class VoiceAlerts:
    def __init__(self):
        self._engine    = None
        self._edge_tts  = None
        self._tried     = False
        self._min_rank  = _SEVERITY_RANK.get(_MIN_SEVERITY, 4)

    def _lazy_init(self):
        if self._tried:
            return
        self._tried = True
        if not _ENABLED:
            return
        try:
            from core.lib_registry import lib_registry
            if lib_registry.is_enabled("tts"):
                self._engine = lib_registry.get("tts")
            # Try edge-tts for higher quality
            try:
                import edge_tts
                self._edge_tts = edge_tts
            except ImportError:
                pass
        except Exception as e:
            logger.debug(f"VoiceAlerts init: {e}")

    async def speak(self, text: str) -> bool:
        """Speak text. Returns True if spoken, False if unavailable/disabled."""
        self._lazy_init()
        if not _ENABLED:
            return False

        # ── edge-tts (preferred — better voice) ──────────────────────
        if self._edge_tts:
            try:
                import tempfile
                tts       = self._edge_tts.Communicate(text, voice="en-US-AriaNeural")
                tmp_file  = tempfile.mktemp(suffix=".mp3")
                await tts.save(tmp_file)
                # Play using playsound if available, else skip
                try:
                    import playsound
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(None, lambda: playsound.playsound(tmp_file))
                except ImportError:
                    pass  # playsound not installed — edge-tts saved file but can't play
                os.unlink(tmp_file)
                return True
            except Exception as e:
                logger.debug(f"edge-tts speak error: {e}")

        # ── pyttsx3 fallback ──────────────────────────────────────────
        if self._engine:
            try:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(
                    None,
                    lambda: (self._engine.say(text), self._engine.runAndWait())
                )
                return True
            except Exception as e:
                logger.debug(f"pyttsx3 speak error: {e}")

        return False

    async def speak_threat(self, threat: dict) -> bool:
        """Speak a threat alert if severity meets threshold."""
        severity = str(threat.get("severity", "low")).lower()
        rank     = _SEVERITY_RANK.get(severity, 1)
        if rank < self._min_rank:
            return False

        t_type = threat.get("type", "Unknown")
        source = threat.get("source", "unknown source")
        text   = f"Security alert. {severity} severity. {t_type} detected from {source}."
        return await self.speak(text)

    def is_available(self) -> bool:
        self._lazy_init()
        return bool(self._engine or self._edge_tts) and _ENABLED


# Singleton
voice_alerts = VoiceAlerts()
