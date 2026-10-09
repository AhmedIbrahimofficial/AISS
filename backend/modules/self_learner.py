"""AISS — Self-Learner Module
Learns threat intelligence from YouTube video transcripts.
Requires: youtube-transcript-api, anthropic (optional — falls back to OpenRouter)
"""
import os
import re
import json
from utils.logger import setup_logger

logger = setup_logger("self_learner")

# Optional heavy imports — graceful fallback
try:
    from youtube_transcript_api import YouTubeTranscriptApi
    _YT_AVAILABLE = True
except ImportError:
    _YT_AVAILABLE = False
    logger.warning("youtube_transcript_api not installed — self-learning disabled")

try:
    from anthropic import Anthropic as _Anthropic
    _ANTHROPIC_AVAILABLE = True
except ImportError:
    _ANTHROPIC_AVAILABLE = False


class SelfLearner:

    def __init__(self):
        self.learned_count = 0
        self._client = None

    def _get_client(self):
        if self._client is None and _ANTHROPIC_AVAILABLE:
            api_key = os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("OPENROUTER_API_KEY")
            if api_key:
                try:
                    self._client = _Anthropic(api_key=api_key)
                except Exception as e:
                    logger.warning(f"Anthropic client init failed: {e}")
        return self._client

    def extract_video_id(self, url: str) -> str:
        patterns = [
            r"youtube\.com/watch\?v=([a-zA-Z0-9_-]{11})",
            r"youtu\.be/([a-zA-Z0-9_-]{11})",
            r"youtube\.com/shorts/([a-zA-Z0-9_-]{11})",
        ]
        for pattern in patterns:
            match = re.search(pattern, url)
            if match:
                return match.group(1)
        raise ValueError("Invalid YouTube URL")

    def get_transcript(self, video_id: str) -> str:
        if not _YT_AVAILABLE:
            raise RuntimeError("youtube_transcript_api not installed")
        try:
            ytt = YouTubeTranscriptApi()
            fetched = ytt.fetch(video_id)
            full_text = " ".join(entry.text for entry in fetched)
            return full_text[:8000]
        except Exception:
            raise ValueError("No transcript available for this video")

    async def analyze_with_ai(self, transcript: str, video_url: str) -> dict:
        client = self._get_client()
        if client is None:
            # Fallback: basic keyword extraction without AI
            return {
                "threats_learned": [],
                "attack_patterns": [],
                "indicators": [],
                "defenses": [],
                "summary": "AI analysis unavailable — configure ANTHROPIC_API_KEY or OPENROUTER_API_KEY",
                "confidence": 0.0,
            }
        response = client.messages.create(
            model="claude-opus-4-5",
            max_tokens=1000,
            system="You are a cybersecurity expert. Extract threat intelligence from video transcripts.",
            messages=[
                {
                    "role": "user",
                    "content": f"""Analyze this cybersecurity video transcript and extract:
1. NEW threat types mentioned
2. NEW attack patterns described
3. NEW indicators of compromise
4. NEW defensive techniques mentioned
5. KEY security insights

Return ONLY valid JSON:
{{
  "threats_learned": ["threat1"],
  "attack_patterns": ["pattern1"],
  "indicators": ["indicator1"],
  "defenses": ["technique1"],
  "summary": "2 sentence summary",
  "confidence": 0.95
}}

Transcript:
{transcript[:6000]}""",
                }
            ],
        )
        response_text = response.content[0].text
        try:
            match = re.search(r"\{.*\}", response_text, re.DOTALL)
            if match:
                return json.loads(match.group())
            return json.loads(response_text)
        except Exception:
            return {"error": "Could not parse AI response", "raw": response_text}

    async def learn_from_youtube(self, url: str) -> dict:
        if not _YT_AVAILABLE:
            return {
                "status": "error",
                "video_url": url,
                "error": "youtube_transcript_api not installed. Run: pip install youtube-transcript-api",
            }
        try:
            video_id   = self.extract_video_id(url)
            transcript = self.get_transcript(video_id)
            knowledge  = await self.analyze_with_ai(transcript, url)
            self.learned_count += 1
            logger.info(f"Video analyzed: {url} | threats: {len(knowledge.get('threats_learned', []))}")
            return {
                "status":        "success",
                "video_url":     url,
                "video_id":      video_id,
                "knowledge":     knowledge,
                "total_learned": self.learned_count,
            }
        except Exception as e:
            return {"status": "error", "video_url": url, "error": str(e)}


self_learner = SelfLearner()
