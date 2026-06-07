from youtube_transcript_api import YouTubeTranscriptApi
import os, re, json
from anthropic import Anthropic


class SelfLearner:

    def __init__(self):
        self.client = Anthropic()
        self.learned_count = 0

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
        try:
            ytt = YouTubeTranscriptApi()
            fetched = ytt.fetch(video_id)
            full_text = " ".join(entry.text for entry in fetched)
            return full_text[:8000]
        except Exception:
            raise ValueError("No transcript available for this video")

    async def analyze_with_ai(self, transcript: str, video_url: str) -> dict:
        response = self.client.messages.create(
            model="claude-opus-4-5",
            max_tokens=1000,
            system="You are a cybersecurity expert. Extract threat intelligence from video transcripts.",
            messages=[
                {
                    "role": "user",
                    "content": f"""Analyze this cybersecurity video transcript and extract:
1. NEW threat types mentioned (names, techniques)
2. NEW attack patterns described
3. NEW indicators of compromise (IPs, domains, file names, ports)
4. NEW defensive techniques mentioned
5. KEY security insights

Return ONLY valid JSON in this exact format:
{{
  "threats_learned": ["threat1", "threat2"],
  "attack_patterns": ["pattern1", "pattern2"],
  "indicators": ["ip/domain/filename"],
  "defenses": ["technique1", "technique2"],
  "summary": "2 sentence summary of what was learned",
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
        try:
            video_id   = self.extract_video_id(url)
            transcript = self.get_transcript(video_id)
            knowledge  = await self.analyze_with_ai(transcript, url)
            self.learned_count += 1
            print(f"\033[96m[AISS LEARN] Video analyzed: {url}\033[0m")
            print(f"\033[92m[AISS LEARN] Threats learned: {len(knowledge.get('threats_learned', []))}\033[0m")
            print(f"\033[92m[AISS LEARN] Summary: {knowledge.get('summary', '')}\033[0m")
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
