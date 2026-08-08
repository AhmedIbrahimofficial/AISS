from youtube_transcript_api import YouTubeTranscriptApi
import re, json, os
from pathlib import Path
from datetime import datetime


CYBER_KEYWORDS = {
    "malware_names": [
        "wannacry", "notpetya", "emotet", "trickbot", "ryuk",
        "lockbit", "blackcat", "alphv", "conti", "revil", "sodinokibi",
        "cobalt strike", "mimikatz", "metasploit", "stuxnet", "zeus",
        "mirai", "darkside", "ragnarlocker", "hive", "clop"
    ],
    "attack_techniques": [
        "sql injection", "xss", "cross site scripting", "buffer overflow",
        "privilege escalation", "lateral movement", "credential dumping",
        "pass the hash", "golden ticket", "kerberoasting", "phishing",
        "spear phishing", "man in the middle", "arp spoofing", "dns poisoning",
        "zero day", "supply chain attack", "living off the land",
        "fileless malware", "process injection", "dll hijacking"
    ],
    "cve_pattern": r"CVE-\d{4}-\d{4,7}",
    "suspicious_ports": [
        "4444", "1337", "31337", "9999", "8888", "6666",
        "4545", "5555", "7777", "12345", "54321"
    ],
    "malicious_domains": [
        ".tk", ".ml", ".ga", ".cf", "pastebin.com",
        "ngrok.io", "duckdns.org"
    ],
    "attack_tools": [
        "nmap", "masscan", "shodan", "burpsuite", "wireshark",
        "aircrack", "hashcat", "john the ripper", "sqlmap",
        "nikto", "dirb", "gobuster", "hydra", "medusa"
    ],
}


class KeywordLearner:

    def __init__(self):
        self.learned_patterns_file = Path("data/learned_patterns.json")
        self.learned_patterns_file.parent.mkdir(exist_ok=True)
        self.patterns = self._load_existing_patterns()
        self.total_extracted = 0

    def _load_existing_patterns(self) -> dict:
        if self.learned_patterns_file.exists():
            with open(self.learned_patterns_file) as f:
                return json.load(f)
        return {
            "malware_names":      [],
            "attack_techniques":  [],
            "cve_numbers":        [],
            "suspicious_ports":   [],
            "tools":              [],
            "last_updated":       None,
            "total_sources":      0,
        }

    def _save_patterns(self):
        self.patterns["last_updated"] = datetime.now().isoformat()
        with open(self.learned_patterns_file, "w") as f:
            json.dump(self.patterns, f, indent=2)

    def extract_video_id(self, url: str) -> str:
        patterns = [
            r"watch\?v=([^&]+)",
            r"youtu\.be/([^?]+)",
            r"shorts/([^?]+)",
        ]
        for p in patterns:
            m = re.search(p, url)
            if m:
                return m.group(1)
        raise ValueError("Invalid YouTube URL")

    def get_transcript(self, video_id: str) -> str:
        ytt = YouTubeTranscriptApi()
        fetched = ytt.fetch(video_id)
        text = " ".join(entry.text for entry in fetched)
        return text.lower()

    def extract_patterns(self, transcript: str) -> dict:
        found = {
            "malware_names":     [],
            "attack_techniques": [],
            "cve_numbers":       [],
            "suspicious_ports":  [],
            "tools":             [],
        }

        for name in CYBER_KEYWORDS["malware_names"]:
            if name in transcript:
                if name not in self.patterns["malware_names"]:
                    if name not in found["malware_names"]:
                        found["malware_names"].append(name)

        for tech in CYBER_KEYWORDS["attack_techniques"]:
            if tech in transcript:
                if tech not in self.patterns["attack_techniques"]:
                    if tech not in found["attack_techniques"]:
                        found["attack_techniques"].append(tech)

        cves = re.findall(CYBER_KEYWORDS["cve_pattern"], transcript.upper())
        for cve in cves:
            if cve not in self.patterns["cve_numbers"]:
                if cve not in found["cve_numbers"]:
                    found["cve_numbers"].append(cve)

        for port in CYBER_KEYWORDS["suspicious_ports"]:
            if port in transcript:
                if port not in self.patterns["suspicious_ports"]:
                    if port not in found["suspicious_ports"]:
                        found["suspicious_ports"].append(port)

        for tool in CYBER_KEYWORDS["attack_tools"]:
            if tool in transcript:
                if tool not in self.patterns["tools"]:
                    if tool not in found["tools"]:
                        found["tools"].append(tool)

        return found

    def update_patterns(self, new_patterns: dict):
        for key in ["malware_names", "attack_techniques", "cve_numbers", "suspicious_ports", "tools"]:
            self.patterns[key].extend(new_patterns.get(key, []))
        self.patterns["total_sources"] += 1
        self._save_patterns()

    def learn_from_youtube(self, url: str) -> dict:
        try:
            video_id     = self.extract_video_id(url)
            transcript   = self.get_transcript(video_id)
            new_patterns = self.extract_patterns(transcript)
            self.update_patterns(new_patterns)

            total_new = sum(len(v) for v in new_patterns.values())
            self.total_extracted += total_new

            print(f"\033[96m[AISS LEARN] YouTube analyzed: {url}\033[0m")
            print(f"\033[92m[AISS LEARN] New patterns found: {total_new}\033[0m")
            if new_patterns["malware_names"]:
                print(f"\033[93m[AISS LEARN] New malware: {new_patterns['malware_names']}\033[0m")
            if new_patterns["cve_numbers"]:
                print(f"\033[91m[AISS LEARN] CVEs found: {new_patterns['cve_numbers']}\033[0m")
            if new_patterns["attack_techniques"]:
                print(f"\033[96m[AISS LEARN] Techniques: {new_patterns['attack_techniques']}\033[0m")

            return {
                "status":               "success",
                "video_url":            url,
                "new_patterns_found":   total_new,
                "details":              new_patterns,
                "total_known_patterns": self.total_extracted,
            }

        except Exception as e:
            print(f"\033[91m[AISS LEARN] Error: {str(e)}\033[0m")
            return {"status": "error", "error": str(e)}


keyword_learner = KeywordLearner()
