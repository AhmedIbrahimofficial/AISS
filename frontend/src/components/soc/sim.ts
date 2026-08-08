/* Deterministic pseudo-random helpers so SSR and client render identically. */

export function seeded(seed: string) {
  let h = 2166136261;
  for (let i = 0; i < seed.length; i++) {
    h ^= seed.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return () => {
    h += 0x6d2b79f5;
    let t = h;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export const pick = <T,>(r: () => number, arr: readonly T[]) => arr[Math.floor(r() * arr.length)]!;
export const int = (r: () => number, a: number, b: number) => a + Math.floor(r() * (b - a + 1));

export const COUNTRIES = [
  ["Russia", "RU"],
  ["China", "CN"],
  ["Brazil", "BR"],
  ["Netherlands", "NL"],
  ["Vietnam", "VN"],
  ["United States", "US"],
  ["India", "IN"],
  ["Iran", "IR"],
  ["Türkiye", "TR"],
  ["Nigeria", "NG"],
] as const;

export const TACTICS = [
  "initial-access",
  "execution",
  "persistence",
  "privilege-escalation",
  "defense-evasion",
  "credential-access",
  "discovery",
  "lateral-movement",
  "collection",
  "command-and-control",
  "exfiltration",
  "impact",
] as const;

export const VECTORS = [
  "email",
  "web",
  "endpoint",
  "identity",
  "cloud",
  "rdp",
  "vpn",
  "usb",
  "api-abuse",
  "supply-chain",
] as const;

export const MALWARE = [
  "Emotet",
  "LockBit 3.0",
  "AgentTesla",
  "Cobalt Strike",
  "QakBot",
  "RedLine Stealer",
  "Mirai",
  "BlackCat",
];

export const TECHNIQUES = [
  ["T1566.001", "Spearphishing Attachment"],
  ["T1059.001", "PowerShell"],
  ["T1486", "Data Encrypted for Impact"],
  ["T1021.001", "Remote Desktop Protocol"],
  ["T1055", "Process Injection"],
  ["T1110.003", "Password Spraying"],
  ["T1071.001", "Web Protocols C2"],
  ["T1567.002", "Exfiltration to Cloud Storage"],
] as const;

export const CVES = ["CVE-2026-21042", "CVE-2025-53770", "CVE-2025-31324", "CVE-2024-3400"];

export function title(slug: string) {
  return slug
    .split("-")
    .map((w) => (w.length <= 3 ? w.toUpperCase() : w[0]!.toUpperCase() + w.slice(1)))
    .join(" ");
}

export function ip(r: () => number) {
  const pools = ["192.168.1.", "10.0.4.", "172.16.9.", "45.83.12.", "203.0.113.", "185.22.4."];
  return pick(r, pools) + int(r, 10, 250);
}

export function host(r: () => number) {
  return `${pick(r, ["EPA", "SRV", "WKS", "DC", "K8S"])}-${int(r, 100, 999)}`;
}

export function hash(r: () => number, len = 64) {
  let s = "";
  const c = "0123456789abcdef";
  for (let i = 0; i < len; i++) s += c[Math.floor(r() * 16)];
  return s;
}
