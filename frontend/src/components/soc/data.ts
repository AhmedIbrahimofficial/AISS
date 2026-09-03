export const C = {
  cyan: "#3B82F6",
  teal: "#10B981",
  critical: "#DC2626",
  warning: "#D97706",
  success: "#22C55E",
  campaign: "#0EA5E9",
  text: "#E6EDEA",
  muted: "#7C8C85",
} as const;

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export const sevColor: Record<Severity, string> = {
  CRITICAL: C.critical,
  HIGH: C.warning,
  MEDIUM: C.warning,
  LOW: C.cyan,
};

export const THREAT_TYPES = [
  "Port Scan",
  "Brute Force SSH",
  "Malware Signature",
  "C2 Traffic",
  "Ransomware",
  "Data Exfiltration",
  "DDoS",
  "Trojan",
  "Credential Stuffing",
  "APT Chain Detected",
];

export function severityFor(type: string): Severity {
  if (["Ransomware", "APT Chain Detected", "Data Exfiltration", "C2 Traffic"].includes(type))
    return "CRITICAL";
  if (["Brute Force SSH", "DDoS", "Trojan"].includes(type)) return "HIGH";
  if (["Malware Signature", "Credential Stuffing"].includes(type)) return "MEDIUM";
  return "LOW";
}

export function timeLabel(d: Date) {
  return d.toTimeString().slice(0, 8);
}
