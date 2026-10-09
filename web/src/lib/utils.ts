import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function uid(prefix = "id"): string {
  return `${prefix}_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 9)}`;
}

export function riskLevelFromScore(score: number): "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" {
  if (score <= 20) return "LOW";
  if (score <= 50) return "MEDIUM";
  if (score <= 80) return "HIGH";
  return "CRITICAL";
}

export function decisionFromScore(score: number): "ALLOW" | "HOLD" | "QUARANTINE" | "BLOCK" {
  if (score <= 20) return "ALLOW";
  if (score <= 50) return "HOLD";
  if (score <= 80) return "QUARANTINE";
  return "BLOCK";
}
