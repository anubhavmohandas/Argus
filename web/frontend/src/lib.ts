import type { Severity } from "./types";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export const SEV_ORDER: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export const SEV_COLOR: Record<Severity, string> = {
  critical: "#ff4d6d",
  high: "#ff8a4c",
  medium: "#ffd43b",
  low: "#4cc9f0",
  info: "#6b7280",
};

// Color per node type for the entity graph.
const TYPE_COLORS: Record<string, string> = {
  domain: "#5eead4",
  subdomain: "#38bdf8",
  ip: "#f472b6",
  username: "#a78bfa",
  email: "#fbbf24",
  phone: "#34d399",
};
export function typeColor(t: string): string {
  return TYPE_COLORS[t] ?? "#8a93a6";
}

export function sevRank(s: Severity): number {
  return SEV_ORDER[s] ?? 0;
}
