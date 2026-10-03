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

import type { Dossier } from "./types";

/** Build a Markdown bounty-style report from a dossier and trigger a download. */
export function downloadReport(dossier: Dossier, seed: string): void {
  const now = new Date().toISOString();
  const lines: string[] = [];
  lines.push(`# Argus dossier — ${seed}`, "", `_Generated ${now}_`, "");
  lines.push(
    `**Entities:** ${dossier.nodes.length} · **Edges:** ${dossier.edges.length} · **Findings:** ${dossier.findings.length}`,
    ""
  );

  const sorted = [...dossier.findings].sort(
    (a, b) => sevRank(b.severity) - sevRank(a.severity) || (b.score ?? 0) - (a.score ?? 0)
  );
  lines.push("## Findings", "");
  for (const f of sorted) {
    lines.push(`### [${f.severity.toUpperCase()}] ${f.title}`);
    const meta = [`rule: ${f.rule}`, `target: ${f.target}`];
    if (f.confidence != null) meta.push(`confidence: ${f.confidence}%`);
    if (f.score != null && f.score > 0) meta.push(`score: ${f.score}`);
    lines.push("", meta.join(" · "), "");
    for (const h of f.hypotheses) lines.push(`- **Hypothesis:** ${h}`);
    for (const r of f.recommendations) lines.push(`- **Remediation:** ${r}`);
    if (f.evidence.length) {
      lines.push("", "```json", JSON.stringify(f.evidence, null, 2), "```");
    }
    lines.push("");
  }

  lines.push("## Entity graph", "");
  for (const e of dossier.edges) lines.push(`- \`${e.src}\` —${e.rel}→ \`${e.dst}\``);

  const blob = new Blob([lines.join("\n")], { type: "text/markdown" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `argus-${seed.replace(/[^a-z0-9.-]/gi, "_")}.md`;
  a.click();
  URL.revokeObjectURL(url);
}
