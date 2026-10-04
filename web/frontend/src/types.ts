// Mirrors Argus's engine JSON contract. Verified against live `argus pivot --json`:
// top level is { graph: {nodes, edges, findings}, investigation: {conclusions} }.
// The scored dossier lives in investigation.conclusions — that is what the UI
// renders as "findings". This is NOT ReconVision's per-host screenshot model.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type EngagementLevel = "passive" | "active" | "active-plus" | "full";

// ---- raw engine shapes ----
export interface RawNode {
  type: string;
  value: string;
  depth: number;
  via: string;
  evidence: Record<string, unknown>;
  observed: unknown; // engine emits {} or a dict, not a bare bool
}
export interface RawEdge {
  src: string; // "type:value"
  rel: string;
  dst: string; // "type:value"
}
export interface RawFinding {
  module: string;
  target: string;
  title: string;
  severity: Severity;
  data: Record<string, unknown>;
  source: string;
}
export interface RawConclusion {
  kind: string;
  rule: string;
  name: string;
  target: string;
  target_type: string;
  confidence: number; // 0-100
  severity: Severity;
  score: number;
  ledger?: { evidence?: unknown[]; calculation?: unknown[]; final?: number };
  recommendations?: string[];
  hypotheses?: string[];
  tags?: string[];
}
export interface RawResult {
  graph?: { nodes?: RawNode[]; edges?: RawEdge[]; findings?: RawFinding[] };
  investigation?: { conclusions?: RawConclusion[] };
  // some runs may emit the bare graph — tolerate it
  nodes?: RawNode[];
  edges?: RawEdge[];
  findings?: RawFinding[];
}

// ---- normalized UI shapes (what components consume) ----
export interface GraphNode {
  key: string; // `${type}:${value}` — matches edge endpoints
  type: string;
  value: string;
  depth: number;
  via: string;
  evidence: Record<string, unknown>;
  observed: boolean;
}
export interface GraphEdge {
  src: string; // node key
  rel: string;
  dst: string; // node key
}
// A dossier finding = a scored investigation conclusion (preferred), or a raw
// module observation when no conclusions exist.
export interface Finding {
  title: string;
  severity: Severity;
  rule: string; // rule id / module
  target: string;
  confidence: number | null; // 0-100
  score: number | null;
  hypotheses: string[];
  recommendations: string[];
  evidence: unknown[];
  tags: string[];
}
export interface Dossier {
  nodes: GraphNode[];
  edges: GraphEdge[];
  findings: Finding[];
  rawFindingCount: number; // count of raw module observations (graph.findings)
}

export type RunState = "idle" | "running" | "done" | "error";

// ---- engagement policy (compiled from a pasted program page) ----
export interface PolicyAsset {
  pattern: string;
  env: string;
  tier: number | null;
  action: string; // "active" | "passive" | "none"
}
export interface Policy {
  in_scope: PolicyAsset[];
  out_of_scope: string[];
  non_network_assets: string[];
  rate_per_sec: number | null;
  max_requests: number | null;
  user_agent: string;
  request_headers: Record<string, string>;
  unfilled_headers: string[];
  forbidden: string[];
  non_reportable_labels: string[];
  suppresses: string[];
  objectives: string[];
  warnings: string[];
  scope_file: string;
}
