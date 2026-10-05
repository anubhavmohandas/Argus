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

// ---- campaign control plane (the orchestrator read/write model) ----
// Mirrors the server read model (web/server.py _campaign_detail) and the durable
// Task/Approval records (argus/orchestrator.py). The UI never invents a task state —
// these are exactly the orchestrator's closed vocabularies.
export type TaskState =
  | "CREATED" | "POLICY_CHECKED" | "DENIED" | "APPROVAL_REQUIRED"
  | "QUEUED" | "RUNNING" | "RETRY_SCHEDULED" | "INTERRUPTED"
  | "COMPLETED" | "FAILED" | "EVALUATED" | "PAUSED" | "CANCELLED";

export interface Task {
  id: string;
  technique: string;
  host: string;
  hypothesis: string;
  state: TaskState;
  verdict: string;
  verdict_reason: string;
  experiment_id: string;
  attempts: number;
  created_at: string;
  updated_at: string;
  [k: string]: unknown;
}
export interface Approval {
  id: string;
  task_id: string;
  reason: string;
  policy_reason: string;
  decision: string; // "" = pending | APPROVE_ONCE | DENY | CANCEL
  requested_at: string;
  resolved_at: string;
  resolved_by: string;
  note: string;
}
// The orchestrator's work-unit snapshot (argus/orchestrator.py progress()). `percentage`
// is VERIFIED work (completed/planned), never time-based; `state` drives the UI heartbeat.
export interface Progress {
  campaign_id: string;
  source: string;
  state: "RUNNING" | "WAITING" | "BLOCKED" | "COMPLETE" | "IDLE";
  planned: number;
  completed: number;
  running: number;
  queued: number;
  blocked: number;
  approval_required: number;
  denied: number;
  failed: number;
  cancelled: number;
  queue_depth: number;
  percentage: number;
  current_task: string;
  current_technique: string;
  last_completed: string;
}
export interface CampaignSummary {
  id: string;
  created_at: string;
  progress: Progress;
}
export interface CampaignIdentity {
  name: string;
  role: string;
  researcher_owned: boolean;
  tenant?: string;
  has_credential: boolean;
}
export interface CampaignDetail {
  id: string;
  created_at: string;
  program_text: string;
  policy: Policy;
  progress: Progress;
  experiments: Record<string, unknown>[];
  observations: Record<string, unknown>[];
  findings: Record<string, unknown>[];
  tasks: Task[];
  approvals: Approval[];
  identities: CampaignIdentity[];
  audit: Record<string, unknown>[];
}
// One structured SSE event (web/server.py _structured_events). `event` is the typed
// name; `data` carries the audit record plus its `seq` for ?since= resume.
export interface CampaignEvent {
  event: string;
  data: Record<string, unknown> & { seq?: number };
}

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
