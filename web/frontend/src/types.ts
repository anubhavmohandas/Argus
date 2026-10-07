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
// The coordinator's run-activity state (argus/run.py RUN_STATES) — the authority for
// "is this campaign executing", kept SEPARATE from Progress.percentage (verified work).
export type CampaignRunState =
  | "IDLE" | "STARTING" | "RUNNING" | "PAUSING" | "PAUSED"
  | "WAITING_APPROVAL" | "STOPPING" | "STOPPED" | "FAILED" | "COMPLETE";
export interface RunSnapshot {
  campaign_id: string;
  run_state: CampaignRunState;
  run_id: string;
  started_at: string;
  detail: string;
  updated_at: string;
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
// ---- observed application surface (argus/traffic.py) ----
// An Endpoint is the INTERPRETATION of captured requests to one normalized route; it
// carries parameter NAMES and references, never raw values or secrets. A CaptureRecord is
// the raw request EVIDENCE, already redacted at capture time.
export interface Endpoint {
  id: string;
  method: string;
  scheme: string;
  host: string;
  path_template: string;
  query_params: string[];
  body_params: string[];
  content_types: string[];
  identities: string[];
  session_ids: string[];
  auth: "required" | "none" | "unknown";
  response_classes: string[];
  sample_capture_ids: string[];
  obs_count: number;
  created_at: string;
  last_seen: string;
}
export interface CaptureRecord {
  id: string;
  method: string;
  host: string;
  path: string;
  url: string; // redacted
  headers: Record<string, string>; // redacted
  body_excerpt: string;
  identity: string;
  session_id: string;
  response_status: number | null;
  source: string;
  captured_at: string;
}
export interface TrafficSession {
  id: string;
  identity: string;
  base_origin: string;
  auth_mechanism: string;
  status: string;
  source: string;
  last_seen: string;
  has_credential: boolean;
}

// ---- identity x endpoint research matrix (argus/matrix.py) ----
// A deterministic projection over captured traffic. A cell is OBSERVED or absent
// (unobserved) — NEVER "denied"/"vulnerable". Absence is a research opportunity.
export interface MatrixIdentityCol {
  name: string;
  role: string;
  tenant: string;
  researcher_owned: boolean;
  declared: boolean;
  is_anonymous: boolean;
  endpoints_observed: number;
  first_seen: string;
  last_seen: string;
}
export interface MatrixEndpointRow {
  id: string;
  method: string;
  host: string;
  path_template: string;
  auth: "required" | "none" | "unknown";
  obs_count: number;
  query_params: string[];
  body_params: string[];
  response_classes: string[];
  last_seen: string;
  identities_observed: string[];
  anonymous_observed: boolean;
  authenticated_observed: boolean;
}
// Only OBSERVED cells are sent; a missing (endpoint, identity) pair renders unobserved.
export interface MatrixCell {
  endpoint_id: string;
  identity: string;
  observed: boolean;
  request_count: number;
  first_seen: string;
  last_seen: string;
  sessions: string[];
  response_status_classes: string[];
  sample_capture_refs: string[];
}
export interface MatrixSummary {
  endpoints: number;
  identities: number;
  possible_cells: number;
  observed_cells: number;
  unobserved_cells: number;
  multi_identity_endpoints: number;
  single_identity_endpoints: number;
  anonymous_only_endpoints: number;
  authenticated_only_endpoints: number;
  endpoints_no_authenticated_observation: number;
  research_coverage_pct: number;
  coverage_denominator: string;
}
export interface MatrixGap {
  endpoint_id: string;
  method: string;
  path_template: string;
  gap_type: string;
  observed_identities: string[];
  reason: string;
  status: string;
}
export interface Matrix {
  campaign_id: string;
  identities: MatrixIdentityCol[];
  endpoints: MatrixEndpointRow[];
  cells: MatrixCell[];
  summary: MatrixSummary;
  gaps: MatrixGap[];
}

// ---- resource / object knowledge (argus/resource.py) ----
// A resource row = a candidate mined from captured traffic, overlaid with an explicit
// ownership assertion when one exists. Unknown owner is a NORMAL state (ownership_status
// ""), never a warning; researcher_controlled is only ever set by an explicit assertion.
export interface ResourceRow {
  resource_type: string;
  value: string;
  fields: string[];
  sources: string[];
  confidence: string; // "" | "low" | "medium" | "high"
  endpoint_refs: string[];
  capture_refs: string[];
  observations: number;
  first_seen: string;
  last_seen: string;
  observed: boolean;
  owner_identity: string;
  tenant: string;
  researcher_controlled: boolean;
  ownership_status: string; // "" = unknown | "CONFIRMED" | "INFERRED"
  ownership_confidence: number | null;
  ownership_source: string;
  ownership_note: string;
  owner_known: boolean;
}

// ---- ownership-aware authorization coverage (argus/coverage.py) ----
// A ResearchGap is MISSING RESEARCH EVIDENCE, never a finding. It is derived
// deterministically and carries the policy verdict a test WOULD get — it never executes.
export interface GapPolicyPreview {
  verdict: string;
  reason: string;
  limits: Record<string, unknown> | null;
}
export interface ResearchGap {
  gap_id: string;
  gap_type: string;
  boundary?: string[];
  endpoint_id?: string;
  method?: string;
  host?: string;
  path_template?: string;
  baseline_identity?: string;
  mutation_identity?: string;
  resource_type?: string;
  resource_id?: string;
  ownership_context?: {
    owner: string;
    tenant: string;
    researcher_controlled: boolean;
    ownership_status: string;
  };
  evidence?: { owner_observations: number; owner_capture_refs: string[] };
  confidence?: number;
  reason?: string;
  policy_preview?: GapPolicyPreview;
  estimated_requests?: number;
  technique?: string;
  status: string; // OPEN | PROPOSED | TESTED | RESOLVED | BLOCKED | DISMISSED
  lifecycle?: Record<string, unknown>;
  orphan?: boolean;
  // priority engine (argus/priority.py) — present on ranked results; research signal,
  // never severity. priority_factors is the transparent per-factor breakdown.
  priority_score?: number;
  priority_rank?: number;
  priority_factors?: Record<string, number>;
}
export interface PriorityResult {
  campaign_id: string;
  ranked: ResearchGap[];
}
export interface Coverage {
  campaign_id: string;
  gaps: ResearchGap[];
  summary: {
    total_gaps: number;
    open_gaps: number;
    owner_nonowner_untested: number;
    by_status: Record<string, number>;
  };
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
