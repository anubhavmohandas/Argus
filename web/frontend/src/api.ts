import type {
  Dossier,
  EngagementLevel,
  Finding,
  GraphNode,
  RawConclusion,
  RawFinding,
  RawNode,
  RawResult,
} from "./types";

export interface RunOptions {
  depth?: number;
  max?: number;
  deep?: number;
  ports?: string;
}

export interface RunCallbacks {
  onStart?: (d: { seed: string; level: string; command: string }) => void;
  onStatus?: (line: string) => void;
  onResult?: (dossier: Dossier) => void;
  onError?: (message: string) => void;
  onDone?: () => void;
}

function nodeKey(n: RawNode): string {
  return `${n.type}:${n.value}`;
}

function normNode(n: RawNode): GraphNode {
  const obs =
    typeof n.observed === "boolean"
      ? n.observed
      : !!n.observed && typeof n.observed === "object"
        ? Object.keys(n.observed as object).length > 0
        : false;
  return {
    key: nodeKey(n),
    type: n.type,
    value: n.value,
    depth: n.depth ?? 0,
    via: n.via ?? "",
    evidence: n.evidence ?? {},
    observed: obs,
  };
}

function conclusionToFinding(c: RawConclusion): Finding {
  return {
    title: c.name,
    severity: c.severity,
    rule: c.rule,
    target: c.target,
    confidence: typeof c.confidence === "number" ? c.confidence : null,
    score: typeof c.score === "number" ? c.score : null,
    hypotheses: c.hypotheses ?? [],
    recommendations: c.recommendations ?? [],
    evidence: c.ledger?.evidence ?? [],
    tags: c.tags ?? [],
  };
}

function rawFindingToFinding(f: RawFinding): Finding {
  return {
    title: f.title,
    severity: f.severity,
    rule: f.module,
    target: f.target,
    confidence: null,
    score: null,
    hypotheses: [],
    recommendations: [],
    evidence: Object.keys(f.data || {}).length ? [f.data] : [],
    tags: f.source ? [f.source] : [],
  };
}

/** Flatten the engine's {graph, investigation} (or a bare graph) into the UI Dossier. */
export function normalize(raw: RawResult): Dossier {
  const g = raw.graph ?? { nodes: raw.nodes, edges: raw.edges, findings: raw.findings };
  const nodes = (g.nodes ?? []).map(normNode);
  const edges = (g.edges ?? []).map((e) => ({ src: e.src, rel: e.rel, dst: e.dst }));
  const conclusions = raw.investigation?.conclusions ?? [];
  const rawFindings = g.findings ?? [];
  // Scored conclusions are the dossier. But some modules (secrets, github_dork)
  // yield high-severity findings directly, outside the predicate/rule path — those
  // must still surface, so merge in any non-info raw finding alongside conclusions.
  const findings: Finding[] =
    conclusions.length > 0
      ? [
          ...conclusions.map(conclusionToFinding),
          ...rawFindings
            .filter((f) => f.severity && f.severity !== "info")
            .map(rawFindingToFinding),
        ]
      : rawFindings.map(rawFindingToFinding);
  return {
    nodes,
    edges,
    findings,
    rawFindingCount: (g.findings ?? []).length,
  };
}

/**
 * Open an SSE stream to the Argus engine. Returns an abort function.
 * The server spawns `python3 -m argus pivot <seed> --json <flags>`, relays its
 * live `[argus]` status lines, then the final graph+investigation JSON.
 */
export function runPivot(
  seed: string,
  level: EngagementLevel,
  opts: RunOptions,
  cb: RunCallbacks
): () => void {
  const params = new URLSearchParams({ seed, level });
  if (opts.depth != null) params.set("depth", String(opts.depth));
  if (opts.max != null) params.set("max", String(opts.max));
  if (opts.deep != null) params.set("deep", String(opts.deep));
  if (opts.ports) params.set("ports", opts.ports);

  const es = new EventSource(`/api/stream?${params.toString()}`);

  es.addEventListener("start", (e) => {
    try {
      cb.onStart?.(JSON.parse((e as MessageEvent).data));
    } catch {
      /* ignore */
    }
  });
  es.addEventListener("status", (e) => {
    try {
      cb.onStatus?.(JSON.parse((e as MessageEvent).data).line);
    } catch {
      /* ignore */
    }
  });
  es.addEventListener("result", (e) => {
    try {
      cb.onResult?.(normalize(JSON.parse((e as MessageEvent).data) as RawResult));
    } catch {
      cb.onError?.("could not parse result");
    }
  });
  es.addEventListener("error", (e) => {
    const data = (e as MessageEvent).data;
    if (data) {
      try {
        cb.onError?.(JSON.parse(data).message);
      } catch {
        cb.onError?.("stream error");
      }
    }
  });
  es.addEventListener("done", () => {
    cb.onDone?.();
    es.close();
  });

  return () => es.close();
}

/** Compile a pasted bug-bounty program page into the engagement contract.
 * Pure parse on the server (no target traffic) — scope / out-of-scope / exclusions. */
export async function compilePolicy(text: string): Promise<import("./types").Policy> {
  const r = await fetch("/api/policy", {
    method: "POST",
    headers: { "Content-Type": "text/plain" },
    body: text,
  });
  const data = await r.json();
  if (!r.ok) throw new Error(data.error || "compile failed");
  return data as import("./types").Policy;
}

export async function health(): Promise<{
  ok: boolean;
  levels: string[];
  modules?: string[];
  utility_modules?: string[];
  github_token?: boolean;
}> {
  const r = await fetch("/api/health");
  return r.json();
}

// ---- campaign control plane (orchestrator remote control) ----
import type {
  CampaignDetail,
  CampaignEvent,
  CampaignSummary,
  RunSnapshot,
  Task,
} from "./types";

async function jsonFetch<T>(url: string, init?: RequestInit): Promise<T> {
  const r = await fetch(url, init);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error((data as { error?: string }).error || `${r.status} ${r.statusText}`);
  return data as T;
}

export function listCampaigns(): Promise<{ campaigns: CampaignSummary[] }> {
  return jsonFetch("/api/campaigns");
}

export function getCampaign(id: string): Promise<CampaignDetail> {
  return jsonFetch(`/api/campaign?id=${encodeURIComponent(id)}`);
}

export function createCampaign(programText: string, name = ""): Promise<{ id: string }> {
  return jsonFetch("/api/campaigns", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ program_text: programText, name }),
  });
}

export function registerIdentity(
  cid: string,
  ident: { name: string; role?: string; researcher_owned?: boolean; credential_ref?: string; tenant?: string }
): Promise<{ name: string }> {
  return jsonFetch(`/api/campaign/${encodeURIComponent(cid)}/identities`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(ident),
  });
}

/** Approve / deny / cancel a parked task — straight through the orchestrator, which
 * re-runs can_test on approve (a UI approval can never override a scope/forbidden DENY). */
export function decideTask(
  cid: string,
  taskId: string,
  action: "approve" | "deny" | "cancel",
  by = "web-operator",
  note = ""
): Promise<{ task: Task }> {
  return jsonFetch(
    `/api/campaign/${encodeURIComponent(cid)}/tasks/${encodeURIComponent(taskId)}/${action}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ by, note }),
    }
  );
}

/** Start a real background pivot bound to a campaign (coordinator-owned). The body
 * carries only bounded config (level + discovery budgets + ports) — it can never name a
 * provider. Returns immediately with the run snapshot; SSE carries discovery + progress. */
export function startPivot(
  cid: string,
  level: EngagementLevel,
  opts: RunOptions = {}
): Promise<{ run: RunSnapshot; seed: string; level: string }> {
  return jsonFetch(`/api/campaign/${encodeURIComponent(cid)}/pivot`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ level, ...opts }),
  });
}

/** Pause / resume / stop a campaign's run — thin controllers over the coordinator. PAUSE
 * stops NEW dispatch (a bounded task in flight finishes); STOP preserves durable queued
 * work. The operation is applied on the coordinator's single thread, never racing a run. */
export function controlRun(
  cid: string,
  action: "pause" | "resume" | "stop"
): Promise<{ run: RunSnapshot }> {
  return jsonFetch(`/api/campaign/${encodeURIComponent(cid)}/${action}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{}",
  });
}

/** Reproduce a finding's controlled differential through the same coordinator. 409s if a
 * run is already active (one execution owner) or the finding has no re-runnable differential. */
export function reproduceFinding(
  cid: string,
  findingId: string,
  trials = 2
): Promise<{ run: RunSnapshot; finding: string; trials: number }> {
  return jsonFetch(
    `/api/campaign/${encodeURIComponent(cid)}/findings/${encodeURIComponent(findingId)}/reproduce`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ trials }),
    }
  );
}

/** Subscribe to a campaign's structured event stream (replay from the durable audit
 * log, then live tail). Returns an unsubscribe function. The named events match
 * web/server.py's vocabulary; `onEvent` also receives every event generically so a
 * consumer can refresh on any change without enumerating names. */
export function subscribeCampaign(
  cid: string,
  onEvent: (ev: CampaignEvent) => void,
  since?: number
): () => void {
  const q = since != null ? `?since=${since}` : "";
  const es = new EventSource(`/api/campaign/${encodeURIComponent(cid)}/events${q}`);
  const NAMES = [
    "campaign.created", "campaign.progress",
    "task.proposed", "task.queued", "task.retry", "task.completed",
    "task.cancelled", "task.failed",
    "policy.allow", "policy.limit", "policy.deny", "policy.approval_required",
    "approval.requested", "approval.approved", "approval.denied",
    "experiment.created", "experiment.completed",
    "finding.promoted", "finding.transition", "identity.registered",
    "reproduction.checked",
    // coordinator run-state transitions — the authority for campaign activity
    "campaign.run.starting", "campaign.run.running", "campaign.run.pausing",
    "campaign.run.paused", "campaign.run.waiting_approval", "campaign.run.stopping",
    "campaign.run.stopped", "campaign.run.complete", "campaign.run.failed",
    "campaign.run.recovered",
  ];
  const handle = (name: string) => (e: Event) => {
    try {
      onEvent({ event: name, data: JSON.parse((e as MessageEvent).data) });
    } catch {
      /* ignore malformed frame */
    }
  };
  for (const n of NAMES) es.addEventListener(n, handle(n));
  return () => es.close();
}

export interface ModuleCallbacks {
  onStatus?: (line: string) => void;
  onResult?: (findings: Finding[]) => void;
  onError?: (message: string) => void;
  onDone?: () => void;
}

/** Run a single secret-recon module (`argus run <name> <target> --json`). */
export function runModule(
  name: string,
  target: string,
  cb: ModuleCallbacks
): () => void {
  const params = new URLSearchParams({ name, target });
  const es = new EventSource(`/api/module?${params.toString()}`);

  es.addEventListener("status", (e) => {
    try {
      cb.onStatus?.(JSON.parse((e as MessageEvent).data).line);
    } catch {
      /* ignore */
    }
  });
  es.addEventListener("result", (e) => {
    try {
      const raw = JSON.parse((e as MessageEvent).data).findings as RawFinding[];
      cb.onResult?.((raw ?? []).map(rawFindingToFinding));
    } catch {
      cb.onError?.("could not parse module result");
    }
  });
  es.addEventListener("error", (e) => {
    const data = (e as MessageEvent).data;
    if (data) {
      try {
        cb.onError?.(JSON.parse(data).message);
      } catch {
        cb.onError?.("stream error");
      }
    }
  });
  es.addEventListener("done", () => {
    cb.onDone?.();
    es.close();
  });

  return () => es.close();
}
