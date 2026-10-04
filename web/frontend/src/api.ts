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
