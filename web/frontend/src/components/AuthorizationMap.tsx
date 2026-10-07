import { useEffect, useMemo, useState } from "react";
import type {
  CampaignSummary,
  Coverage,
  Matrix,
  MatrixCell,
  MatrixEndpointRow,
  MatrixIdentityCol,
  ResearchGap,
} from "../types";
import { getCoverage, getMatrix, listCampaigns } from "../api";

// SURFACE → Authorization Map. A deterministic read model over captured traffic:
// which identities have been OBSERVED using each normalized endpoint, and which have
// NOT. A missing cell is an unexplored research opportunity (○), NEVER denied or
// vulnerable — absence of traffic is never a security conclusion. Same graphite/aqua
// DNA as the Endpoints surface; the matrix is a projection, the traffic store is truth.

type CovFilter = "all" | "gaps" | "single" | "multi" | "anon";

const COV_LABEL: Record<CovFilter, string> = {
  all: "all endpoints",
  gaps: "gaps only",
  single: "single-identity observed",
  multi: "multi-identity observed",
  anon: "anonymous-only",
};

const cellKey = (ep: string, id: string) => `${ep}\u0000${id}`;

export default function AuthorizationMap() {
  const [campaigns, setCampaigns] = useState<CampaignSummary[]>([]);
  const [cid, setCid] = useState<string | null>(null);
  const [matrix, setMatrix] = useState<Matrix | null>(null);
  const [coverage, setCoverage] = useState<Coverage | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [q, setQ] = useState("");
  const [method, setMethod] = useState("");
  const [cov, setCov] = useState<CovFilter>("all");
  const [sel, setSel] = useState<Inspect | null>(null);

  useEffect(() => {
    listCampaigns().then((r) => setCampaigns(r.campaigns)).catch((e) => setError(String(e)));
  }, []);

  useEffect(() => {
    setMatrix(null);
    setCoverage(null);
    setSel(null);
    setError(null);
    if (!cid) return;
    getMatrix(cid).then(setMatrix).catch((e) => setError(String(e)));
    getCoverage(cid).then(setCoverage).catch((e) => setError(String(e)));
  }, [cid]);

  // observed-cell lookup — only observed cells are sent; a miss is unobserved (○).
  const cellIndex = useMemo(() => {
    const m = new Map<string, MatrixCell>();
    for (const c of matrix?.cells ?? []) m.set(cellKey(c.endpoint_id, c.identity), c);
    return m;
  }, [matrix]);

  const methods = useMemo(
    () => Array.from(new Set((matrix?.endpoints ?? []).map((e) => e.method))).sort(),
    [matrix]
  );

  const rows = useMemo(() => {
    let r = matrix?.endpoints ?? [];
    const needle = q.trim().toLowerCase();
    if (needle) r = r.filter((e) => `${e.host}${e.path_template}`.toLowerCase().includes(needle));
    if (method) r = r.filter((e) => e.method === method);
    if (cov === "gaps") {
      const gapEps = new Set((matrix?.gaps ?? []).map((g) => g.endpoint_id));
      r = r.filter((e) => gapEps.has(e.id));
    } else if (cov === "single") r = r.filter((e) => e.identities_observed.length === 1);
    else if (cov === "multi") r = r.filter((e) => e.identities_observed.length >= 2);
    else if (cov === "anon") r = r.filter((e) => e.anonymous_observed && !e.authenticated_observed);
    return r;
  }, [matrix, q, method, cov]);

  const cols = matrix?.identities ?? [];

  return (
    <div className="flex gap-4">
      <div className="flex-1 flex flex-col gap-4 min-w-0">
        <div className="flex items-center gap-3 flex-wrap">
          <div className="text-xs font-mono tracking-wide text-mute uppercase">Surface · Authorization Map</div>
          <select
            value={cid ?? ""}
            onChange={(e) => setCid(e.target.value || null)}
            className="bg-panel2 border border-edge rounded px-2 py-1 text-xs font-mono text-ink outline-none focus:border-accent/60"
          >
            <option value="">select a campaign…</option>
            {campaigns.map((c) => (
              <option key={c.id} value={c.id}>{c.id}</option>
            ))}
          </select>
        </div>

        {error && (
          <div className="text-xs font-mono text-critical bg-critical/10 border border-critical/30 rounded px-3 py-2">
            {error}
          </div>
        )}

        {matrix && <CoverageBar m={matrix} />}

        {!cid ? (
          <Empty text="pick a campaign to see its identity × endpoint coverage." />
        ) : matrix && matrix.endpoints.length === 0 ? (
          <Empty text="no observed traffic yet — import a HAR export or paste a request on the Endpoints surface." />
        ) : matrix && cols.length === 0 ? (
          <Empty text="traffic is captured but no identity columns resolved — tag captures with an identity to compare coverage." />
        ) : matrix ? (
          <>
            <div className="flex items-center gap-2 flex-wrap text-xs font-mono">
              <input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="filter host / path…"
                className="bg-panel2 border border-edge rounded px-2 py-1 text-ink placeholder:text-mute/50 outline-none focus:border-accent/60 w-56"
              />
              <select value={method} onChange={(e) => setMethod(e.target.value)}
                className="bg-panel2 border border-edge rounded px-2 py-1 text-ink outline-none focus:border-accent/60">
                <option value="">any method</option>
                {methods.map((m) => <option key={m} value={m}>{m}</option>)}
              </select>
              <select value={cov} onChange={(e) => setCov(e.target.value as CovFilter)}
                className="bg-panel2 border border-edge rounded px-2 py-1 text-ink outline-none focus:border-accent/60">
                {(Object.keys(COV_LABEL) as CovFilter[]).map((k) => (
                  <option key={k} value={k}>{COV_LABEL[k]}</option>
                ))}
              </select>
              <span className="text-mute/70">{rows.length} / {matrix.endpoints.length} endpoints</span>
              <span className="ml-auto flex items-center gap-3 text-mute/70">
                <Legend sym="●" cls="text-accent" label="observed" />
                <Legend sym="○" cls="text-mute/50" label="unobserved" />
              </span>
            </div>

            <Grid
              rows={rows}
              cols={cols}
              cellIndex={cellIndex}
              onCell={(ep, col) => {
                const c = cellIndex.get(cellKey(ep.id, col.name)) ?? null;
                setSel({ kind: "cell", ep, col, cell: c });
              }}
              onEndpoint={(ep) => setSel({ kind: "endpoint", ep })}
              onIdentity={(col) => setSel({ kind: "identity", col })}
              selected={sel}
            />
            {coverage && <GapsPanel coverage={coverage} />}
          </>
        ) : (
          <Empty text="loading matrix…" />
        )}
      </div>

      {sel && matrix && (
        <Inspector sel={sel} matrix={matrix} cellIndex={cellIndex} onClose={() => setSel(null)} />
      )}
    </div>
  );
}

function CoverageBar({ m }: { m: Matrix }) {
  const s = m.summary;
  const stat = (label: string, value: string | number) => (
    <div className="flex flex-col">
      <span className="text-ink text-sm">{value}</span>
      <span className="text-mute/70 text-[10px] uppercase tracking-wide">{label}</span>
    </div>
  );
  return (
    <div className="bg-panel border border-edge rounded-lg px-4 py-3 flex items-center gap-6 flex-wrap text-xs font-mono">
      <div className="flex flex-col">
        <span className="text-accent text-sm">{s.research_coverage_pct}%</span>
        <span className="text-mute/70 text-[10px] uppercase tracking-wide">research coverage</span>
      </div>
      {stat("endpoints", s.endpoints)}
      {stat("identities", s.identities)}
      {stat("cells observed", `${s.observed_cells} / ${s.possible_cells}`)}
      {stat("multi-identity", s.multi_identity_endpoints)}
      {stat("single-identity", s.single_identity_endpoints)}
      {stat("anon-only", s.anonymous_only_endpoints)}
      {stat("no auth traffic", s.endpoints_no_authenticated_observation)}
      {stat("open gaps", m.gaps.length)}
      <span className="text-mute/50 text-[10px] ml-auto">
        coverage = observed / ({s.coverage_denominator}) · research signal, not a security score
      </span>
    </div>
  );
}

function Grid({
  rows, cols, cellIndex, onCell, onEndpoint, onIdentity, selected,
}: {
  rows: MatrixEndpointRow[];
  cols: MatrixIdentityCol[];
  cellIndex: Map<string, MatrixCell>;
  onCell: (ep: MatrixEndpointRow, col: MatrixIdentityCol) => void;
  onEndpoint: (ep: MatrixEndpointRow) => void;
  onIdentity: (col: MatrixIdentityCol) => void;
  selected: Inspect | null;
}) {
  const selEp = selected?.kind === "endpoint" || selected?.kind === "cell" ? selected.ep?.id : null;
  const selCol = selected?.kind === "identity" || selected?.kind === "cell" ? selected.col?.name : null;
  // sticky endpoint column + a fixed-width cell per identity, horizontally scrollable.
  const template = `minmax(260px, 1fr) repeat(${cols.length}, 72px)`;
  return (
    <div className="bg-panel border border-edge rounded-lg overflow-hidden">
      <div className="overflow-auto max-h-[64vh]">
        <div className="min-w-max">
          {/* header: identities */}
          <div className="grid sticky top-0 z-20 bg-panel border-b border-edge" style={{ gridTemplateColumns: template }}>
            <div className="sticky left-0 z-30 bg-panel px-3 py-2 text-[10px] font-mono uppercase tracking-wide text-mute">
              Endpoint
            </div>
            {cols.map((col) => (
              <button
                key={col.name}
                onClick={() => onIdentity(col)}
                title={col.declared ? `${col.role || "no role"}${col.tenant ? " · " + col.tenant : ""}` : "observed-only (undeclared)"}
                className={`px-1 py-2 text-[10px] font-mono text-center truncate hover:text-accent ${
                  selCol === col.name ? "text-accent" : "text-mute"
                }`}
              >
                {col.is_anonymous ? "anon" : col.name}
              </button>
            ))}
          </div>
          {/* rows: endpoints × identity cells */}
          {rows.map((ep) => (
            <div key={ep.id} className="grid border-b border-edge/40 last:border-0 items-stretch"
              style={{ gridTemplateColumns: template }}>
              <button
                onClick={() => onEndpoint(ep)}
                className={`sticky left-0 z-10 bg-panel px-3 py-1.5 text-left text-xs font-mono flex items-center gap-2 hover:bg-panel2 ${
                  selEp === ep.id ? "bg-panel2" : ""
                }`}
              >
                <span className="text-mute w-10 shrink-0">{ep.method}</span>
                <span className="text-ink truncate">{ep.path_template}</span>
              </button>
              {cols.map((col) => {
                const c = cellIndex.get(cellKey(ep.id, col.name));
                const isSel = selEp === ep.id && selCol === col.name;
                return (
                  <button
                    key={col.name}
                    onClick={() => onCell(ep, col)}
                    title={c ? `${c.request_count} request(s) · ${c.response_status_classes.join(", ") || "—"}` : "unobserved — research opportunity"}
                    className={`flex items-center justify-center border-l border-edge/30 text-xs font-mono hover:bg-panel2 ${
                      isSel ? "bg-panel2" : ""
                    } ${c ? "text-accent" : "text-mute/40"}`}
                  >
                    {c ? "●" : "○"}
                  </button>
                );
              })}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ---- right inspector: cell / endpoint / identity ----
type Inspect =
  | { kind: "cell"; ep: MatrixEndpointRow; col: MatrixIdentityCol; cell: MatrixCell | null }
  | { kind: "endpoint"; ep: MatrixEndpointRow }
  | { kind: "identity"; col: MatrixIdentityCol };

function Inspector({
  sel, matrix, cellIndex, onClose,
}: { sel: Inspect; matrix: Matrix; cellIndex: Map<string, MatrixCell>; onClose: () => void }) {
  let title = "";
  let rows: [string, string][] = [];
  let extra: React.ReactNode = null;

  if (sel.kind === "cell") {
    const { ep, col, cell } = sel;
    title = "cell";
    rows = [
      ["endpoint", `${ep.method} ${ep.path_template}`],
      ["host", ep.host],
      ["identity", col.is_anonymous ? "anonymous" : col.name],
      ["role", col.role || "—"],
      ["observed", cell ? "yes" : "no — research opportunity"],
      ["request count", cell ? String(cell.request_count) : "0"],
      ["first seen", cell?.first_seen || "—"],
      ["last seen", cell?.last_seen || "—"],
      ["sessions", cell?.sessions.join(", ") || "—"],
      ["response classes", cell?.response_status_classes.join(", ") || "—"],
      ["parameters", [...ep.query_params, ...ep.body_params].join(", ") || "—"],
      ["sample captures", cell?.sample_capture_refs.join(", ") || "—"],
    ];
    if (!cell) {
      extra = (
        <Note text="This identity has not been observed on this endpoint. That is missing research evidence — not a denial, not a finding." />
      );
    }
  } else if (sel.kind === "endpoint") {
    const { ep } = sel;
    title = "endpoint";
    const unobserved = matrix.identities
      .filter((c) => !ep.identities_observed.includes(c.name))
      .map((c) => (c.is_anonymous ? "anon" : c.name));
    const roles = Array.from(
      new Set(matrix.identities.filter((c) => ep.identities_observed.includes(c.name) && c.role).map((c) => c.role))
    );
    rows = [
      ["method", ep.method],
      ["host", ep.host],
      ["template", ep.path_template],
      ["auth", ep.auth],
      ["observations", String(ep.obs_count)],
      ["observed by", ep.identities_observed.join(", ") || "—"],
      ["not observed by", unobserved.join(", ") || "—"],
      ["roles represented", roles.join(", ") || "—"],
      ["query params", ep.query_params.join(", ") || "—"],
      ["body params", ep.body_params.join(", ") || "—"],
      ["response classes", ep.response_classes.join(", ") || "—"],
      ["last seen", ep.last_seen],
    ];
  } else {
    const { col } = sel;
    title = "identity";
    const observedEps = matrix.endpoints
      .filter((e) => e.identities_observed.includes(col.name))
      .map((e) => `${e.method} ${e.path_template}`);
    rows = [
      ["identity", col.is_anonymous ? "anonymous" : col.name],
      ["role", col.role || "—"],
      ["tenant", col.tenant || "—"],
      ["researcher-owned", col.researcher_owned ? "yes" : "no"],
      ["declared", col.declared ? "yes" : "no (observed-only)"],
      ["endpoints observed", String(col.endpoints_observed)],
      ["first activity", col.first_seen || "—"],
      ["last activity", col.last_seen || "—"],
    ];
    extra = (
      <div className="px-4 pb-4">
        <div className="text-[10px] font-mono uppercase tracking-wide text-mute mb-2">
          observed endpoints ({observedEps.length})
        </div>
        <div className="flex flex-col gap-1">
          {observedEps.map((e) => (
            <div key={e} className="text-[11px] font-mono text-ink truncate">{e}</div>
          ))}
          {observedEps.length === 0 && <div className="text-xs font-mono text-mute">none observed yet.</div>}
        </div>
      </div>
    );
  }

  // void unused param lint — cellIndex reserved for future per-cell evidence expansion
  void cellIndex;

  return (
    <aside className="shrink-0 w-96 border border-edge rounded-lg bg-panel overflow-auto max-h-[78vh]">
      <div className="flex items-center justify-between px-4 h-10 border-b border-edge sticky top-0 bg-panel">
        <span className="text-xs font-mono uppercase tracking-wide text-mute">Inspector · {title}</span>
        <button onClick={onClose} className="text-xs font-mono text-mute hover:text-ink">close</button>
      </div>
      <dl className="p-4 flex flex-col gap-2">
        {rows.map(([k, v]) => (
          <div key={k} className="grid grid-cols-[112px_1fr] gap-2 text-xs font-mono">
            <dt className="text-mute">{k}</dt>
            <dd className="text-ink break-words">{v}</dd>
          </div>
        ))}
      </dl>
      {extra}
    </aside>
  );
}

// Research gaps are MISSING EVIDENCE, never findings — the panel says so and shows the
// policy verdict a test would get, but queues nothing (Phase 5 adds the orchestrated run).
function GapsPanel({ coverage }: { coverage: Coverage }) {
  const live = coverage.gaps.filter((g) => !g.orphan);
  return (
    <div className="bg-panel border border-edge rounded-lg">
      <div className="flex items-center gap-3 px-3 py-2 border-b border-edge">
        <span className="text-[10px] font-mono uppercase tracking-wide text-mute">Research gaps</span>
        <span className="text-xs font-mono text-mute/70">
          {coverage.summary.open_gaps} open · owner→non-owner {coverage.summary.owner_nonowner_untested}
        </span>
        <span className="ml-auto text-[10px] font-mono text-mute/50">missing research evidence — not findings</span>
      </div>
      {live.length === 0 ? (
        <div className="px-3 py-5 text-xs font-mono text-mute text-center">
          no ownership-aware gaps yet — assert researcher-controlled ownership on the Resources
          surface so ARGUS can spot untested owner → non-owner boundaries.
        </div>
      ) : (
        <div className="max-h-[36vh] overflow-auto divide-y divide-edge/40">
          {live.map((g) => <GapRow key={g.gap_id} g={g} />)}
        </div>
      )}
    </div>
  );
}

function GapRow({ g }: { g: ResearchGap }) {
  return (
    <div className="px-3 py-2 text-xs font-mono flex flex-col gap-1">
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-medium">{g.gap_type}</span>
        <span className="text-mute">·</span>
        <span className="text-ink">{g.method} {g.path_template}</span>
        <span className="ml-auto text-[10px] px-1.5 py-0.5 rounded border border-edge text-mute uppercase">{g.status}</span>
      </div>
      <div className="text-mute">
        <span className="text-accent">{g.baseline_identity}</span> (owner) → untested{" "}
        <span className="text-accent">{g.mutation_identity}</span> on {g.resource_type} {g.resource_id}
      </div>
      <div className="flex items-center gap-2 flex-wrap text-mute/80">
        {(g.boundary ?? []).map((b) => (
          <span key={b} className="text-[10px] px-1.5 py-0.5 rounded bg-panel2 border border-edge/60">{b}</span>
        ))}
        {g.policy_preview && (
          <span className="text-[10px] px-1.5 py-0.5 rounded border border-edge/60">
            policy {g.policy_preview.verdict}
          </span>
        )}
        {g.estimated_requests != null && <span className="text-[10px]">~{g.estimated_requests} requests</span>}
        {g.confidence != null && <span className="text-[10px]">conf {g.confidence}</span>}
      </div>
    </div>
  );
}

function Legend({ sym, cls, label }: { sym: string; cls: string; label: string }) {
  return (
    <span className="flex items-center gap-1">
      <span className={cls}>{sym}</span>
      <span>{label}</span>
    </span>
  );
}

function Note({ text }: { text: string }) {
  return (
    <div className="mx-4 mb-4 text-[11px] font-mono text-mute bg-panel2 border border-edge rounded px-3 py-2">
      {text}
    </div>
  );
}

function Empty({ text }: { text: string }) {
  return (
    <div className="bg-panel border border-edge rounded-lg px-3 py-6 text-xs font-mono text-mute text-center">
      {text}
    </div>
  );
}
