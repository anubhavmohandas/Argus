import { useCallback, useEffect, useRef, useState } from "react";
import type {
  CampaignSummary,
  FindingReport,
  QueueStatus,
  ReportQueueRow,
} from "../types";
import { getReport, getReports, listCampaigns, subscribeCampaign } from "../api";
import { downloadText } from "../lib";

// The dedicated Reports workspace: submission preparation, not investigation.
//   REPORT QUEUE  │  REPORT (the server-rendered structured report)  │  READINESS / EVIDENCE
// Every status is the BACKEND's deterministic verdict (reportability engine + critic +
// dedupe). The frontend renders queue_status / reportability_reasons / critic verbatim and
// never decides readiness itself. A critic BLOCK visually prevents a submission-ready state,
// and there is no override that changes backend truth — the hunter improves the evidence.

const STATUS_META: Record<QueueStatus, { label: string; cls: string }> = {
  READY: { label: "READY", cls: "text-accent border-accent/50" },
  NOT_READY: { label: "NOT READY", cls: "text-medium border-medium/40" },
  BLOCKED: { label: "BLOCKED", cls: "text-critical border-critical/50" },
  DUPLICATE: { label: "DUPLICATE / RELATED", cls: "text-low border-low/40" },
  DO_NOT_REPORT: { label: "DO NOT REPORT", cls: "text-mute border-edge" },
};
// the queue buckets, in the order a hunter triages them.
const BUCKETS: { key: QueueStatus; heading: string }[] = [
  { key: "READY", heading: "Ready" },
  { key: "NOT_READY", heading: "Not ready" },
  { key: "BLOCKED", heading: "Blocked" },
  { key: "DUPLICATE", heading: "Duplicate / related" },
  { key: "DO_NOT_REPORT", heading: "Do not report" },
];

function StatusTag({ s }: { s: QueueStatus }) {
  const m = STATUS_META[s];
  return (
    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${m.cls}`}>{m.label}</span>
  );
}

export default function ReportsWorkspace() {
  const [campaigns, setCampaigns] = useState<CampaignSummary[]>([]);
  const [cid, setCid] = useState<string | null>(null);
  const [rows, setRows] = useState<ReportQueueRow[]>([]);
  const [selId, setSelId] = useState<string | null>(null);
  const [report, setReport] = useState<FindingReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const refetchTimer = useRef<number | null>(null);

  useEffect(() => {
    listCampaigns().then((r) => setCampaigns(r.campaigns)).catch((e) => setError(String(e)));
  }, []);

  const loadQueue = useCallback((id: string) => {
    getReports(id).then((r) => setRows(r.reports)).catch((e) => setError(String(e)));
  }, []);

  useEffect(() => {
    if (!cid) { setRows([]); setSelId(null); return; }
    loadQueue(cid);
    const unsub = subscribeCampaign(cid, () => {
      if (refetchTimer.current) window.clearTimeout(refetchTimer.current);
      refetchTimer.current = window.setTimeout(() => loadQueue(cid), 250);
    });
    return () => {
      unsub();
      if (refetchTimer.current) window.clearTimeout(refetchTimer.current);
    };
  }, [cid, loadQueue]);

  // the full structured report for the selected finding (reportability + critic live here too)
  useEffect(() => {
    if (!cid || !selId) { setReport(null); return; }
    getReport(cid, selId).then(setReport).catch(() => setReport(null));
  }, [cid, selId, rows]);

  const selectedRow = rows.find((r) => r.finding_id === selId) ?? null;

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center gap-3">
        <span className="text-xs font-mono uppercase tracking-wide text-mute">Reports</span>
        <select
          value={cid ?? ""}
          onChange={(e) => { setCid(e.target.value || null); setSelId(null); }}
          className="bg-panel2 border border-edge rounded px-2 py-1 text-xs font-mono text-ink outline-none focus:border-accent/60"
        >
          <option value="">select a campaign…</option>
          {campaigns.map((c) => <option key={c.id} value={c.id}>{c.id}</option>)}
        </select>
        {cid && (
          <span className="text-[11px] font-mono text-mute ml-auto">
            {rows.filter((r) => r.queue_status === "READY").length} ready ·{" "}
            {rows.filter((r) => r.queue_status === "BLOCKED").length} blocked · {rows.length} total
          </span>
        )}
      </div>

      {error && (
        <div className="text-xs font-mono text-critical bg-critical/10 border border-critical/30 rounded px-3 py-2">
          {error}
        </div>
      )}

      {!cid ? (
        <div className="text-xs font-mono text-mute px-1">
          select a campaign to prepare its reports — readiness is earned, never asserted.
        </div>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-[minmax(300px,420px)_1fr_minmax(260px,360px)] gap-3 min-h-[65vh]">
          <ReportQueue rows={rows} selId={selId} onSelect={setSelId} />
          <ReportPreview report={report} row={selectedRow} />
          <ReadinessPanel report={report} row={selectedRow} />
        </div>
      )}
    </div>
  );
}

// ── REPORT QUEUE ─────────────────────────────────────────────────────────
function ReportQueue({
  rows, selId, onSelect,
}: { rows: ReportQueueRow[]; selId: string | null; onSelect: (id: string) => void }) {
  if (rows.length === 0) {
    return (
      <div className="bg-panel border border-edge rounded-lg px-3 py-4 text-xs font-mono text-mute self-start">
        no findings with report state yet — promote and reproduce a candidate first.
      </div>
    );
  }
  return (
    <div className="bg-panel border border-edge rounded-lg overflow-hidden self-start max-h-[72vh] overflow-y-auto">
      {BUCKETS.map(({ key, heading }) => {
        const bucket = rows.filter((r) => r.queue_status === key);
        if (bucket.length === 0) return null;
        return (
          <div key={key}>
            <div className="px-3 py-1.5 bg-panel2/70 text-[10px] font-mono uppercase tracking-widest text-mute/70 sticky top-0">
              {heading} · {bucket.length}
            </div>
            {bucket.map((r) => (
              <button
                key={r.finding_id}
                onClick={() => onSelect(r.finding_id)}
                className={`w-full text-left px-3 py-2 border-b border-edge/50 hover:bg-panel2 ${
                  selId === r.finding_id ? "bg-panel2" : ""
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-mono text-ink truncate">{r.title}</span>
                  <StatusTag s={r.queue_status} />
                </div>
                <div className="mt-1 grid grid-cols-[auto_1fr] gap-x-2 gap-y-0.5 text-[10px] font-mono text-mute">
                  <span className="text-mute/60">endpoint</span>
                  <span className="text-ink truncate">{r.endpoint || "—"}</span>
                  <span className="text-mute/60">boundary</span>
                  <span className="truncate">{r.boundary_type}{r.boundary_confirmed ? "" : " (unconfirmed)"}</span>
                  <span className="text-mute/60">impact</span>
                  <span className="truncate">{r.impact.length ? `${r.impact.length} effect(s)` : "none proven"}</span>
                  <span className="text-mute/60">lifecycle</span>
                  <span className="truncate">{r.state}</span>
                  <span className="text-mute/60">critic</span>
                  <span className={r.critic_verdict === "BLOCK" ? "text-critical" : r.critic_verdict === "WARN" ? "text-medium" : "text-accent"}>
                    {r.critic_verdict}
                  </span>
                  {r.cluster_id && (<><span className="text-mute/60">cluster</span><span className="truncate">{r.cluster_id}</span></>)}
                  {r.last_verified && (<><span className="text-mute/60">verified</span><span className="truncate">{r.last_verified.slice(0, 19).replace("T", " ")}</span></>)}
                </div>
              </button>
            ))}
          </div>
        );
      })}
    </div>
  );
}

// ── REPORT (server-rendered structured report, never invented prose) ───────
function CopyBtn({ label, text }: { label: string; text: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      onClick={async () => {
        try { await navigator.clipboard.writeText(text); setDone(true); setTimeout(() => setDone(false), 1200); }
        catch { /* clipboard blocked — no-op */ }
      }}
      disabled={!text}
      className="text-[11px] font-mono border border-accent/40 text-accent rounded px-2 py-0.5 hover:bg-accent/15 disabled:opacity-40"
    >
      {done ? "copied" : label}
    </button>
  );
}

function Field({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-widest text-mute/70 mb-1">{title}</div>
      <div className="text-mute">{children}</div>
    </div>
  );
}

function ReportPreview({ report, row }: { report: FindingReport | null; row: ReportQueueRow | null }) {
  if (!report || !row) {
    return (
      <div className="bg-panel border border-edge rounded-lg px-3 py-4 text-xs font-mono text-mute">
        select a finding to see its structured report.
      </div>
    );
  }
  const r = report.report;
  const bnd = r.security_boundary as Record<string, unknown>;
  return (
    <div className="bg-panel border border-edge rounded-lg p-4 flex flex-col gap-3 text-xs font-mono max-h-[72vh] overflow-y-auto">
      {/* submission banner: a BLOCK can never read as submittable */}
      <div className={`flex items-center gap-2 px-3 py-2 rounded border ${
        r.submittable ? "border-accent/50 bg-accent/10 text-accent"
          : r.critic_verdict === "BLOCK" ? "border-critical/50 bg-critical/10 text-critical"
          : "border-medium/40 bg-medium/10 text-medium"}`}>
        <span className="font-mono">
          {r.submittable ? "SUBMISSION READY" : r.critic_verdict === "BLOCK" ? "BLOCKED — not submission ready" : "NOT READY"}
        </span>
        <span className="ml-auto flex gap-1.5">
          <CopyBtn label="copy title" text={r.title} />
          <CopyBtn label="copy repro" text={r.repro_steps.map((s, i) => `${i + 1}. ${s}`).join("\n")} />
          <CopyBtn label="copy md" text={report.markdown} />
          <button
            onClick={() => downloadText(`${row.finding_id}.md`, report.markdown)}
            className="text-[11px] font-mono border border-accent/40 text-accent rounded px-2 py-0.5 hover:bg-accent/15"
          >
            download md
          </button>
        </span>
      </div>

      <div className="text-ink text-sm">{r.title}</div>
      <div className="text-mute"><span className="text-accent">{r.host}</span> · {r.technique}</div>

      {r.summary && <Field title="Summary">{r.summary}</Field>}
      <Field title="Affected asset">
        <span className="text-ink">{row.endpoint || r.host}</span>
      </Field>
      <Field title="Security boundary">
        <span className="text-ink">{r.security_boundary["boundary_type"] as string ?? "unknown"}</span>
        {bnd["confirmed"] ? "" : " · not yet confirmed"}
      </Field>
      {r.prerequisites.length > 0 && (
        <Field title="Prerequisites"><ul className="list-disc ml-4">{r.prerequisites.map((p, i) => <li key={i}>{p}</li>)}</ul></Field>
      )}
      {r.controlled_accounts.length > 0 && (
        <Field title="Researcher-controlled identities / resources">{r.controlled_accounts.join(", ")}</Field>
      )}
      {r.repro_steps.length > 0 && (
        <Field title="Steps to reproduce"><ol className="list-decimal ml-4 space-y-0.5">{r.repro_steps.map((s, i) => <li key={i}>{s}</li>)}</ol></Field>
      )}
      {(r.expected || r.observed) && (
        <Field title="Expected vs observed">
          <div><span className="text-mute/60">expected:</span> {r.expected || "—"}</div>
          <div><span className="text-mute/60">observed:</span> {r.observed || "—"}</div>
        </Field>
      )}
      <Field title="Demonstrated impact">
        {r.demonstrated_impact.length ? (
          <>
            <ul className="list-disc ml-4">{r.demonstrated_impact.map((e, i) => <li key={i}>{e}</li>)}</ul>
            <div className="text-mute/50 mt-1 text-[10px]">
              demonstrated on researcher-controlled objects; real-user blast radius not established.
            </div>
          </>
        ) : <span className="text-mute/60">none proven — a status/size difference is not impact</span>}
      </Field>
      <Field title="Reproduction status">
        {(r.reproduction_status["reproduced"] as boolean)
          ? `reproduced (${String(r.reproduction_status["completed_trials"] ?? 0)}/${String(r.reproduction_status["requested_trials"] ?? 0)} trials)`
          : "not reproduced"}
      </Field>
      {Object.keys(r.scope_context).length > 0 && (
        <Field title="Scope context">
          asset <span className="text-ink">{String(r.scope_context["asset"] ?? "")}</span> · policy {String(r.scope_context["policy_version"] ?? "")}
        </Field>
      )}
      {r.evidence.length > 0 && (
        <Field title="Evidence">
          <div className="flex flex-col gap-2">
            {r.evidence.map((e, i) => (
              <div key={i} className="border border-edge/60 rounded p-2">
                <div className="text-ink">{e.label} · <span className="text-mute">{e.method} {e.url}</span> → {e.status}</div>
                <pre className="mt-1 text-[10px] text-mute whitespace-pre-wrap break-words">{e.body_note}</pre>
              </div>
            ))}
          </div>
        </Field>
      )}
      {Object.keys(r.root_cause).length > 0 && (
        <Field title="Root cause / duplicate relationship">
          {String(r.root_cause["relation"] ?? "—")} · {String(r.root_cause["reason_for_cluster"] ?? "")}
          {r.root_cause["cluster_id"] ? ` · cluster ${String(r.root_cause["cluster_id"])}` : ""}
        </Field>
      )}
      {r.remediation.length > 0 && (
        <Field title="Suggested remediation"><ul className="list-disc ml-4">{r.remediation.map((x, i) => <li key={i}>{x}</li>)}</ul></Field>
      )}
    </div>
  );
}

// ── READINESS / EVIDENCE ───────────────────────────────────────────────────
// The exact gates, mirrored from the backend reportability engine. A gate is satisfied unless
// the backend's reportability_reasons name it missing — the frontend reflects, never decides.
const GATES: { label: string; reason: string }[] = [
  { label: "in scope", reason: "missing: scope confirmed" },
  { label: "reproduced", reason: "missing: reproduced" },
  { label: "boundary confirmed", reason: "missing: boundary confirmed" },
  { label: "impact confirmed", reason: "missing: impact confirmed" },
  { label: "duplicate checked", reason: "missing: duplicate checked" },
];

function ReadinessPanel({ report, row }: { report: FindingReport | null; row: ReportQueueRow | null }) {
  if (!report || !row) {
    return (
      <div className="bg-panel border border-edge rounded-lg px-3 py-4 text-xs font-mono text-mute">
        readiness, missing evidence, and the critic appear here.
      </div>
    );
  }
  const r = report.report;
  const reasons = new Set(r.reportability_reasons);
  const criticPass = r.critic_verdict !== "BLOCK";
  const missing = r.reportability_reasons.filter((x) => x.startsWith("missing:")).map((x) => x.replace("missing: ", ""));
  const vcolor = (v: string) =>
    v === "REPORTABLE" || v === "PASS" ? "text-accent"
      : v === "WARN" || v === "NOT_READY" ? "text-medium" : "text-critical";

  return (
    <div className="bg-panel border border-edge rounded-lg p-3 flex flex-col gap-3 text-xs font-mono max-h-[72vh] overflow-y-auto">
      <div>
        <div className="text-[10px] uppercase tracking-widest text-mute/70 mb-1">Readiness</div>
        <div className={`text-sm ${vcolor(r.reportability)}`}>{r.reportability.replace("_", " ")}</div>
        <div className="mt-2 flex flex-col gap-0.5">
          {GATES.map((g) => {
            const ok = !reasons.has(g.reason);
            return (
              <div key={g.label} className={ok ? "text-accent" : "text-mute"}>
                [{ok ? "x" : " "}] {g.label}
              </div>
            );
          })}
          <div className={criticPass ? "text-accent" : "text-mute"}>
            [{criticPass ? "x" : " "}] critic pass
          </div>
        </div>
        {missing.length > 0 && (
          <div className="mt-2">
            <div className="text-mute/60">Missing:</div>
            <ul className="list-disc ml-4 text-medium">{missing.map((m, i) => <li key={i}>{m}</li>)}</ul>
          </div>
        )}
      </div>

      <div>
        <div className="text-[10px] uppercase tracking-widest text-mute/70 mb-1">Critic</div>
        <div className={vcolor(r.critic_verdict)}>{r.critic_verdict}</div>
        {r.critic_issues.length === 0 ? (
          <div className="text-accent mt-1">✓ no issues</div>
        ) : (
          <ul className="mt-1 flex flex-col gap-0.5">
            {r.critic_issues.map((x, i) => (
              <li key={i}>
                <span className={vcolor(x.level)}>{x.level === "BLOCK" ? "✕" : x.level === "WARN" ? "△" : "✓"} [{x.level}]</span>{" "}
                <span className="text-mute">{x.msg}</span>
              </li>
            ))}
          </ul>
        )}
        {!criticPass && (
          <div className="text-[10px] text-critical/80 mt-1">
            a BLOCK prevents submission-ready — improve the evidence, there is no override.
          </div>
        )}
      </div>

      <Field title="Lifecycle">{r.state}</Field>
      {Object.keys(r.root_cause).length > 0 && (
        <Field title="Root cause">
          {String(r.root_cause["relation"] ?? "—")}
          {r.root_cause["cluster_id"] ? ` · ${String(r.root_cause["cluster_id"])}` : ""}
        </Field>
      )}
      {Object.keys(r.scope_context).length > 0 && (
        <Field title="Policy">
          policy {String(r.scope_context["policy_version"] ?? "")} · verdict {String(r.scope_context["experiment_verdict"] ?? "")}
        </Field>
      )}
      {r.evidence_refs.length > 0 && (
        <Field title="Evidence refs">
          <div className="break-all text-mute/70">{r.evidence_refs.join(", ")}</div>
        </Field>
      )}
    </div>
  );
}
