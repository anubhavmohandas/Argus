import { useCallback, useEffect, useRef, useState } from "react";
import type {
  CampaignFinding,
  CampaignSummary,
  FindingReport,
} from "../types";
import {
  getCampaign,
  getReport,
  getTriage,
  listCampaigns,
  recordTriage,
  reproduceFinding,
  subscribeCampaign,
  validateFinding,
} from "../api";
import type { ProgramResponse } from "../types";

// The findings workspace: finding TRUTH, not report preparation (that lives in Reports).
//   FINDINGS LIST  │  FINDING DETAILS (lifecycle + boundary + impact + root cause)  │  EVIDENCE / REPRODUCTION + REPORT READINESS
// Status language is precise and EARNED — never "VULNERABLE/CRITICAL" because one experiment
// looked suspicious. Every mutation goes through an earned server API; this only reads + commands.
// `filter` splits the nav: Candidates = investigation in progress, Validated = REPORT_READY.
export type FindingsFilter = "candidates" | "validated";

const STATUS_LABEL: Record<string, string> = {
  OBSERVED: "Needs reproduction",
  REPRODUCIBLE: "Reproduced",
  IN_SCOPE: "In scope",
  BOUNDARY_CONFIRMED: "Boundary confirmed",
  IMPACT_CONFIRMED: "Impact confirmed",
  DUPLICATE_CHECKED: "Dedupe checked",
  REPORT_READY: "Report ready",
  DISMISSED: "Dismissed",
};
const STATUS_COLOR: Record<string, string> = {
  OBSERVED: "text-medium",
  REPRODUCIBLE: "text-low",
  IN_SCOPE: "text-low",
  BOUNDARY_CONFIRMED: "text-accent",
  IMPACT_CONFIRMED: "text-accent",
  DUPLICATE_CHECKED: "text-accent",
  REPORT_READY: "text-accent",
  DISMISSED: "text-mute",
};
const LADDER = [
  "OBSERVED", "REPRODUCIBLE", "IN_SCOPE", "BOUNDARY_CONFIRMED",
  "IMPACT_CONFIRMED", "DUPLICATE_CHECKED", "REPORT_READY",
];

function statusLabel(f: CampaignFinding): string {
  if (f.state === "DUPLICATE_CHECKED") {
    const rel = (f.evidence?.DUPLICATE_CHECKED as { relation?: string })?.relation;
    if (rel === "SAME_ROOT_CAUSE" || rel === "LIKELY_RELATED") return "Likely duplicate";
  }
  return STATUS_LABEL[f.state] ?? f.state;
}

export default function FindingsWorkspace({ filter }: { filter: FindingsFilter }) {
  const [campaigns, setCampaigns] = useState<CampaignSummary[]>([]);
  const [cid, setCid] = useState<string | null>(null);
  const [findings, setFindings] = useState<CampaignFinding[]>([]);
  const [selId, setSelId] = useState<string | null>(null);
  const [report, setReport] = useState<FindingReport | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const refetchTimer = useRef<number | null>(null);

  useEffect(() => {
    listCampaigns().then((r) => setCampaigns(r.campaigns)).catch((e) => setError(String(e)));
  }, []);

  const loadFindings = useCallback((id: string) => {
    getCampaign(id)
      .then((d) => setFindings((d.findings as unknown as CampaignFinding[]) ?? []))
      .catch((e) => setError(String(e)));
  }, []);

  useEffect(() => {
    if (!cid) {
      setFindings([]); setSelId(null);
      return;
    }
    loadFindings(cid);
    const unsub = subscribeCampaign(cid, () => {
      if (refetchTimer.current) window.clearTimeout(refetchTimer.current);
      refetchTimer.current = window.setTimeout(() => loadFindings(cid), 250);
    });
    return () => {
      unsub();
      if (refetchTimer.current) window.clearTimeout(refetchTimer.current);
    };
  }, [cid, loadFindings]);

  // load the report for the selected finding (works at any state — shows readiness)
  useEffect(() => {
    if (!cid || !selId) {
      setReport(null);
      return;
    }
    getReport(cid, selId).then(setReport).catch(() => setReport(null));
  }, [cid, selId, findings]);

  const visible = filter === "validated"
    ? findings.filter((f) => f.state === "REPORT_READY")
    : findings.filter((f) => f.state !== "REPORT_READY");
  const selected = visible.find((f) => f.id === selId) ?? null;

  const onReproduce = useCallback(async () => {
    if (!cid || !selId) return;
    setBusy("reproduce"); setError(null);
    try {
      await reproduceFinding(cid, selId, 2);   // coordinator-owned; result arrives via SSE
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  }, [cid, selId]);

  const onValidate = useCallback(async () => {
    if (!cid || !selId) return;
    setBusy("validate"); setError(null);
    try {
      const res = await validateFinding(cid, selId);
      if (res.stopped_reason) setError(`stopped at ${res.reached}: ${res.stopped_reason}`);
      loadFindings(cid);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  }, [cid, selId, loadFindings]);

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center gap-3">
        <span className="text-xs font-mono uppercase tracking-wide text-mute">
          {filter === "validated" ? "Validated" : "Candidates"}
        </span>
        <select
          value={cid ?? ""}
          onChange={(e) => { setCid(e.target.value || null); setSelId(null); }}
          className="bg-panel2 border border-edge rounded px-2 py-1 text-xs font-mono text-ink outline-none focus:border-accent/60"
        >
          <option value="">select a campaign…</option>
          {campaigns.map((c) => <option key={c.id} value={c.id}>{c.id}</option>)}
        </select>
        {cid && <span className="text-[11px] font-mono text-mute ml-auto">{visible.length} shown</span>}
      </div>

      {error && (
        <div className="text-xs font-mono text-critical bg-critical/10 border border-critical/30 rounded px-3 py-2">
          {error}
        </div>
      )}

      {!cid ? (
        <div className="text-xs font-mono text-mute px-1">
          {filter === "validated"
            ? "select a campaign to see its report-ready findings — submission prep lives in Reports."
            : "select a campaign to review candidates — each advances only as the evidence earns it."}
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-[minmax(220px,300px)_1fr_minmax(260px,380px)] gap-3 min-h-[60vh]">
          <FindingsList findings={visible} selId={selId} onSelect={setSelId} />
          <FindingDetails
            f={selected}
            busy={busy}
            onReproduce={onReproduce}
            onValidate={onValidate}
          />
          <EvidencePanel f={selected} report={report} cid={cid} />
        </div>
      )}
    </div>
  );
}

function FindingsList({
  findings, selId, onSelect,
}: { findings: CampaignFinding[]; selId: string | null; onSelect: (id: string) => void }) {
  if (findings.length === 0) {
    return (
      <div className="bg-panel border border-edge rounded-lg px-3 py-4 text-xs font-mono text-mute">
        no findings yet — a suspicious differential promotes one candidate.
      </div>
    );
  }
  return (
    <div className="bg-panel border border-edge rounded-lg overflow-hidden self-start max-h-[70vh] overflow-y-auto">
      {findings.map((f) => (
        <button
          key={f.id}
          onClick={() => onSelect(f.id)}
          className={`w-full text-left px-3 py-2 border-b border-edge/50 last:border-0 hover:bg-panel2 ${
            selId === f.id ? "bg-panel2" : ""
          }`}
        >
          <div className="text-xs font-mono text-ink truncate">{f.title}</div>
          <div className="flex items-center justify-between mt-0.5">
            <span className={`text-[11px] font-mono ${STATUS_COLOR[f.state] ?? "text-mute"}`}>
              {statusLabel(f)}
            </span>
            {!f.reportable && <span className="text-[10px] font-mono text-mute">suppressed</span>}
          </div>
        </button>
      ))}
    </div>
  );
}

function Ladder({ state }: { state: string }) {
  const at = LADDER.indexOf(state);
  return (
    <div className="flex flex-wrap gap-1">
      {LADDER.map((s, i) => (
        <span
          key={s}
          className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${
            state === "DISMISSED" ? "border-edge text-mute"
              : i < at ? "border-accent/30 text-accent/70"
              : i === at ? "border-accent text-accent bg-accent/10"
              : "border-edge text-mute/50"
          }`}
        >
          {STATUS_LABEL[s]}
        </span>
      ))}
    </div>
  );
}

function FindingDetails({
  f, busy, onReproduce, onValidate,
}: {
  f: CampaignFinding | null;
  busy: string | null;
  onReproduce: () => void;
  onValidate: () => void;
}) {
  if (!f) {
    return (
      <div className="bg-panel border border-edge rounded-lg px-3 py-4 text-xs font-mono text-mute">
        select a finding.
      </div>
    );
  }
  const bnd = (f.evidence?.BOUNDARY_CONFIRMED ?? {}) as Record<string, unknown>;
  const imp = (f.evidence?.IMPACT_CONFIRMED ?? {}) as Record<string, unknown>;
  const ded = (f.evidence?.DUPLICATE_CHECKED ?? {}) as Record<string, unknown>;
  const effects = (imp.demonstrated_effects as string[]) ?? [];
  const canReproduce = f.state === "OBSERVED";
  const canValidate = LADDER.indexOf(f.state) >= LADDER.indexOf("REPRODUCIBLE")
    && f.state !== "REPORT_READY" && f.state !== "DISMISSED";
  return (
    <div className="bg-panel border border-edge rounded-lg p-3 flex flex-col gap-3 text-xs font-mono">
      <div>
        <div className="text-ink text-sm">{f.title}</div>
        <div className="text-mute mt-0.5">
          <span className="text-accent">{f.host}</span> · {f.technique}
        </div>
      </div>
      <Ladder state={f.state} />
      {!f.reportable && (
        <div className="text-medium">suppressed: {f.suppressed_reason}</div>
      )}

      <Section title="Security boundary">
        {bnd.confirmed ? (
          <div className="text-mute">
            <span className="text-ink">{String(bnd.boundary_type)}</span>
            <div>{String(bnd.rationale ?? "")}</div>
          </div>
        ) : <span className="text-mute/60">not yet confirmed</span>}
      </Section>

      <Section title="Demonstrated impact">
        {effects.length ? (
          <ul className="list-disc ml-4 text-mute">{effects.map((e, i) => <li key={i}>{e}</li>)}</ul>
        ) : <span className="text-mute/60">not yet confirmed — a status/size difference is not impact</span>}
      </Section>

      <Section title="Root cause / duplicate">
        {ded.relation ? (
          <div className="text-mute">
            {String(ded.relation)} · {String(ded.reason_for_cluster ?? "")}
            <div className="text-mute/60">{(ded.finding_ids as string[])?.length ?? 1} finding(s) in cluster</div>
          </div>
        ) : <span className="text-mute/60">not yet checked</span>}
      </Section>

      <div className="flex gap-1.5 mt-auto pt-2">
        <button
          onClick={onReproduce}
          disabled={!canReproduce || busy === "reproduce"}
          className="text-[11px] font-mono border border-accent/40 text-accent rounded px-2 py-1 hover:bg-accent/15 disabled:opacity-40"
        >
          {busy === "reproduce" ? "reproducing…" : "Reproduce"}
        </button>
        <button
          onClick={onValidate}
          disabled={!canValidate || busy === "validate"}
          className="text-[11px] font-mono border border-accent/40 text-accent rounded px-2 py-1 hover:bg-accent/15 disabled:opacity-40"
        >
          {busy === "validate" ? "validating…" : "Validate"}
        </button>
      </div>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-widest text-mute/70 mb-1">{title}</div>
      {children}
    </div>
  );
}

const OUTCOMES = ["SUBMITTED", "ACCEPTED", "DUPLICATE", "INFORMATIVE", "NOT_APPLICABLE", "NEEDS_MORE_INFO", "RESOLVED"];

function TriageControl({ cid, finding }: { cid: string; finding: CampaignFinding }) {
  const [resp, setResp] = useState<ProgramResponse | null>(null);
  const [outcome, setOutcome] = useState("SUBMITTED");
  const [reward, setReward] = useState("");
  const [notes, setNotes] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    getTriage(cid).then((r) => setResp(r.responses.find((x) => x.finding_id === finding.id) ?? null))
      .catch(() => { /* best-effort */ });
  }, [cid, finding.id]);

  const onRecord = async () => {
    setBusy(true); setErr(null);
    try {
      const r = await recordTriage(cid, finding.id, { outcome, reward, notes });
      setResp(r.triage); setReward(""); setNotes("");
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Section title="Program response (research memory)">
      {resp && resp.outcome && (
        <div className="text-mute mb-1">
          latest: <span className="text-ink">{resp.outcome}</span>
          {resp.reward ? ` · ${resp.reward}` : ""} · {resp.history.length} event(s)
        </div>
      )}
      <div className="flex flex-wrap gap-1.5 items-center">
        <select value={outcome} onChange={(e) => setOutcome(e.target.value)}
          className="bg-panel2 border border-edge rounded px-1.5 py-1 text-[11px] text-ink outline-none focus:border-accent/60">
          {OUTCOMES.map((o) => <option key={o} value={o}>{o}</option>)}
        </select>
        <input value={reward} onChange={(e) => setReward(e.target.value)} placeholder="reward"
          className="bg-panel2 border border-edge rounded px-1.5 py-1 text-[11px] text-ink w-20 outline-none focus:border-accent/60" />
        <input value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="notes"
          className="bg-panel2 border border-edge rounded px-1.5 py-1 text-[11px] text-ink flex-1 min-w-[80px] outline-none focus:border-accent/60" />
        <button onClick={onRecord} disabled={busy}
          className="text-[11px] font-mono border border-accent/40 text-accent rounded px-2 py-1 hover:bg-accent/15 disabled:opacity-40">
          {busy ? "…" : "record"}
        </button>
      </div>
      {err && <div className="text-critical mt-1">{err}</div>}
      <div className="text-mute/50 mt-1 text-[10px]">
        research memory only — ARGUS never submits or scrapes.
      </div>
    </Section>
  );
}

function EvidencePanel({ f, report, cid }: { f: CampaignFinding | null; report: FindingReport | null; cid: string }) {
  if (!f) {
    return (
      <div className="bg-panel border border-edge rounded-lg px-3 py-4 text-xs font-mono text-mute">
        evidence + reproduction appear here.
      </div>
    );
  }
  const repro = (f.evidence?.REPRODUCIBLE ?? {}) as Record<string, unknown>;
  const r = report?.report;
  const verdictColor = (v?: string) =>
    v === "REPORTABLE" || v === "PASS" ? "text-accent"
      : v === "WARN" || v === "NOT_READY" ? "text-medium"
      : "text-critical";
  return (
    <div className="bg-panel border border-edge rounded-lg p-3 flex flex-col gap-3 text-xs font-mono max-h-[70vh] overflow-y-auto">
      <Section title="Reproduction">
        {repro.reproduced ? (
          <div className="text-mute">
            reproduced {String(repro.completed_trials ?? "")} / {String(repro.requested_trials ?? "")} trials
            <div className="text-mute/60 break-all">
              trials: {((repro.trial_experiment_ids as string[]) ?? []).join(", ") || "—"}
            </div>
          </div>
        ) : <span className="text-mute/60">not reproduced yet</span>}
      </Section>

      {r && (
        <Section title="Report readiness">
          <div className="flex flex-col gap-1">
            <div>readiness: <span className={verdictColor(r.reportability)}>{r.reportability}</span></div>
            <div>critic: <span className={verdictColor(r.critic_verdict)}>{r.critic_verdict}</span></div>
            {r.reportability_reasons.length > 0 && (
              <ul className="list-disc ml-4 text-mute">
                {r.reportability_reasons.map((x, i) => <li key={i}>{x}</li>)}
              </ul>
            )}
            {r.critic_issues.length > 0 && (
              <ul className="list-disc ml-4 text-mute">
                {r.critic_issues.map((x, i) => (
                  <li key={i}><span className={verdictColor(x.level)}>[{x.level}]</span> {x.msg}</li>
                ))}
              </ul>
            )}
          </div>
        </Section>
      )}

      {r && r.evidence_refs.length > 0 && (
        <Section title="Evidence records">
          <div className="text-mute/70 break-all">{r.evidence_refs.join(", ")}</div>
        </Section>
      )}

      {f.state === "REPORT_READY" && <TriageControl cid={cid} finding={f} />}

      {r && (
        <div className="text-[10px] font-mono text-mute/60">
          full structured report + markdown export live in the Reports workspace.
        </div>
      )}
    </div>
  );
}

