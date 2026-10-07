import { useCallback, useEffect, useState } from "react";
import type { CampaignSummary, ExperimentProposal } from "../types";
import { getProposals, listCampaigns, queueGap, subscribeCampaign } from "../api";

// SURFACE → Experiments. The action end of the research loop: each ranked research gap
// becomes a controlled experiment PROPOSAL. A proposal is a PLAN — the frontend never
// sends the test request. "Queue experiment" hands the plan to the EXISTING coordinator,
// which re-gates it through can_test and drives the existing differential runner; the
// observation then updates the gap (resolved / tested) and promotes any finding. Same
// graphite/aqua DNA. This is derived research state, not an AI recommendation.

export default function ExperimentsSurface() {
  const [campaigns, setCampaigns] = useState<CampaignSummary[]>([]);
  const [cid, setCid] = useState<string | null>(null);
  const [proposals, setProposals] = useState<ExperimentProposal[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [queuing, setQueuing] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);

  useEffect(() => {
    listCampaigns().then((r) => setCampaigns(r.campaigns)).catch((e) => setError(String(e)));
  }, []);

  const load = useCallback((id: string) => {
    getProposals(id).then((r) => setProposals(r.proposals)).catch((e) => setError(String(e)));
  }, []);

  useEffect(() => {
    setProposals([]);
    setError(null);
    setNote(null);
    if (cid) load(cid);
  }, [cid, load]);

  // after queuing, the coordinator runs on its own thread; refresh proposals on each campaign
  // event so a tested gap drops out of the list once the loop closes.
  useEffect(() => {
    if (!cid) return;
    const stop = subscribeCampaign(cid, () => load(cid));
    return stop;
  }, [cid, load]);

  const queue = async (p: ExperimentProposal) => {
    if (!cid) return;
    setQueuing(p.gap_id);
    setNote(null);
    try {
      const r = await queueGap(cid, p.gap_id);
      setNote(`queued through coordinator — run ${r.run.run_state.toLowerCase()}`);
      load(cid);
    } catch (e) {
      setError(String(e));
    } finally {
      setQueuing(null);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center gap-3 flex-wrap">
        <div className="text-xs font-mono tracking-wide text-mute uppercase">Surface · Experiments</div>
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
        <span className="ml-auto text-[10px] font-mono text-mute/50">
          a proposal is a plan — queuing runs it through the orchestrator, nothing here sends a request
        </span>
      </div>

      {error && (
        <div className="text-xs font-mono text-critical bg-critical/10 border border-critical/30 rounded px-3 py-2">
          {error}
        </div>
      )}
      {note && (
        <div className="text-xs font-mono text-accent bg-accent/10 border border-accent/30 rounded px-3 py-2">
          {note}
        </div>
      )}

      {!cid ? (
        <Empty text="pick a campaign to see the controlled experiments ARGUS proposes from its research gaps." />
      ) : proposals.length === 0 ? (
        <Empty text="no proposals — assert researcher-controlled ownership on the Resources surface so ARGUS can spot untested owner → non-owner boundaries." />
      ) : (
        <div className="flex flex-col gap-3">
          {proposals.map((p) => (
            <ProposalCard key={p.proposal_id} p={p} queuing={queuing === p.gap_id} onQueue={() => queue(p)} />
          ))}
        </div>
      )}
    </div>
  );
}

function ProposalCard({ p, queuing, onQueue }: { p: ExperimentProposal; queuing: boolean; onQueue: () => void }) {
  const safe = p.policy_decision_preview?.verdict?.startsWith("ALLOW");
  const rows: [string, string][] = [
    ["baseline", `${p.baseline_identity} → owns ${p.target_resource}`],
    ["mutation", `${p.mutation_identity} → ${p.baseline_identity}-owned ${p.target_resource}`],
    ["expected secure behavior", p.expected_secure_behavior],
    ["policy", `${p.policy_decision_preview?.verdict ?? "—"}`],
    ["estimated requests", String(p.request_count)],
    ["risk", p.risk],
  ];
  return (
    <div className="bg-panel border border-edge rounded-lg p-4 flex flex-col gap-3">
      <div className="flex items-center gap-2 flex-wrap text-xs font-mono">
        {p.priority_rank != null && <span className="text-accent">#{p.priority_rank}</span>}
        <span className="text-medium">Suggested controlled experiment</span>
        <span className="text-mute">·</span>
        <span className="text-ink">{p.endpoint}</span>
        <span className="ml-auto flex items-center gap-1.5 flex-wrap">
          {p.security_boundary.map((b) => (
            <span key={b} className="text-[10px] px-1.5 py-0.5 rounded bg-panel2 border border-edge/60 text-mute">{b}</span>
          ))}
        </span>
      </div>
      <div className="text-xs font-mono text-mute">{p.hypothesis}</div>
      <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1">
        {rows.map(([k, v]) => (
          <div key={k} className="grid grid-cols-[150px_1fr] gap-2 text-xs font-mono">
            <dt className="text-mute">{k}</dt>
            <dd className="text-ink break-words">{v}</dd>
          </div>
        ))}
      </dl>
      <div className="flex items-center gap-3">
        <button
          onClick={onQueue}
          disabled={queuing}
          className={`text-xs font-mono border rounded px-3 py-1.5 disabled:opacity-40 ${
            safe ? "bg-accent/15 text-accent border-accent/40 hover:bg-accent/25"
                 : "bg-medium/10 text-medium border-medium/40 hover:bg-medium/20"
          }`}
        >
          {queuing ? "queuing…" : "Queue experiment"}
        </button>
        {!safe && (
          <span className="text-[10px] font-mono text-mute">
            needs human approval — it will park for authorization in the campaign workstation
          </span>
        )}
      </div>
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
