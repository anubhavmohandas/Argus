import { useState } from "react";
import type { BoundaryCard, Intel } from "../types";

// Command Center research-intelligence block: the deterministic coverage counts and the
// single highest-value unexplored boundary from argus/priority.py intel(). This is REAL
// derived research state, not an AI suggestion — it renders exactly what the engine ranked
// and never computes anything itself. Restrained on purpose: two columns, no card sprawl.

function Row({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="flex items-baseline justify-between gap-3">
      <span className="text-mute">{label}</span>
      <span className="text-ink tabular-nums">{value}</span>
    </div>
  );
}

export default function ResearchIntel({
  intel,
  onQueue,
  queueBusy,
  queueDisabled,
}: {
  intel: Intel;
  onQueue: (gapId: string) => void;
  queueBusy: string | null;          // gap_id currently queuing, or null
  queueDisabled: boolean;            // a run already owns execution
}) {
  const c = intel.research_coverage;
  const top = intel.highest_value_boundary;
  const wf = intel.workflow;
  return (
    <div className="flex flex-col gap-3">
    {wf && <WorkflowStrip wf={wf} />}
    <div className="bg-panel border border-edge rounded-lg p-3 grid gap-4 md:grid-cols-2">
      <div>
        <div className="text-[10px] font-mono uppercase tracking-widest text-mute/70 mb-2">
          Research coverage
        </div>
        <div className="flex flex-col gap-1 text-xs font-mono">
          <Row label="Endpoints" value={c.endpoints} />
          <Row label="Identities" value={c.identities} />
          <Row label="Resources" value={c.resources_known} />
          <Row label="Ownership confirmed" value={c.ownership_confirmed} />
          <Row label="Open boundaries" value={c.open_boundary_gaps} />
          <Row label="Coverage" value={`${c.research_coverage_pct}%`} />
        </div>
        <div className="mt-2 text-[10px] font-mono text-mute/60">{c.note}</div>
      </div>

      <div>
        <div className="text-[10px] font-mono uppercase tracking-widest text-mute/70 mb-2">
          Highest-value unexplored boundary
        </div>
        {top ? (
          <BoundaryBlock
            card={top}
            onQueue={onQueue}
            queuing={queueBusy === top.gap_id}
            queueDisabled={queueDisabled}
          />
        ) : (
          <div className="text-xs font-mono text-mute">
            no open boundaries — every derivable gap is tested or resolved.
          </div>
        )}
      </div>
    </div>
    </div>
  );
}

function WorkflowStrip({ wf }: { wf: NonNullable<Intel["workflow"]> }) {
  const cells: { label: string; value: number }[] = [
    { label: "open gaps", value: wf.open_research_gaps },
    { label: "awaiting approval", value: wf.experiments_awaiting_approval },
    { label: "suspicious obs", value: wf.suspicious_observations },
    { label: "need reproduction", value: wf.candidates_needing_reproduction },
    { label: "reproduced", value: wf.reproduced_findings },
    { label: "impact confirmed", value: wf.impact_confirmed_findings },
    { label: "duplicate clusters", value: wf.likely_duplicate_clusters },
    { label: "reports ready", value: wf.reports_ready },
    { label: "reports blocked", value: wf.reports_blocked },
  ];
  return (
    <div className="bg-panel border border-edge rounded-lg p-3">
      <div className="text-[10px] font-mono uppercase tracking-widest text-mute/70 mb-2">
        Where your attention is valuable
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
        {cells.map((c) => (
          <div key={c.label} className="flex flex-col">
            <span className={`text-lg font-mono tabular-nums ${c.value > 0 ? "text-accent" : "text-mute/50"}`}>
              {c.value}
            </span>
            <span className="text-[10px] font-mono text-mute">{c.label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function BoundaryBlock({
  card,
  onQueue,
  queuing,
  queueDisabled,
}: {
  card: BoundaryCard;
  onQueue: (gapId: string) => void;
  queuing: boolean;
  queueDisabled: boolean;
}) {
  const [open, setOpen] = useState(false);
  const verdict = card.policy_preview?.verdict ?? "—";
  return (
    <div className="flex flex-col gap-1.5 text-xs font-mono">
      <div className="text-accent break-all">{card.endpoint || card.gap_id}</div>
      {card.reason && <div className="text-mute">{card.reason}</div>}
      {(card.baseline_identity || card.mutation_identity) && (
        <div className="text-mute">
          <span className="text-ink">{card.baseline_identity || "—"}</span>
          {card.resource_type ? ` → ${card.resource_type} ${card.resource_id ?? ""}` : " → baseline"}
          <br />
          <span className="text-ink">{card.mutation_identity || "—"}</span>
          {" → same controlled object"}
        </div>
      )}
      <div className="flex gap-4 text-mute">
        <span>req <span className="text-ink tabular-nums">{card.estimated_requests ?? "—"}</span></span>
        <span>policy <span className="text-ink">{verdict}</span></span>
        {card.priority_score != null && (
          <span>priority <span className="text-ink tabular-nums">{card.priority_score}</span></span>
        )}
      </div>

      {open && card.priority_factors && (
        <div className="mt-1 border-t border-edge/50 pt-1 grid grid-cols-2 gap-x-4 gap-y-0.5 text-[11px]">
          {Object.entries(card.priority_factors).map(([k, v]) => (
            <div key={k} className="flex justify-between">
              <span className="text-mute">{k}</span>
              <span className="text-ink tabular-nums">{v}</span>
            </div>
          ))}
        </div>
      )}

      <div className="flex gap-1.5 mt-1">
        <button
          onClick={() => setOpen((v) => !v)}
          className="text-[11px] font-mono border border-edge text-mute rounded px-2 py-1 hover:bg-panel2"
        >
          {open ? "hide" : "inspect"}
        </button>
        <button
          onClick={() => onQueue(card.gap_id)}
          disabled={queuing || queueDisabled}
          title={queueDisabled ? "a run already owns execution — stop it first" : ""}
          className="text-[11px] font-mono border border-accent/40 text-accent rounded px-2 py-1 hover:bg-accent/15 disabled:opacity-40"
        >
          {queuing ? "queuing…" : "queue experiment"}
        </button>
      </div>
    </div>
  );
}
