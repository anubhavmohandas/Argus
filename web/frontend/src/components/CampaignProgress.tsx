import type { Progress } from "../types";

// CAMPAIGN PROGRESS — the durable, factual work-unit bar.
//
// The percentage is completed/planned work units (from the orchestrator snapshot);
// it NEVER moves on elapsed time. While state === RUNNING an energy pulse travels
// through the completed section so the operator sees "still working" even when the
// bar sits at the same percentage for minutes — the width does not change, only the
// sheen. That distinction is mandatory (see the spec).

const STATE_LABEL: Record<Progress["state"], string> = {
  RUNNING: "Active Mapping",
  WAITING: "Queued",
  BLOCKED: "Blocked — approvals or failed deps",
  COMPLETE: "Complete",
  IDLE: "Idle",
};

const STATE_DOT: Record<Progress["state"], string> = {
  RUNNING: "bg-accent pulse-dot",
  WAITING: "bg-low",
  BLOCKED: "bg-medium",
  COMPLETE: "bg-accent",
  IDLE: "bg-mute",
};

export default function CampaignProgress({ p }: { p: Progress }) {
  const pct = Math.max(0, Math.min(100, p.percentage));
  const running = p.state === "RUNNING";
  return (
    <div className="bg-panel border border-edge rounded-lg p-4">
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs font-mono tracking-wide text-mute uppercase">Campaign Progress</div>
        <div className="flex items-center gap-2 text-xs font-mono">
          <span className={`inline-block w-2 h-2 rounded-full ${STATE_DOT[p.state]}`} />
          <span className="text-ink">{STATE_LABEL[p.state]}</span>
        </div>
      </div>

      <div className="relative h-3 rounded bg-panel2 overflow-hidden border border-edge/60">
        <div
          className="absolute inset-y-0 left-0 bg-accent/80 transition-[width] duration-500"
          style={{ width: `${pct}%` }}
        >
          {running && pct > 0 && <div className="energy-sweep" />}
        </div>
      </div>

      <div className="flex items-center justify-between mt-3 text-xs font-mono">
        <span className="text-ink">
          {p.completed} / {p.planned} work units complete
        </span>
        <span className="text-accent">{pct}%</span>
      </div>

      {p.current_technique && running && (
        <div className="mt-2 text-xs font-mono text-mute">
          Currently <span className="text-ink">{p.current_technique}</span>
          {p.current_task && <span className="text-mute/70"> · {p.current_task}</span>}
        </div>
      )}

      <div className="mt-3 grid grid-cols-4 gap-2 text-center">
        {([
          ["queued", p.queued, "text-low"],
          ["approvals", p.approval_required, "text-medium"],
          ["denied", p.denied, "text-mute"],
          ["failed", p.failed, p.failed ? "text-critical" : "text-mute"],
        ] as const).map(([label, n, cls]) => (
          <div key={label} className="bg-panel2 border border-edge rounded px-2 py-1.5">
            <div className={`text-sm font-mono ${cls}`}>{n}</div>
            <div className="text-[10px] uppercase tracking-wide text-mute">{label}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
