import { useState } from "react";
import type { ReactNode } from "react";
import type { Assessment, BoundaryCard, Completion, StopReason } from "../types";

// The planner's brain, in the workstation: the single highest-value SAFE next research action
// and WHY — or, when nothing safe is worth running, the HONEST stop reason (never "secure").
// This renders argus/planner.assess()+completion() verbatim via GET /api/campaign/{id}/plan;
// it decides nothing itself. The queue button reuses the one coordinator-owned execution path.

// Honest, operator-facing text for each closed stop reason. None of these is a security verdict:
// absence of a next test means ARGUS has run out of KNOWLEDGE to act on, not that the app is safe.
const STOP_TEXT: Record<Exclude<StopReason, "">, string> = {
  no_open_gaps:
    "No unexplored boundary is derivable from current knowledge. Capture more traffic or register another controlled identity to reopen research.",
  all_remaining_need_approval:
    "Open boundaries remain, but every one needs your approval before it can run.",
  all_remaining_denied:
    "Open boundaries remain, but the frozen engagement policy denies every one.",
  below_useful_threshold:
    "Safe boundaries remain, but none clears the useful-work bar — only low-information retests are left.",
  budget_exhausted:
    "The remaining request budget can't afford the cheapest safe experiment.",
};

export default function NextAction({
  assessment,
  completion,
  onQueue,
  queueBusy,
  queueDisabled,
  onStartAutonomous,
  autonomousStarting,
  running,
  activity,
}: {
  assessment: Assessment;
  completion: Completion;
  onQueue: (gapId: string) => void;
  queueBusy: string | null; // gap_id currently queuing, or null
  queueDisabled: boolean; // a run already owns execution
  onStartAutonomous: () => void;
  autonomousStarting: boolean;
  running: boolean; // a run (possibly this autonomous loop) owns execution
  activity: { endpoint: string; reason: string } | null; // live planner.selected, if running
}) {
  const na = assessment.next_action;
  const exhausted = completion.status === "RESEARCH_EXHAUSTED";
  return (
    <div
      className={`bg-panel border rounded-lg p-3 ${
        exhausted && !running ? "border-edge" : "border-accent/40"
      }`}
    >
      <div className="flex items-center justify-between mb-2">
        <div
          className={`text-[10px] font-mono uppercase tracking-widest ${
            exhausted && !running ? "text-mute/70" : "text-accent"
          }`}
        >
          {running
            ? "Autonomous research running"
            : exhausted
              ? "Research exhausted under current knowledge"
              : "Best next research action"}
        </div>
        <CountsChip a={assessment} />
      </div>

      {running && <ActivityStrip activity={activity} />}

      {na ? (
        <ActionBlock
          gap={na.gap}
          hypothesis={na.proposal.hypothesis}
          requests={na.proposal.request_count}
          onQueue={onQueue}
          queuing={queueBusy === na.gap.gap_id}
          queueDisabled={queueDisabled}
          onStartAutonomous={onStartAutonomous}
          autonomousStarting={autonomousStarting}
          running={running}
        />
      ) : (
        <StoppedBlock
          reason={completion.why_stopped}
          parked={assessment.parked_for_approval}
          onQueue={onQueue}
          queueBusy={queueBusy}
          queueDisabled={queueDisabled}
        />
      )}

      <CompletionFooter completion={completion} />
    </div>
  );
}

function ActivityStrip({ activity }: { activity: { endpoint: string; reason: string } | null }) {
  return (
    <div className="mb-2 flex items-start gap-2 text-xs font-mono bg-accent/5 border border-accent/20 rounded px-2 py-1.5">
      <span className="text-accent animate-pulse mt-0.5" aria-hidden>
        ●
      </span>
      <div className="min-w-0">
        {activity ? (
          <>
            <div className="text-ink break-all">testing {activity.endpoint}</div>
            {activity.reason && <div className="text-mute truncate">{activity.reason}</div>}
          </>
        ) : (
          <div className="text-mute">assessing the next safe experiment…</div>
        )}
        <div className="text-mute/60 text-[10px]">control from the execution rail ↓</div>
      </div>
    </div>
  );
}

function CountsChip({ a }: { a: Assessment }) {
  const c = a.counts;
  return (
    <div className="flex gap-3 text-[10px] font-mono text-mute">
      <span>open <span className="text-ink tabular-nums">{c.open_gaps}</span></span>
      <span>safe <span className="text-accent tabular-nums">{c.safe_runnable}</span></span>
      <span>approval <span className="text-medium tabular-nums">{c.need_approval}</span></span>
      <span>denied <span className="text-ink tabular-nums">{c.denied}</span></span>
    </div>
  );
}

function ActionBlock({
  gap,
  hypothesis,
  requests,
  onQueue,
  queuing,
  queueDisabled,
  onStartAutonomous,
  autonomousStarting,
  running,
}: {
  gap: BoundaryCard;
  hypothesis: string;
  requests: number;
  onQueue: (gapId: string) => void;
  queuing: boolean;
  queueDisabled: boolean;
  onStartAutonomous: () => void;
  autonomousStarting: boolean;
  running: boolean;
}) {
  const [open, setOpen] = useState(false);
  const verdict = gap.policy_preview?.verdict ?? "—";
  return (
    <div className="flex flex-col gap-1.5 text-xs font-mono">
      <div className="text-accent text-sm break-all">{gap.endpoint || gap.gap_id}</div>

      <Field label="Boundary">
        <span className="text-ink">{(gap.boundary ?? []).join(" → ") || gap.gap_type}</span>
        {(gap.baseline_identity || gap.mutation_identity) && (
          <span className="text-mute">
            {" · "}
            {gap.baseline_identity || "—"} vs {gap.mutation_identity || "—"}
            {gap.resource_type ? ` on ${gap.resource_type} ${gap.resource_id ?? ""}` : ""}
          </span>
        )}
      </Field>

      {gap.reason && (
        <Field label="Why now">
          <span className="text-mute">{gap.reason}</span>
        </Field>
      )}
      {hypothesis && (
        <Field label="Hypothesis">
          <span className="text-mute">{hypothesis}</span>
        </Field>
      )}

      <div className="flex gap-4 text-mute mt-0.5">
        <span>cost <span className="text-ink tabular-nums">{requests}</span> req</span>
        <span title={gap.policy_preview?.reason ?? ""}>policy <span className="text-ink">{verdict}</span></span>
        {gap.priority_score != null && (
          <span>priority <span className="text-ink tabular-nums">{gap.priority_score}</span></span>
        )}
      </div>

      {open && gap.priority_factors && (
        <div className="mt-1 border-t border-edge/50 pt-1 grid grid-cols-2 gap-x-4 gap-y-0.5 text-[11px]">
          {Object.entries(gap.priority_factors).map(([k, v]) => (
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
          onClick={() => onQueue(gap.gap_id)}
          disabled={queuing || queueDisabled}
          title={queueDisabled ? "a run already owns execution — stop it first" : ""}
          className="text-[11px] font-mono border border-accent/40 text-accent rounded px-2 py-1 hover:bg-accent/15 disabled:opacity-40"
        >
          {queuing ? "queuing…" : "queue this experiment"}
        </button>
        <button
          onClick={onStartAutonomous}
          disabled={autonomousStarting || running}
          title={running ? "a run already owns execution — stop it first" : "run safe experiments until none remain"}
          className="text-[11px] font-mono border border-accent/40 text-accent rounded px-2 py-1 hover:bg-accent/15 disabled:opacity-40"
        >
          {autonomousStarting ? "starting…" : "run autonomous research"}
        </button>
      </div>
    </div>
  );
}

function StoppedBlock({
  reason,
  parked,
  onQueue,
  queueBusy,
  queueDisabled,
}: {
  reason: StopReason;
  parked: BoundaryCard[];
  onQueue: (gapId: string) => void;
  queueBusy: string | null;
  queueDisabled: boolean;
}) {
  return (
    <div className="flex flex-col gap-2 text-xs font-mono">
      <div className="text-mute">{reason ? STOP_TEXT[reason] : "No safe next action."}</div>
      {parked.length > 0 && (
        <div className="border-t border-edge/50 pt-2">
          <div className="text-[10px] font-mono uppercase tracking-widest text-medium/80 mb-1">
            Awaiting your approval · {parked.length}
          </div>
          <div className="flex flex-col gap-1">
            {parked.slice(0, 5).map((g) => (
              <div key={g.gap_id} className="flex items-center justify-between gap-2">
                <span className="text-ink truncate">{g.endpoint || g.gap_id}</span>
                <button
                  onClick={() => onQueue(g.gap_id)}
                  disabled={queueBusy === g.gap_id || queueDisabled}
                  className="text-[11px] font-mono border border-medium/40 text-medium rounded px-2 py-0.5 hover:bg-medium/10 disabled:opacity-40 shrink-0"
                >
                  {queueBusy === g.gap_id ? "queuing…" : "queue → parks for approval"}
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function CompletionFooter({ completion }: { completion: Completion }) {
  const r = completion.researched;
  const cells: { label: string; value: number; accent?: boolean }[] = [
    { label: "experiments run", value: r.experiments_run },
    { label: "secure boundaries", value: r.secure_boundaries_confirmed },
    { label: "candidates", value: r.suspicious_candidates, accent: r.suspicious_candidates > 0 },
    { label: "reports ready", value: r.reports_ready, accent: r.reports_ready > 0 },
  ];
  return (
    <div className="mt-3 border-t border-edge/50 pt-2 flex flex-wrap gap-x-5 gap-y-1 text-[10px] font-mono">
      {cells.map((c) => (
        <span key={c.label} className="text-mute">
          {c.label}{" "}
          <span className={`tabular-nums ${c.accent ? "text-accent" : "text-ink"}`}>{c.value}</span>
        </span>
      ))}
    </div>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="leading-snug">
      <span className="text-mute/70">{label}: </span>
      {children}
    </div>
  );
}
