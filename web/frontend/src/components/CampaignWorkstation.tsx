import { useCallback, useEffect, useRef, useState } from "react";
import type {
  CampaignDetail,
  CampaignRunState,
  CampaignSummary,
  EngagementLevel,
  Progress,
  Task,
  TaskState,
} from "../types";
import {
  createCampaign,
  decideTask,
  getCampaign,
  listCampaigns,
  startPivot,
  subscribeCampaign,
} from "../api";
import CampaignProgress from "./CampaignProgress";

const RUN_PREFIX = "campaign.run.";
const ACTIVE_RUN = new Set<CampaignRunState>([
  "STARTING", "RUNNING", "PAUSING", "PAUSED", "WAITING_APPROVAL", "STOPPING",
]);

// The campaign workstation: pick/create a campaign, watch its orchestrated work live
// (progress + dense task table + approvals), and action parked tasks. Every mutation
// goes through the write API -> the orchestrator; this component only reads and commands.

const STATE_COLOR: Record<TaskState, string> = {
  CREATED: "text-mute", POLICY_CHECKED: "text-mute",
  DENIED: "text-mute", APPROVAL_REQUIRED: "text-medium",
  QUEUED: "text-low", RUNNING: "text-accent", RETRY_SCHEDULED: "text-low",
  INTERRUPTED: "text-medium", COMPLETED: "text-accent", FAILED: "text-critical",
  EVALUATED: "text-accent", PAUSED: "text-mute", CANCELLED: "text-mute",
};

function hhmm(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "—" : d.toISOString().slice(11, 19);
}

export default function CampaignWorkstation({
  onSelectTask,
  onProgress,
  onRunState,
}: {
  onSelectTask?: (t: Task | null) => void;
  onProgress?: (cid: string, p: Progress) => void;
  onRunState?: (cid: string, run: CampaignRunState) => void;
}) {
  const [campaigns, setCampaigns] = useState<CampaignSummary[]>([]);
  const [cid, setCid] = useState<string | null>(null);
  const [detail, setDetail] = useState<CampaignDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [programText, setProgramText] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [runState, setRunState] = useState<CampaignRunState | null>(null);
  const refetchTimer = useRef<number | null>(null);

  const refreshList = useCallback(() => {
    listCampaigns()
      .then((r) => setCampaigns(r.campaigns))
      .catch((e) => setError(String(e)));
  }, []);

  useEffect(() => {
    refreshList();
  }, [refreshList]);

  const loadDetail = useCallback((id: string) => {
    getCampaign(id)
      .then((d) => {
        setDetail(d);
        onProgress?.(d.id, d.progress);   // feed the bottom execution rail
      })
      .catch((e) => setError(String(e)));
  }, [onProgress]);

  // Subscribe to the campaign's structured event stream; on any event, debounce a
  // detail refetch so the UI reflects the durable task table without a parallel reducer.
  useEffect(() => {
    if (!cid) {
      setDetail(null);
      setRunState(null);
      return;
    }
    loadDetail(cid);
    const unsub = subscribeCampaign(cid, (ev) => {
      // the coordinator's run-state transitions are the authority for activity — track
      // them directly (replayed on connect, so a fresh subscription learns current state).
      if (ev.event.startsWith(RUN_PREFIX)) {
        const suffix = ev.event.slice(RUN_PREFIX.length).toUpperCase();
        if (suffix !== "RECOVERED") {
          const rs = suffix as CampaignRunState;
          setRunState(rs);
          onRunState?.(cid, rs);
        }
      }
      if (refetchTimer.current) window.clearTimeout(refetchTimer.current);
      refetchTimer.current = window.setTimeout(() => loadDetail(cid), 250);
    });
    return () => {
      unsub();
      if (refetchTimer.current) window.clearTimeout(refetchTimer.current);
    };
  }, [cid, loadDetail, onRunState]);

  const onCreate = useCallback(async () => {
    if (!programText.trim()) return;
    setError(null);
    try {
      const { id } = await createCampaign(programText.trim());
      setCreating(false);
      setProgramText("");
      refreshList();
      setCid(id);
    } catch (e) {
      setError(String(e));
    }
  }, [programText, refreshList]);

  const [pivotLevel, setPivotLevel] = useState<EngagementLevel>("active");
  const onLaunchPivot = useCallback(async () => {
    if (!cid) return;
    setBusy("pivot");
    setError(null);
    try {
      await startPivot(cid, pivotLevel);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  }, [cid, pivotLevel]);

  const onDecide = useCallback(
    async (taskId: string, action: "approve" | "deny" | "cancel") => {
      if (!cid) return;
      setBusy(taskId + action);
      setError(null);
      try {
        await decideTask(cid, taskId, action);
        loadDetail(cid);
      } catch (e) {
        setError(String(e));
      } finally {
        setBusy(null);
      }
    },
    [cid, loadDetail]
  );

  const pending = (detail?.tasks ?? []).filter((t) => t.state === "APPROVAL_REQUIRED");

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <div className="text-xs font-mono tracking-wide text-mute uppercase">Campaigns</div>
        <button
          onClick={() => setCreating((v) => !v)}
          className="text-xs font-mono text-accent hover:underline"
        >
          {creating ? "cancel" : "+ new campaign"}
        </button>
      </div>

      {error && (
        <div className="text-xs font-mono text-critical bg-critical/10 border border-critical/30 rounded px-3 py-2">
          {error}
        </div>
      )}

      {creating && (
        <div className="bg-panel border border-edge rounded-lg p-3 flex flex-col gap-2">
          <div className="text-xs font-mono text-mute">
            Paste a bug-bounty program page. The policy is compiled and FROZEN at creation;
            active work against anything out of scope fails closed.
          </div>
          <textarea
            value={programText}
            onChange={(e) => setProgramText(e.target.value)}
            rows={6}
            placeholder={"In scope:\napi.example.com\n*.example.com\nRate: 2 requests/sec"}
            className="bg-panel2 border border-edge rounded p-2 text-xs font-mono text-ink outline-none focus:border-accent/60 resize-y"
          />
          <div className="flex justify-end">
            <button
              onClick={onCreate}
              disabled={!programText.trim()}
              className="text-xs font-mono bg-accent/15 text-accent border border-accent/40 rounded px-3 py-1.5 disabled:opacity-40 hover:bg-accent/25"
            >
              create campaign
            </button>
          </div>
        </div>
      )}

      {/* campaign picker — dense, click to select */}
      <div className="bg-panel border border-edge rounded-lg overflow-hidden">
        {campaigns.length === 0 ? (
          <div className="px-3 py-4 text-xs font-mono text-mute">
            no campaigns yet — create one, or run <span className="text-ink">argus program</span> /
            a Quick Pivot with an active tier.
          </div>
        ) : (
          campaigns.map((c) => (
            <button
              key={c.id}
              onClick={() => setCid(c.id)}
              className={`w-full flex items-center justify-between px-3 py-2 text-xs font-mono border-b border-edge/50 last:border-0 hover:bg-panel2 ${
                cid === c.id ? "bg-panel2" : ""
              }`}
            >
              <span className={cid === c.id ? "text-accent" : "text-ink"}>{c.id}</span>
              <span className="text-mute">
                {c.progress.percentage}% · {c.progress.state.toLowerCase()}
              </span>
            </button>
          ))
        )}
      </div>

      {detail && (
        <>
          <CampaignProgress p={detail.progress} />

          <div className="flex items-center gap-2 bg-panel border border-edge rounded-lg px-3 py-2">
            <span className="text-[10px] font-mono uppercase tracking-wide text-mute">Pivot</span>
            <select
              value={pivotLevel}
              onChange={(e) => setPivotLevel(e.target.value as EngagementLevel)}
              disabled={runState != null && ACTIVE_RUN.has(runState)}
              className="bg-panel2 border border-edge rounded px-2 py-1 text-xs font-mono text-ink outline-none focus:border-accent/60 disabled:opacity-40"
            >
              <option value="passive">passive</option>
              <option value="active">active</option>
              <option value="active-plus">active-plus</option>
              <option value="full">full</option>
            </select>
            <button
              onClick={onLaunchPivot}
              disabled={busy === "pivot" || (runState != null && ACTIVE_RUN.has(runState))}
              className="text-xs font-mono bg-accent/15 text-accent border border-accent/40 rounded px-3 py-1 disabled:opacity-40 hover:bg-accent/25"
            >
              {busy === "pivot" ? "starting…" : "start background pivot"}
            </button>
            {runState != null && ACTIVE_RUN.has(runState) && (
              <span className="text-[11px] font-mono text-accent ml-1">
                run {runState.toLowerCase()} — control it from the execution rail ↓
              </span>
            )}
          </div>

          {pending.length > 0 && (
            <div className="bg-panel border border-medium/30 rounded-lg p-3">
              <div className="text-xs font-mono tracking-wide text-medium uppercase mb-2">
                Approvals required · {pending.length}
              </div>
              <div className="flex flex-col gap-2">
                {pending.map((t) => (
                  <div
                    key={t.id}
                    className="flex items-center justify-between gap-3 bg-panel2 border border-edge rounded px-3 py-2"
                  >
                    <div className="min-w-0">
                      <div className="text-xs font-mono text-ink truncate">
                        {t.technique} · {t.host}
                      </div>
                      <div className="text-[11px] font-mono text-mute truncate">
                        {t.verdict_reason}
                      </div>
                    </div>
                    <div className="flex gap-1.5 shrink-0">
                      <DecisionBtn label="approve" cls="text-accent border-accent/40 hover:bg-accent/15"
                        busy={busy === t.id + "approve"} onClick={() => onDecide(t.id, "approve")} />
                      <DecisionBtn label="deny" cls="text-critical border-critical/40 hover:bg-critical/15"
                        busy={busy === t.id + "deny"} onClick={() => onDecide(t.id, "deny")} />
                      <DecisionBtn label="cancel" cls="text-mute border-edge hover:bg-panel"
                        busy={busy === t.id + "cancel"} onClick={() => onDecide(t.id, "cancel")} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          <TaskTable tasks={detail.tasks} onSelectTask={onSelectTask} onCancel={(id) => onDecide(id, "cancel")} />
        </>
      )}
    </div>
  );
}

function DecisionBtn({
  label, cls, busy, onClick,
}: { label: string; cls: string; busy: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      disabled={busy}
      className={`text-[11px] font-mono border rounded px-2 py-1 disabled:opacity-40 ${cls}`}
    >
      {busy ? "…" : label}
    </button>
  );
}

function TaskTable({
  tasks, onSelectTask, onCancel,
}: {
  tasks: Task[];
  onSelectTask?: (t: Task) => void;
  onCancel: (id: string) => void;
}) {
  if (tasks.length === 0) {
    return (
      <div className="bg-panel border border-edge rounded-lg px-3 py-4 text-xs font-mono text-mute">
        no tasks — active mapping proposes bounded tasks per host/technique.
      </div>
    );
  }
  const cancellable = new Set<TaskState>(["QUEUED", "RUNNING", "APPROVAL_REQUIRED", "PAUSED", "RETRY_SCHEDULED"]);
  // newest first
  const rows = [...tasks].sort((a, b) => (a.updated_at < b.updated_at ? 1 : -1));
  return (
    <div className="bg-panel border border-edge rounded-lg overflow-hidden">
      <div className="grid grid-cols-[72px_1fr_110px_90px] gap-2 px-3 py-2 text-[10px] font-mono uppercase tracking-wide text-mute border-b border-edge">
        <span>Time</span><span>Task · Target</span><span>State</span><span className="text-right">Action</span>
      </div>
      <div className="max-h-[48vh] overflow-auto">
        {rows.map((t) => (
          <div
            key={t.id}
            className="grid grid-cols-[72px_1fr_110px_90px] gap-2 px-3 py-1.5 text-xs font-mono border-b border-edge/40 last:border-0 hover:bg-panel2 cursor-pointer items-center"
            onClick={() => onSelectTask?.(t)}
          >
            <span className="text-mute">{hhmm(t.updated_at || t.created_at)}</span>
            <span className="truncate">
              <span className="text-ink">{t.technique}</span>
              <span className="text-mute"> · {t.host}</span>
            </span>
            <span className={STATE_COLOR[t.state] ?? "text-mute"}>{t.state.toLowerCase()}</span>
            <span className="text-right">
              {cancellable.has(t.state) ? (
                <button
                  onClick={(e) => { e.stopPropagation(); onCancel(t.id); }}
                  className="text-[11px] text-mute hover:text-critical"
                >
                  cancel
                </button>
              ) : (
                <span className="text-mute/50">—</span>
              )}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
