import { useCallback, useEffect, useRef, useState } from "react";
import type {
  CampaignDetail,
  CampaignRunState,
  Dossier,
  EngagementLevel,
  GraphNode,
  Progress,
  RunState,
  Task,
} from "./types";
import {
  controlRun,
  createCampaign,
  getCampaign,
  getCampaignSurface,
  runPivot,
  startPivot,
  subscribeCampaign,
} from "./api";
import SeedBar from "./components/SeedBar";
import type { PivotOptions } from "./components/SeedBar";
import RunProgress from "./components/RunProgress";
import StatBar from "./components/StatBar";
import EntityGraph from "./components/EntityGraph";
import FindingsList from "./components/FindingsList";
import NodePanel from "./components/NodePanel";
import SecretRecon from "./components/SecretRecon";
import ModuleRunner from "./components/ModuleRunner";
import ProgramScope from "./components/ProgramScope";
import CampaignWorkstation from "./components/CampaignWorkstation";
import CampaignProgress from "./components/CampaignProgress";
import EndpointsSurface from "./components/EndpointsSurface";
import ResourcesSurface from "./components/ResourcesSurface";
import AuthorizationMap from "./components/AuthorizationMap";
import ExperimentsSurface from "./components/ExperimentsSurface";
import { downloadReport } from "./lib";

// The ARGUS workstation shell. Quick Pivot is preserved verbatim as the Command
// Center; the campaign control plane (orchestrated active work, approvals, live
// progress) is a second surface. Same graphite/aqua DNA, nothing redesigned.

type View =
  | "command" | "campaigns" | "endpoints" | "resources" | "authmap" | "experiments" | "capabilities";

const NAV: { group: string; items: { id: View; label: string }[] }[] = [
  { group: "Command", items: [{ id: "command", label: "Quick Pivot" }] },
  { group: "Control", items: [{ id: "campaigns", label: "Campaigns" }] },
  { group: "Surface", items: [
    { id: "endpoints", label: "Endpoints" },
    { id: "resources", label: "Resources" },
    { id: "authmap", label: "Authorization Map" },
  ] },
  { group: "Research", items: [{ id: "experiments", label: "Experiments" }] },
  { group: "System", items: [{ id: "capabilities", label: "Capabilities" }] },
];

export default function App() {
  const [view, setView] = useState<View>("command");
  const [railProgress, setRailProgress] = useState<{ cid: string; p: Progress } | null>(null);
  const [railRun, setRailRun] = useState<{ cid: string; runState: CampaignRunState } | null>(null);
  const [inspectTask, setInspectTask] = useState<Task | null>(null);
  // the campaign the workstation should preselect — set when Quick Pivot hands off an
  // active run's approvals ("Review approvals") so the operator lands on the right one.
  const [selectedCid, setSelectedCid] = useState<string | null>(null);
  const openCampaign = useCallback((cid: string) => {
    setSelectedCid(cid);
    setView("campaigns");
  }, []);

  // stable identity — the workstation keys its SSE subscription off this callback, so a
  // new identity each render would thrash the EventSource connection.
  const onProgress = useCallback((cid: string, p: Progress) => {
    setRailProgress(p.state === "IDLE" ? null : { cid, p });
  }, []);
  // run activity is the coordinator's authority (SSE campaign.run.*), kept separate from
  // the verified-work percentage — the rail drives its controls off this, not off progress.
  const onRunState = useCallback((cid: string, runState: CampaignRunState) => {
    setRailRun({ cid, runState });
  }, []);

  return (
    <div className="h-screen flex flex-col bg-base text-ink">
      <Header />
      <div className="flex-1 flex min-h-0">
        <LeftNav view={view} setView={setView} />
        <main className="flex-1 overflow-auto">
          <div className="max-w-[1400px] w-full mx-auto px-5 py-5">
            {view === "command" && <CommandCenter onOpenCampaign={openCampaign} />}
            {view === "campaigns" && (
              <CampaignWorkstation
                initialCid={selectedCid}
                onSelectTask={setInspectTask}
                onProgress={onProgress}
                onRunState={onRunState}
              />
            )}
            {view === "endpoints" && <EndpointsSurface />}
            {view === "resources" && <ResourcesSurface />}
            {view === "authmap" && <AuthorizationMap />}
            {view === "experiments" && <ExperimentsSurface />}
            {view === "capabilities" && <Capabilities />}
          </div>
        </main>
        {inspectTask && (
          <RightInspector task={inspectTask} onClose={() => setInspectTask(null)} />
        )}
      </div>
      <ExecutionRail
        progress={railProgress}
        run={railRun}
        onOpen={() => setView("campaigns")}
      />
    </div>
  );
}

function Header() {
  return (
    <header className="shrink-0 h-12 border-b border-edge bg-panel flex items-center px-4 gap-4">
      <div className="font-mono text-sm tracking-widest text-accent">ARGUS</div>
      <div className="text-xs font-mono text-mute">/ offensive-intelligence workstation</div>
      <div className="ml-auto flex items-center gap-4 text-xs font-mono text-mute">
        <span className="flex items-center gap-1.5">
          <span className="inline-block w-2 h-2 rounded-full bg-accent" /> policy
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block w-2 h-2 rounded-full bg-accent" /> workers
        </span>
      </div>
    </header>
  );
}

function LeftNav({ view, setView }: { view: View; setView: (v: View) => void }) {
  return (
    <nav className="shrink-0 w-48 border-r border-edge bg-panel/60 overflow-auto py-3">
      {NAV.map((g) => (
        <div key={g.group} className="mb-4">
          <div className="px-4 mb-1 text-[10px] font-mono uppercase tracking-widest text-mute/70">
            {g.group}
          </div>
          {g.items.map((it) => (
            <button
              key={it.id}
              onClick={() => setView(it.id)}
              className={`w-full text-left px-4 py-1.5 text-xs font-mono border-l-2 ${
                view === it.id
                  ? "border-accent text-accent bg-panel2"
                  : "border-transparent text-ink hover:bg-panel2/60"
              }`}
            >
              {it.label}
            </button>
          ))}
        </div>
      ))}
    </nav>
  );
}

// The global live-activity surface AND the run controller. Activity (the dot + label +
// which buttons show) is driven by the coordinator's run state; progress is telemetry
// that changes beside it. Elapsed/queue depth move; the percentage only tracks verified
// work — so a ten-minute task keeps the sweep moving at a steady "Done 6/10", never faking
// progress. Every control here operates on real campaign state (no decorative buttons).
const ACTIVE_RUN = new Set<CampaignRunState>([
  "STARTING", "RUNNING", "PAUSING", "PAUSED", "WAITING_APPROVAL", "STOPPING",
]);

function ExecutionRail({
  progress,
  run,
  onOpen,
}: {
  progress: { cid: string; p: Progress } | null;
  run: { cid: string; runState: CampaignRunState } | null;
  onOpen: () => void;
}) {
  const [busy, setBusy] = useState(false);
  // show the rail while a run is active, or while a just-finished run's telemetry stands.
  const cid = run?.cid ?? progress?.cid ?? null;
  const runState = run && run.cid === cid ? run.runState : null;
  const p = progress && progress.cid === cid ? progress.p : null;
  if (!cid || (!runState && !p)) return null;

  const running = runState === "RUNNING" || runState === "STARTING";
  const paused = runState === "PAUSED" || runState === "PAUSING";
  const blocked = runState === "WAITING_APPROVAL";
  const active = runState != null && ACTIVE_RUN.has(runState);
  const label = (runState ?? p?.state ?? "idle").toLowerCase().replace(/_/g, " ");

  const control = async (action: "pause" | "resume" | "stop") => {
    setBusy(true);
    try {
      await controlRun(cid, action);   // SSE pushes the resulting run state back
    } catch {
      /* surfaced in the workstation; the rail stays quiet */
    } finally {
      setBusy(false);
    }
  };
  const Btn = ({ label, action, danger }: { label: string; action: "pause" | "resume" | "stop"; danger?: boolean }) => (
    <button
      onClick={(e) => { e.stopPropagation(); control(action); }}
      disabled={busy}
      className={`text-[11px] font-mono border rounded px-2 py-0.5 disabled:opacity-40 ${
        danger ? "text-critical border-critical/40 hover:bg-critical/15"
               : "text-accent border-accent/40 hover:bg-accent/15"
      }`}
    >
      {label}
    </button>
  );

  return (
    <div className="shrink-0 h-9 border-t border-edge bg-panel flex items-center gap-4 px-4 text-xs font-mono">
      <button onClick={onOpen} className="flex items-center gap-1.5 hover:text-accent">
        <span className={`inline-block w-2 h-2 rounded-full ${active ? "bg-accent" : "bg-mute"} ${running ? "pulse-dot" : ""}`} />
        <span className={active ? "text-accent" : "text-mute"}>{label}</span>
      </button>
      <button onClick={onOpen} className="text-ink truncate max-w-[260px] hover:underline">{cid}</button>
      {p?.current_technique && (
        <span className="text-mute truncate">
          {p.current_technique} {p.current_task && `· ${p.current_task}`}
        </span>
      )}
      <span className="ml-auto flex items-center gap-4 text-mute">
        {p && <span>Queue {p.queued}</span>}
        {p && <span>Approvals {p.approval_required}</span>}
        {p && <span>Done {p.completed}/{p.planned}</span>}
        {p && <span className={p.failed ? "text-critical" : ""}>Errors {p.failed}</span>}
        {/* controls: each only appears when it can actually act on the current run */}
        {(running || blocked) && <Btn label="pause" action="pause" />}
        {paused && <Btn label="resume" action="resume" />}
        {blocked && (
          <button onClick={(e) => { e.stopPropagation(); onOpen(); }}
            className="text-[11px] font-mono text-medium border border-medium/40 rounded px-2 py-0.5 hover:bg-medium/15">
            open approvals
          </button>
        )}
        {active && <Btn label="stop" action="stop" danger />}
      </span>
    </div>
  );
}

function RightInspector({ task, onClose }: { task: Task; onClose: () => void }) {
  const rows: [string, string][] = [
    ["id", task.id],
    ["technique", task.technique],
    ["host", task.host],
    ["state", task.state],
    ["verdict", task.verdict || "—"],
    ["reason", task.verdict_reason || "—"],
    ["hypothesis", task.hypothesis || "—"],
    ["attempts", String(task.attempts ?? 0)],
    ["experiment", task.experiment_id || "—"],
    ["updated", task.updated_at || "—"],
  ];
  return (
    <aside className="shrink-0 w-80 border-l border-edge bg-panel overflow-auto">
      <div className="flex items-center justify-between px-4 h-10 border-b border-edge">
        <span className="text-xs font-mono uppercase tracking-wide text-mute">Inspector · task</span>
        <button onClick={onClose} className="text-xs font-mono text-mute hover:text-ink">close</button>
      </div>
      <dl className="p-4 flex flex-col gap-2">
        {rows.map(([k, v]) => (
          <div key={k} className="grid grid-cols-[84px_1fr] gap-2 text-xs font-mono">
            <dt className="text-mute">{k}</dt>
            <dd className="text-ink break-words">{v}</dd>
          </div>
        ))}
      </dl>
    </aside>
  );
}

function Capabilities() {
  return (
    <div className="flex flex-col gap-5">
      <div className="text-xs font-mono text-mute">
        Manual capabilities — passive recon modules run directly; active probing is
        orchestrator-gated under a campaign.
      </div>
      <SecretRecon seed="" />
      <ModuleRunner />
    </div>
  );
}

// Active engagement levels run through the campaign coordinator (durable, controllable,
// restart-resilient); passive stays the lightweight public-discovery path. Same paste →
// mode → Pivot UX underneath both.
const ACTIVE_LEVELS = new Set<EngagementLevel>(["active", "active-plus", "full"]);
const LIVE_RUN = new Set<CampaignRunState>([
  "STARTING", "RUNNING", "PAUSING", "PAUSED", "WAITING_APPROVAL", "STOPPING",
]);

// --- Command Center: Quick Pivot. Passive = direct lightweight discovery. Active =
// create an ephemeral seed-scoped campaign, start a coordinator-owned background run, and
// ATTACH this screen to it (structured SSE + durable surface) — the browser is an
// observer/controller, never the owner of the run's lifetime. ---
function CommandCenter({ onOpenCampaign }: { onOpenCampaign: (cid: string) => void }) {
  const [state, setState] = useState<RunState>("idle");
  const [log, setLog] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [dossier, setDossier] = useState<Dossier | null>(null);
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const [meta, setMeta] = useState<{ seed: string; level: string } | null>(null);
  const [seed, setSeed] = useState("");
  // active attachment: the ephemeral campaign this screen created + its live state.
  const [live, setLive] = useState<{ cid: string; level: EngagementLevel } | null>(null);
  const [runState, setRunState] = useState<CampaignRunState | null>(null);
  const [detail, setDetail] = useState<CampaignDetail | null>(null);
  const abortRef = useRef<(() => void) | null>(null);   // passive ES abort OR active SSE unsub
  const refetchTimer = useRef<number | null>(null);
  const liveRef = useRef<string | null>(null);          // current active cid — ignore stale callbacks

  const teardown = useCallback(() => {
    abortRef.current?.();
    abortRef.current = null;
    if (refetchTimer.current) window.clearTimeout(refetchTimer.current);
    refetchTimer.current = null;
  }, []);
  useEffect(() => teardown, [teardown]);                // close the stream on unmount

  // API is the source of truth for WHAT is true; SSE only tells us WHEN to refresh. Rebuild
  // the dossier from the durable surface + the detail (tasks/approvals/progress) on every
  // event — no client-side event reducer, so a reconnect that replays the backlog is safe.
  const refreshLive = useCallback((cid: string) => {
    Promise.all([getCampaign(cid), getCampaignSurface(cid)])
      .then(([d, dos]) => {
        if (liveRef.current !== cid) return;            // a newer pivot superseded this one
        setDetail(d);
        setDossier(dos);
      })
      .catch(() => { /* transient (e.g. mid-write) — the next event refreshes */ });
  }, []);

  const onLiveEvent = useCallback((cid: string, ev: { event: string }) => {
    if (liveRef.current !== cid) return;
    if (ev.event.startsWith("campaign.run.")) {
      const rs = ev.event.slice("campaign.run.".length).toUpperCase();
      if (rs !== "RECOVERED") {
        setRunState(rs as CampaignRunState);
        // a disconnect is NOT a stop: only the coordinator's own terminal states settle us.
        if (rs === "COMPLETE" || rs === "STOPPED") setState("done");
        else if (rs === "FAILED") { setState("error"); setError("run failed"); }
        else setState("running");
      }
    }
    if (refetchTimer.current) window.clearTimeout(refetchTimer.current);
    refetchTimer.current = window.setTimeout(() => refreshLive(cid), 250);  // debounce bursts
  }, [refreshLive]);

  const onRun = useCallback((seedArg: string, level: EngagementLevel, opts: PivotOptions) => {
    teardown();
    liveRef.current = null;
    setState("running");
    setLog([]);
    setError(null);
    setDossier(null);
    setSelected(null);
    setSeed(seedArg);
    setMeta({ seed: seedArg, level });
    setLive(null);
    setRunState(null);
    setDetail(null);

    if (!ACTIVE_LEVELS.has(level)) {
      // PASSIVE — fast public discovery, straight to a dossier. Unchanged.
      abortRef.current = runPivot(seedArg, level, opts, {
        onStatus: (l) => setLog((prev) => [...prev, l]),
        onResult: (d) => setDossier(d),
        onError: (m) => { setError(m); setState("error"); },
        onDone: () => setState((s) => (s === "error" ? s : "done")),
      });
      return;
    }

    // ACTIVE — ephemeral seed-scoped campaign (frozen fail-closed policy), coordinator-owned
    // background run, then attach. Paste-and-go velocity: the operator never leaves this screen.
    (async () => {
      try {
        const { id } = await createCampaign(`In scope:\n${seedArg}\n`, seedArg);
        await startPivot(id, level, opts);
        liveRef.current = id;
        setLive({ cid: id, level });
        refreshLive(id);
        abortRef.current = subscribeCampaign(id, (ev) => onLiveEvent(id, ev));
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
        setState("error");
      }
    })();
  }, [teardown, refreshLive, onLiveEvent]);

  const onStop = useCallback(() => {
    const cid = liveRef.current;
    if (cid) {
      // ACTIVE: STOP THE RUN through the coordinator — not merely close the browser stream.
      // Closing the EventSource would leave the run executing on the server. STOPPING /
      // STOPPED arrive back over SSE and settle the UI.
      controlRun(cid, "stop").catch((e) => setError(String(e)));
      setLog((l) => [...l, "[web] stop requested — coordinator stopping the run"]);
      return;
    }
    teardown();
    setState((s) => (s === "running" ? "idle" : s));
    setLog((l) => [...l, "[web] stopped by operator"]);
  }, [teardown]);

  const progress = detail?.progress ?? null;

  return (
    <div className="flex flex-col gap-5">
      <SeedBar state={state} onRun={onRun} onStop={onStop} onSeedChange={setSeed} />

      {meta && (
        <div className="text-xs font-mono text-mute">
          seed <span className="text-accent">{meta.seed}</span> · level{" "}
          <span className="text-ink">{meta.level}</span>
          {live && <span className="text-mute/70"> · campaign {live.cid}</span>}
        </div>
      )}

      {live ? (
        <QuickPivotLive
          cid={live.cid}
          level={live.level}
          runState={runState}
          progress={progress}
          onOpenCampaign={onOpenCampaign}
        />
      ) : (
        <RunProgress state={state} log={log} error={error} />
      )}
      <ProgramScope />
      <SecretRecon seed={seed} />
      <ModuleRunner />

      {!dossier && state === "idle" && <EmptyState />}

      {dossier && (
        <>
          <StatBar dossier={dossier} />
          <div className="grid grid-cols-1 lg:grid-cols-[1fr_440px] gap-5 items-start">
            <div className="flex flex-col gap-4">
              <EntityGraph dossier={dossier} onSelect={setSelected} selected={selected} />
              {selected && <NodePanel node={selected} onClose={() => setSelected(null)} />}
            </div>
            <div className="lg:sticky lg:top-5">
              <div className="flex items-center justify-between mb-2">
                <div className="text-xs font-mono text-mute">findings · {dossier.findings.length}</div>
                <button
                  onClick={() => downloadReport(dossier, meta?.seed ?? "argus")}
                  className="text-xs font-mono text-accent hover:underline"
                >
                  export .md
                </button>
              </div>
              <div className="max-h-[calc(100vh-180px)]">
                <FindingsList dossier={dossier} />
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

// The live investigation block under the SeedBar while an active Quick Pivot runs. Shows
// the campaign/run context + the FACTUAL work-unit progress (reusing CampaignProgress, so
// the percentage is verified work, never elapsed time) + a compact approvals hand-off.
function QuickPivotLive({
  cid,
  level,
  runState,
  progress,
  onOpenCampaign,
}: {
  cid: string;
  level: EngagementLevel;
  runState: CampaignRunState | null;
  progress: Progress | null;
  onOpenCampaign: (cid: string) => void;
}) {
  const rs = runState ?? "STARTING";
  const active = LIVE_RUN.has(rs);
  const running = rs === "RUNNING" || rs === "STARTING";
  const label = rs.toLowerCase().replace(/_/g, " ");
  const approvals = progress?.approval_required ?? 0;

  return (
    <div className="flex flex-col gap-3">
      <div className="bg-panel border border-edge rounded-lg px-4 py-3 flex items-center gap-3 text-xs font-mono">
        <span className={`inline-block w-2 h-2 rounded-full ${active ? "bg-accent" : "bg-mute"} ${running ? "pulse-dot" : ""}`} />
        <span className={active ? "text-accent" : "text-mute"}>{label}</span>
        <span className="text-mute/60">·</span>
        <span className="text-ink truncate">Campaign {cid}</span>
        <span className="ml-auto px-2 py-0.5 rounded border border-edge text-mute uppercase tracking-wide">
          {level}
        </span>
      </div>

      {/* factual live progress + current execution + queue/approvals/denied/failed counts */}
      {progress && <CampaignProgress p={progress} />}

      {approvals > 0 && (
        <div className="bg-panel border border-medium/40 rounded-lg px-4 py-3 flex items-center gap-3 text-xs font-mono">
          <span className="text-medium">
            {approvals} {approvals === 1 ? "action requires" : "actions require"} authorization
          </span>
          <button
            onClick={() => onOpenCampaign(cid)}
            className="ml-auto text-medium border border-medium/40 rounded px-3 py-1 hover:bg-medium/15"
          >
            Review approvals
          </button>
        </div>
      )}
    </div>
  );
}

function EmptyState() {
  return (
    <div className="flex-1 flex flex-col items-center justify-center text-center py-24 gap-3">
      <div className="w-14 h-14 rounded-2xl border-2 border-accent/50 flex items-center justify-center">
        <div className="w-5 h-5 rounded-full bg-accent" />
      </div>
      <h1 className="text-lg font-semibold text-ink">One seed in — a scored dossier out.</h1>
      <p className="text-sm text-mute max-w-md">
        Seed a domain, IP, email, username, or phone. Argus walks RDAP → DNS → CT →
        IP and pivots back into more entities, then reasons over the graph for
        evidence-backed, reportable findings.
      </p>
      <p className="text-xs text-mute/70 font-mono mt-2">
        passive by default · active tiers require authorization
      </p>
    </div>
  );
}
