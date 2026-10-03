import { useCallback, useRef, useState } from "react";
import type { Dossier, EngagementLevel, GraphNode, RunState } from "./types";
import { runPivot } from "./api";
import SeedBar from "./components/SeedBar";
import RunProgress from "./components/RunProgress";
import StatBar from "./components/StatBar";
import EntityGraph from "./components/EntityGraph";
import FindingsList from "./components/FindingsList";
import NodePanel from "./components/NodePanel";

export default function App() {
  const [state, setState] = useState<RunState>("idle");
  const [log, setLog] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [dossier, setDossier] = useState<Dossier | null>(null);
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const [meta, setMeta] = useState<{ seed: string; level: string } | null>(null);
  const abortRef = useRef<(() => void) | null>(null);

  const onRun = useCallback((seed: string, level: EngagementLevel) => {
    setState("running");
    setLog([]);
    setError(null);
    setDossier(null);
    setSelected(null);
    setMeta({ seed, level });

    abortRef.current = runPivot(
      seed,
      level,
      {},
      {
        onStatus: (line) => setLog((l) => [...l, line]),
        onResult: (d) => setDossier(d),
        onError: (m) => {
          setError(m);
          setState("error");
        },
        onDone: () => setState((s) => (s === "error" ? s : "done")),
      }
    );
  }, []);

  const onStop = useCallback(() => {
    abortRef.current?.();
    setState((s) => (s === "running" ? "idle" : s));
    setLog((l) => [...l, "[web] stopped by operator"]);
  }, []);

  return (
    <div className="min-h-screen flex flex-col">
      <SeedBar state={state} onRun={onRun} onStop={onStop} />

      <main className="flex-1 max-w-[1400px] w-full mx-auto px-5 py-5 flex flex-col gap-5">
        {meta && (
          <div className="text-xs font-mono text-mute">
            seed <span className="text-accent">{meta.seed}</span> · level{" "}
            <span className="text-ink">{meta.level}</span>
          </div>
        )}

        <RunProgress state={state} log={log} error={error} />

        {!dossier && state === "idle" && (
          <EmptyState />
        )}

        {dossier && (
          <>
            <StatBar dossier={dossier} />
            <div className="grid grid-cols-1 lg:grid-cols-[1fr_440px] gap-5 items-start">
              <div className="flex flex-col gap-4">
                <EntityGraph dossier={dossier} onSelect={setSelected} selected={selected} />
                {selected && (
                  <NodePanel node={selected} onClose={() => setSelected(null)} />
                )}
              </div>
              <div className="lg:sticky lg:top-5">
                <div className="text-xs font-mono text-mute mb-2">
                  findings · {dossier.findings.length}
                </div>
                <div className="max-h-[calc(100vh-180px)]">
                  <FindingsList dossier={dossier} />
                </div>
              </div>
            </div>
          </>
        )}
      </main>
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
