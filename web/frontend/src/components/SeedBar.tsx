import { useState } from "react";
import type { EngagementLevel, RunState } from "../types";

const LEVELS: { id: EngagementLevel; label: string; hint: string; loud: boolean }[] = [
  { id: "passive", label: "Passive", hint: "public sources only · never touches target", loud: false },
  { id: "active", label: "Active", hint: "probe hosts + live CVEs", loud: true },
  { id: "active-plus", label: "Active+", hint: "+ request admin / sensitive paths", loud: true },
  { id: "full", label: "Full scan", hint: "+ TCP port scan (loudest)", loud: true },
];

interface Props {
  state: RunState;
  onRun: (seed: string, level: EngagementLevel) => void;
  onStop: () => void;
}

export default function SeedBar({ state, onRun, onStop }: Props) {
  const [seed, setSeed] = useState("");
  const [level, setLevel] = useState<EngagementLevel>("passive");
  const [ack, setAck] = useState(false);

  const running = state === "running";
  const loud = LEVELS.find((l) => l.id === level)?.loud ?? false;
  const canRun = seed.trim().length > 0 && (!loud || ack) && !running;

  return (
    <div className="border-b border-edge bg-panel/80 backdrop-blur px-5 py-4">
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2 text-accent font-mono text-sm shrink-0">
          <span className="inline-block w-2.5 h-2.5 rounded-full bg-accent" />
          argus
        </div>
        <input
          value={seed}
          onChange={(e) => setSeed(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && canRun) onRun(seed.trim(), level);
          }}
          placeholder="seed — domain, ip, email, username, or phone"
          disabled={running}
          className="flex-1 bg-base border border-edge rounded-lg px-4 py-2.5 font-mono text-sm
                     text-ink placeholder:text-mute/60 focus:outline-none focus:border-accent/60"
        />
        {running ? (
          <button
            onClick={onStop}
            className="px-5 py-2.5 rounded-lg bg-critical/15 text-critical border border-critical/40
                       hover:bg-critical/25 text-sm font-medium"
          >
            Stop
          </button>
        ) : (
          <button
            onClick={() => canRun && onRun(seed.trim(), level)}
            disabled={!canRun}
            className="px-6 py-2.5 rounded-lg bg-accent text-base font-semibold text-sm
                       disabled:opacity-35 disabled:cursor-not-allowed hover:bg-accent/90"
          >
            Pivot
          </button>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-2 mt-3">
        {LEVELS.map((l) => (
          <button
            key={l.id}
            onClick={() => {
              setLevel(l.id);
              setAck(false);
            }}
            disabled={running}
            title={l.hint}
            className={`px-3 py-1.5 rounded-md text-xs font-mono border transition-colors
              ${
                level === l.id
                  ? "bg-accent/15 border-accent/50 text-accent"
                  : "bg-base border-edge text-mute hover:text-ink hover:border-mute/50"
              }`}
          >
            {l.label}
            {l.loud && <span className="ml-1.5 text-high">●</span>}
          </button>
        ))}
        <span className="text-xs text-mute ml-1">
          {LEVELS.find((l) => l.id === level)?.hint}
        </span>
      </div>

      {loud && !running && (
        <label className="flex items-start gap-2 mt-3 text-xs text-high/90 cursor-pointer select-none">
          <input
            type="checkbox"
            checked={ack}
            onChange={(e) => setAck(e.target.checked)}
            className="mt-0.5 accent-high"
          />
          <span>
            This level sends <strong>active traffic</strong> to the target. I confirm I am
            authorized to test it (in-scope for a program or with explicit permission).
          </span>
        </label>
      )}
    </div>
  );
}
