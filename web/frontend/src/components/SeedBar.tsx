import { useState } from "react";
import type { EngagementLevel, RunState } from "../types";

function NumOpt({
  label, value, set, disabled, w,
}: { label: string; value: string; set: (v: string) => void; disabled: boolean; w: number }) {
  return (
    <label className="flex items-center gap-1.5 text-mute">
      {label}
      <input
        type="number"
        value={value}
        onChange={(e) => set(e.target.value)}
        disabled={disabled}
        style={{ width: w * 8 }}
        className="bg-base border border-edge rounded px-2 py-1 text-ink
                   focus:outline-none focus:border-accent/50"
      />
    </label>
  );
}

const LEVELS: { id: EngagementLevel; label: string; hint: string; loud: boolean }[] = [
  { id: "passive", label: "Passive", hint: "public sources only · never touches target", loud: false },
  { id: "active", label: "Active", hint: "probe hosts + live CVEs", loud: true },
  { id: "active-plus", label: "Active+", hint: "+ request admin / sensitive paths", loud: true },
  { id: "full", label: "Full scan", hint: "+ TCP port scan (loudest)", loud: true },
];

export interface PivotOptions {
  depth?: number;
  max?: number;
  deep?: number;
  ports?: string;
}

interface Props {
  state: RunState;
  onRun: (seed: string, level: EngagementLevel, opts: PivotOptions) => void;
  onStop: () => void;
  onSeedChange?: (seed: string) => void;
}

export default function SeedBar({ state, onRun, onStop, onSeedChange }: Props) {
  const [seed, setSeed] = useState("");
  const [level, setLevel] = useState<EngagementLevel>("passive");
  const [ack, setAck] = useState(false);
  const [showOpts, setShowOpts] = useState(false);
  const [depth, setDepth] = useState("2");
  const [max, setMax] = useState("40");
  const [deep, setDeep] = useState("0");
  const [ports, setPorts] = useState("");

  const running = state === "running";
  const loud = LEVELS.find((l) => l.id === level)?.loud ?? false;
  const canRun = seed.trim().length > 0 && (!loud || ack) && !running;

  const opts = (): PivotOptions => {
    const o: PivotOptions = {};
    if (depth.trim()) o.depth = Number(depth);
    if (max.trim()) o.max = Number(max);
    if (deep.trim()) o.deep = Number(deep);
    if (ports.trim()) o.ports = ports.trim();
    return o;
  };
  const fire = () => canRun && onRun(seed.trim(), level, opts());

  return (
    <div className="border-b border-edge bg-panel/80 backdrop-blur px-5 py-4">
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2 text-accent font-mono text-sm shrink-0">
          <span className="inline-block w-2.5 h-2.5 rounded-full bg-accent" />
          argus
        </div>
        <input
          value={seed}
          onChange={(e) => {
            setSeed(e.target.value);
            onSeedChange?.(e.target.value.trim());
          }}
          onKeyDown={(e) => {
            if (e.key === "Enter") fire();
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
            onClick={fire}
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
        <button
          onClick={() => setShowOpts((s) => !s)}
          disabled={running}
          className="ml-auto text-xs font-mono text-mute hover:text-ink"
        >
          {showOpts ? "− options" : "+ options"}
        </button>
      </div>

      {showOpts && (
        <div className="flex flex-wrap items-center gap-3 mt-3 text-xs font-mono">
          <NumOpt label="depth" value={depth} set={setDepth} disabled={running} w={12} />
          <NumOpt label="max" value={max} set={setMax} disabled={running} w={14} />
          <NumOpt label="deep" value={deep} set={setDeep} disabled={running} w={12} />
          <label className="flex items-center gap-1.5 text-mute">
            ports
            <input
              value={ports}
              onChange={(e) => setPorts(e.target.value)}
              disabled={running}
              placeholder="1-1024 or 22,80,443"
              className="w-40 bg-base border border-edge rounded px-2 py-1 text-ink
                         placeholder:text-mute/50 focus:outline-none focus:border-accent/50"
            />
          </label>
          <span className="text-mute/60">ports apply only at Full scan</span>
        </div>
      )}

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
