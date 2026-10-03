import { useEffect, useRef } from "react";
import type { RunState } from "../types";

interface Props {
  state: RunState;
  log: string[];
  error: string | null;
}

export default function RunProgress({ state, log, error }: Props) {
  const endRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    endRef.current?.scrollIntoView({ block: "end" });
  }, [log.length]);

  if (state === "idle" && log.length === 0) return null;

  return (
    <div className="border border-edge rounded-xl bg-panel overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-edge bg-panel2">
        {state === "running" ? (
          <span className="w-2 h-2 rounded-full bg-accent pulse-dot" />
        ) : state === "error" ? (
          <span className="w-2 h-2 rounded-full bg-critical" />
        ) : (
          <span className="w-2 h-2 rounded-full bg-low" />
        )}
        <span className="text-xs font-mono text-mute">
          {state === "running" ? "engine running" : state === "error" ? "failed" : "run complete"}
        </span>
      </div>
      <div className="max-h-48 overflow-y-auto px-4 py-3 font-mono text-xs leading-relaxed">
        {log.map((line, i) => (
          <div key={i} className="text-mute whitespace-pre-wrap break-all">
            {line}
          </div>
        ))}
        {error && <div className="text-critical mt-1 whitespace-pre-wrap break-all">✗ {error}</div>}
        <div ref={endRef} />
      </div>
    </div>
  );
}
