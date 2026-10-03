import { useState } from "react";
import type { Finding, Severity } from "../types";
import { SEV_COLOR } from "../lib";

export default function FindingCard({ f }: { f: Finding }) {
  const [open, setOpen] = useState(false);
  const color = SEV_COLOR[f.severity as Severity] ?? SEV_COLOR.info;
  const hasDetail =
    f.hypotheses.length > 0 ||
    f.recommendations.length > 0 ||
    f.evidence.length > 0 ||
    f.tags.length > 0;

  return (
    <div className="border border-edge rounded-xl bg-panel overflow-hidden">
      <button
        onClick={() => hasDetail && setOpen((o) => !o)}
        className={`w-full flex items-start gap-3 px-4 py-3 text-left ${
          hasDetail ? "hover:bg-panel2/60 cursor-pointer" : "cursor-default"
        }`}
      >
        <span
          className="mt-0.5 px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase shrink-0"
          style={{ background: `${color}22`, color }}
        >
          {f.severity}
        </span>
        <div className="flex-1 min-w-0">
          <div className="text-sm text-ink font-medium">{f.title}</div>
          <div className="text-xs text-mute font-mono mt-0.5 truncate">
            {f.rule} · {f.target}
          </div>
        </div>
        <div className="flex flex-col items-end gap-0.5 shrink-0">
          {f.confidence != null && (
            <span className="text-xs font-mono text-accent">{f.confidence}%</span>
          )}
          {f.score != null && f.score > 0 && (
            <span className="text-[10px] font-mono text-mute">score {f.score}</span>
          )}
        </div>
      </button>

      {open && hasDetail && (
        <div className="px-4 pb-4 pt-1 border-t border-edge/60 bg-base/40 space-y-3">
          {f.hypotheses.length > 0 && (
            <Block label="hypothesis">
              {f.hypotheses.map((h, i) => (
                <p key={i} className="text-xs text-ink/90 leading-relaxed">{h}</p>
              ))}
            </Block>
          )}
          {f.recommendations.length > 0 && (
            <Block label="recommendation">
              {f.recommendations.map((r, i) => (
                <p key={i} className="text-xs text-ink/90 leading-relaxed">{r}</p>
              ))}
            </Block>
          )}
          {f.evidence.length > 0 && (
            <Block label="evidence">
              {f.evidence.map((e, i) => (
                <pre
                  key={i}
                  className="text-[11px] font-mono text-mute whitespace-pre-wrap break-all bg-base rounded p-2"
                >
                  {typeof e === "object" ? JSON.stringify(e, null, 2) : String(e)}
                </pre>
              ))}
            </Block>
          )}
          {f.tags.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {f.tags.map((t) => (
                <span key={t} className="text-[10px] font-mono text-mute border border-edge rounded px-1.5 py-0.5">
                  {t}
                </span>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Block({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wider text-mute mb-1">{label}</div>
      <div className="space-y-1">{children}</div>
    </div>
  );
}
