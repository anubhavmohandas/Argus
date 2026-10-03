import { useMemo, useState } from "react";
import type { Dossier, Severity } from "../types";
import { SEVERITIES, sevRank } from "../lib";
import FindingCard from "./FindingCard";

export default function FindingsList({ dossier }: { dossier: Dossier }) {
  // Default floor = low, so info-level recon noise ("nothing notable") is hidden
  // until the operator opts in — matches Argus's "no low-signal spam" directive.
  const [minSev, setMinSev] = useState<Severity>("low");
  const [q, setQ] = useState("");

  const findings = useMemo(() => {
    const floor = sevRank(minSev);
    return [...dossier.findings]
      .filter((f) => sevRank(f.severity) >= floor)
      .filter((f) => {
        if (!q.trim()) return true;
        const hay = `${f.title} ${f.rule} ${f.target} ${f.hypotheses.join(" ")}`.toLowerCase();
        return hay.includes(q.toLowerCase());
      })
      .sort(
        (a, b) =>
          sevRank(b.severity) - sevRank(a.severity) ||
          (b.score ?? 0) - (a.score ?? 0) ||
          (b.confidence ?? 0) - (a.confidence ?? 0)
      );
  }, [dossier, minSev, q]);

  const hidden = dossier.findings.length - findings.length;

  return (
    <div className="flex flex-col gap-3 h-full">
      <div className="flex items-center gap-2">
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="filter findings…"
          className="flex-1 bg-base border border-edge rounded-lg px-3 py-1.5 text-xs font-mono
                     text-ink placeholder:text-mute/60 focus:outline-none focus:border-accent/50"
        />
        <select
          value={minSev}
          onChange={(e) => setMinSev(e.target.value as Severity)}
          className="bg-base border border-edge rounded-lg px-2 py-1.5 text-xs font-mono text-mute
                     focus:outline-none focus:border-accent/50"
        >
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              ≥ {s}
            </option>
          ))}
        </select>
      </div>

      <div className="flex flex-col gap-2 overflow-y-auto pr-1">
        {findings.length === 0 ? (
          <div className="text-xs text-mute font-mono py-8 text-center">
            no findings at this filter
            {hidden > 0 && <div className="mt-1 opacity-70">{hidden} below threshold</div>}
          </div>
        ) : (
          <>
            {findings.map((f, i) => (
              <FindingCard key={`${f.rule}-${f.target}-${i}`} f={f} />
            ))}
            {hidden > 0 && (
              <div className="text-[11px] text-mute/70 font-mono text-center py-1">
                {hidden} lower-severity item{hidden === 1 ? "" : "s"} hidden
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
