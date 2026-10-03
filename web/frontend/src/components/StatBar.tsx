import type { Dossier, Severity } from "../types";
import { SEVERITIES, SEV_COLOR } from "../lib";

export default function StatBar({ dossier }: { dossier: Dossier }) {
  const nodeCount = dossier.nodes.length;
  const edgeCount = dossier.edges.length;

  const sevCounts = SEVERITIES.map((s) => ({
    sev: s,
    n: dossier.findings.filter((f) => f.severity === s).length,
  }));

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
      <Tile label="entities" value={nodeCount} sub={`${edgeCount} edges`} />
      <Tile
        label="findings"
        value={dossier.findings.length}
        sub={`${sevCounts.filter((s) => s.n > 0 && s.sev !== "info").length} classes`}
      />
      <div className="col-span-2 border border-edge rounded-xl bg-panel px-4 py-3">
        <div className="text-[10px] uppercase tracking-wider text-mute mb-2">severity</div>
        <div className="flex items-end gap-2">
          {sevCounts.map(({ sev, n }) => (
            <div key={sev} className="flex-1 flex flex-col items-center gap-1">
              <div
                className="w-full rounded-sm"
                style={{
                  height: Math.max(4, n === 0 ? 4 : 6 + n * 6),
                  background: n === 0 ? "#232a3a" : SEV_COLOR[sev as Severity],
                  opacity: n === 0 ? 0.5 : 1,
                }}
              />
              <span className="text-[10px] font-mono text-mute">{sev[0].toUpperCase()}</span>
              <span className="text-[11px] font-mono text-ink">{n}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function Tile({ label, value, sub }: { label: string; value: number; sub?: string }) {
  return (
    <div className="border border-edge rounded-xl bg-panel px-4 py-3">
      <div className="text-[10px] uppercase tracking-wider text-mute">{label}</div>
      <div className="text-2xl font-semibold text-ink mt-0.5">{value}</div>
      {sub && <div className="text-xs text-mute mt-0.5 font-mono">{sub}</div>}
    </div>
  );
}
