import type { GraphNode } from "../types";
import { typeColor } from "../lib";

export default function NodePanel({
  node,
  onClose,
}: {
  node: GraphNode;
  onClose: () => void;
}) {
  const evidence = Object.entries(node.evidence || {});
  return (
    <div className="border border-edge rounded-xl bg-panel overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-edge bg-panel2">
        <div className="flex items-center gap-2 min-w-0">
          <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: typeColor(node.type) }} />
          <span className="text-xs font-mono text-ink truncate">{node.value}</span>
        </div>
        <button onClick={onClose} className="text-mute hover:text-ink text-xs">✕</button>
      </div>
      <div className="px-4 py-3 space-y-2 text-xs font-mono">
        <Row k="type" v={node.type} />
        <Row k="depth" v={String(node.depth)} />
        <Row k="via" v={node.via || "—"} />
        <Row k="observed" v={node.observed ? "yes (probed)" : "no (discovered only)"} />
        {evidence.length > 0 && (
          <div className="pt-2 mt-2 border-t border-edge/60">
            <div className="text-[10px] uppercase tracking-wider text-mute mb-1.5">evidence</div>
            {evidence.map(([k, v]) => (
              <Row key={k} k={k} v={typeof v === "object" ? JSON.stringify(v) : String(v)} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex gap-2">
      <span className="text-mute shrink-0 min-w-[80px]">{k}</span>
      <span className="text-ink/90 break-all">{v}</span>
    </div>
  );
}
