import { useMemo, useState } from "react";
import type { Dossier, GraphNode } from "../types";
import { typeColor } from "../lib";

interface Props {
  dossier: Dossier;
  onSelect: (node: GraphNode | null) => void;
  selected: GraphNode | null;
}

interface Placed {
  node: GraphNode;
  x: number;
  y: number;
}

const W = 760;
const H = 520;

/**
 * Dependency-free radial layout: entities are placed on concentric rings by
 * pivot depth (seed at the center), angle spread evenly within each ring.
 * Edges are drawn as straight links. No physics sim — deterministic + cheap,
 * which matters for the 40–500 entity graphs Argus produces.
 */
export default function EntityGraph({ dossier, onSelect, selected }: Props) {
  const [hover, setHover] = useState<string | null>(null);

  const { placed, links } = useMemo(() => {
    const cx = W / 2;
    const cy = H / 2;
    const byDepth = new Map<number, GraphNode[]>();
    for (const n of dossier.nodes) {
      const d = n.depth ?? 0;
      if (!byDepth.has(d)) byDepth.set(d, []);
      byDepth.get(d)!.push(n);
    }
    const depths = [...byDepth.keys()].sort((a, b) => a - b);
    const maxDepth = depths.length ? depths[depths.length - 1] : 0;
    const ringGap = maxDepth > 0 ? Math.min(cx, cy) / (maxDepth + 0.6) : 0;

    const pos = new Map<string, Placed>();
    for (const d of depths) {
      const ring = byDepth.get(d)!;
      const r = d === 0 ? 0 : ringGap * (d + 0.3);
      ring.forEach((node, i) => {
        if (d === 0 && ring.length === 1) {
          pos.set(node.key, { node, x: cx, y: cy });
          return;
        }
        const angle = (2 * Math.PI * i) / ring.length - Math.PI / 2 + d * 0.5;
        pos.set(node.key, {
          node,
          x: cx + r * Math.cos(angle),
          y: cy + r * Math.sin(angle),
        });
      });
    }

    const links = dossier.edges
      .map((e) => {
        const a = pos.get(e.src);
        const b = pos.get(e.dst);
        return a && b ? { a, b, rel: e.rel } : null;
      })
      .filter(Boolean) as { a: Placed; b: Placed; rel: string }[];

    return { placed: [...pos.values()], links };
  }, [dossier]);

  const isActive = (key: string) =>
    hover === key || selected?.key === key;

  return (
    <div className="border border-edge rounded-xl bg-panel overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-edge bg-panel2">
        <span className="text-xs font-mono text-mute">entity graph</span>
        <div className="flex gap-3 text-[10px] font-mono">
          {[...new Set(dossier.nodes.map((n) => n.type))].slice(0, 6).map((t) => (
            <span key={t} className="flex items-center gap-1 text-mute">
              <span className="w-2 h-2 rounded-full" style={{ background: typeColor(t) }} />
              {t}
            </span>
          ))}
        </div>
      </div>
      <svg
        viewBox={`0 0 ${W} ${H}`}
        className="w-full"
        style={{ maxHeight: 520 }}
        onClick={() => onSelect(null)}
      >
        {links.map((l, i) => {
          const active = isActive(l.a.node.key) || isActive(l.b.node.key);
          return (
            <line
              key={i}
              x1={l.a.x}
              y1={l.a.y}
              x2={l.b.x}
              y2={l.b.y}
              stroke={active ? "#5eead4" : "#232a3a"}
              strokeWidth={active ? 1.4 : 0.8}
              opacity={active ? 0.9 : 0.55}
            />
          );
        })}
        {placed.map((p) => {
          const active = isActive(p.node.key);
          const r = p.node.depth === 0 ? 9 : p.node.observed ? 6 : 4.5;
          return (
            <g
              key={p.node.key}
              transform={`translate(${p.x},${p.y})`}
              style={{ cursor: "pointer" }}
              onMouseEnter={() => setHover(p.node.key)}
              onMouseLeave={() => setHover(null)}
              onClick={(e) => {
                e.stopPropagation();
                onSelect(p.node);
              }}
            >
              <circle
                r={active ? r + 2.5 : r}
                fill={typeColor(p.node.type)}
                stroke={active ? "#e6e9ef" : "#0b0e14"}
                strokeWidth={active ? 1.5 : 1}
                opacity={p.node.observed ? 1 : 0.7}
              />
              {(active || p.node.depth === 0) && (
                <text
                  x={0}
                  y={-r - 6}
                  textAnchor="middle"
                  className="font-mono"
                  fontSize={10}
                  fill="#e6e9ef"
                >
                  {p.node.value.length > 34 ? p.node.value.slice(0, 32) + "…" : p.node.value}
                </text>
              )}
            </g>
          );
        })}
      </svg>
    </div>
  );
}
