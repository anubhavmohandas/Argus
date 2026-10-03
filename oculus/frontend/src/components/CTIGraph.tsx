import { useEffect, useMemo, useRef, useState, type CSSProperties, type PointerEvent, type WheelEvent } from 'react';
import type { ScanResult, URLScanPivotHit, URLScanPivotResponse } from '../types';

interface CTIGraphProps {
  results: ScanResult[];
  pivots: URLScanPivotResponse[];
  onClose: () => void;
}

type GraphNodeType = 'scan' | 'root' | 'ip' | 'brand' | 'urlscan' | 'asn';

interface GraphNode {
  id: string;
  label: string;
  type: GraphNodeType;
  risk: number;
  x: number;
  y: number;
  data: Record<string, unknown>;
}

interface GraphEdge {
  id: string;
  from: string;
  to: string;
  label: string;
}

export function CTIGraph({ results, pivots, onClose }: CTIGraphProps) {
  const graph = useMemo(() => buildGraph(results, pivots), [results, pivots]);
  const [selectedId, setSelectedId] = useState(graph.nodes[0]?.id || '');
  const [hoverId, setHoverId] = useState('');
  const [query, setQuery] = useState('');
  const [types, setTypes] = useState<Record<GraphNodeType, boolean>>({
    scan: true,
    root: true,
    ip: true,
    brand: true,
    urlscan: true,
    asn: true,
  });
  const [view, setView] = useState({ x: 0, y: 0, zoom: 1 });
  const [dragging, setDragging] = useState<DragState | null>(null);
  const [positions, setPositions] = useState<Record<string, { x: number; y: number }>>({});
  const [oracleMode, setOracleMode] = useState(false);
  const [cinemaFx, setCinemaFx] = useState(false);
  const frameRef = useRef<number | null>(null);
  const pendingRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    if (!selectedId && graph.nodes[0]) setSelectedId(graph.nodes[0].id);
  }, [graph.nodes, selectedId]);

  const positionedNodes = useMemo(
    () => graph.nodes.map(node => ({ ...node, ...(positions[node.id] || {}) })),
    [graph.nodes, positions],
  );
  const nodeById = useMemo(() => new Map(positionedNodes.map(node => [node.id, node])), [positionedNodes]);
  const selected = nodeById.get(selectedId) || positionedNodes[0];
  const activeId = hoverId || selected?.id || '';
  const neighbors = useMemo(() => connectedNodeIds(activeId, graph.edges), [activeId, graph.edges]);
  const visible = useMemo(() => visibleNodeIds(positionedNodes, query, types, selected?.id), [positionedNodes, query, types, selected?.id]);
  const visibleNodes = positionedNodes.filter(node => visible.has(node.id));
  const visibleEdges = graph.edges.filter(edge => visible.has(edge.from) && visible.has(edge.to));
  const intel = useMemo(() => buildOracleIntel(positionedNodes, graph.edges, pivots), [positionedNodes, graph.edges, pivots]);
  const denseGraph = visibleNodes.length > 120 || visibleEdges.length > 140;
  const richFx = cinemaFx && !denseGraph && !dragging;
  const ambientDotCount = richFx ? 24 : 8;

  useEffect(() => {
    if (!oracleMode || intel.priority.length === 0) return;
    let index = 0;
    const timer = window.setInterval(() => {
      const next = intel.priority[index % intel.priority.length];
      setSelectedId(next.id);
      setView({ x: 600 - next.x, y: 360 - next.y, zoom: 1.32 });
      index += 1;
    }, 3600);
    return () => window.clearInterval(timer);
  }, [oracleMode, intel.priority]);

  useEffect(() => () => {
    if (frameRef.current != null) window.cancelAnimationFrame(frameRef.current);
  }, []);

  const scheduleGraphUpdate = (update: () => void) => {
    pendingRef.current = update;
    if (frameRef.current != null) return;
    frameRef.current = window.requestAnimationFrame(() => {
      frameRef.current = null;
      const pending = pendingRef.current;
      pendingRef.current = null;
      pending?.();
    });
  };

  const toGraphPoint = (event: PointerEvent<SVGSVGElement> | PointerEvent<SVGGElement>) => {
    const svg = event.currentTarget instanceof SVGSVGElement
      ? event.currentTarget
      : event.currentTarget.ownerSVGElement;
    const rect = svg?.getBoundingClientRect();
    if (!rect) return { x: 0, y: 0 };
    return {
      x: ((event.clientX - rect.left) / rect.width * 1200 - view.x) / view.zoom,
      y: ((event.clientY - rect.top) / rect.height * 720 - view.y) / view.zoom,
    };
  };

  const startNodeDrag = (event: PointerEvent<SVGGElement>, node: GraphNode) => {
    event.stopPropagation();
    event.currentTarget.setPointerCapture(event.pointerId);
    const point = toGraphPoint(event);
    setSelectedId(node.id);
    setDragging({ kind: 'node', id: node.id, offsetX: point.x - node.x, offsetY: point.y - node.y });
  };

  const startPan = (event: PointerEvent<SVGSVGElement>) => {
    if (event.target !== event.currentTarget) return;
    event.currentTarget.setPointerCapture(event.pointerId);
    setDragging({ kind: 'pan', startX: event.clientX, startY: event.clientY, viewX: view.x, viewY: view.y });
  };

  const movePointer = (event: PointerEvent<SVGSVGElement>) => {
    if (!dragging) return;
    if (dragging.kind === 'pan') {
      const rect = event.currentTarget.getBoundingClientRect();
      const nextX = dragging.viewX + ((event.clientX - dragging.startX) / rect.width) * 1200;
      const nextY = dragging.viewY + ((event.clientY - dragging.startY) / rect.height) * 720;
      scheduleGraphUpdate(() => setView(prev => ({ ...prev, x: nextX, y: nextY })));
      return;
    }
    const point = toGraphPoint(event);
    const nextX = point.x - dragging.offsetX;
    const nextY = point.y - dragging.offsetY;
    const nodeId = dragging.id;
    scheduleGraphUpdate(() => {
      setPositions(prev => ({
        ...prev,
        [nodeId]: { x: nextX, y: nextY },
      }));
    });
  };

  const handleWheel = (event: WheelEvent<SVGSVGElement>) => {
    event.preventDefault();
    const delta = event.deltaY > 0 ? -0.08 : 0.08;
    setView(prev => ({ ...prev, zoom: clamp(prev.zoom + delta, 0.55, 2.2) }));
  };

  const toggleType = (type: GraphNodeType) => {
    setTypes(prev => ({ ...prev, [type]: !prev[type] }));
  };

  return (
    <div className={`cti-graph-overlay ${oracleMode ? 'oracle-mode' : ''} ${richFx ? 'cinema-fx' : 'smooth-fx'}`}>
      <div className="cti-graph-shell">
        <div className="cti-graph-toolbar">
          <div>
            <div className="cti-graph-title">CTI GRAPH</div>
            <div className="cti-graph-sub">
              {graph.nodes.length} nodes / {graph.edges.length} connections
            </div>
          </div>
          <div className="cti-graph-legend">
            {(['scan', 'root', 'urlscan', 'ip', 'asn', 'brand'] as GraphNodeType[]).map(type => (
              <button
                key={type}
                className={types[type] ? 'active' : ''}
                onClick={() => toggleType(type)}
                style={{ '--legend-tone': nodeColor(type) } as CSSProperties}
              >
                <i />
                {type}
              </button>
            ))}
          </div>
          <div className="cti-graph-controls">
            <input
              value={query}
              onChange={event => setQuery(event.target.value)}
              placeholder="search node / URL / IP..."
            />
            <button onClick={() => setView(prev => ({ ...prev, zoom: clamp(prev.zoom + 0.15, 0.55, 2.2) }))}>+</button>
            <button onClick={() => setView(prev => ({ ...prev, zoom: clamp(prev.zoom - 0.15, 0.55, 2.2) }))}>-</button>
            <button onClick={() => { setView({ x: 0, y: 0, zoom: 1 }); setPositions({}); }}>RESET</button>
            <button
              className={oracleMode ? 'oracle-active' : ''}
              onClick={() => setOracleMode(prev => !prev)}
            >
              ORACLE
            </button>
            <button
              className={cinemaFx ? 'oracle-active' : ''}
              onClick={() => setCinemaFx(prev => !prev)}
              title={denseGraph ? 'Cinematic FX stays light on large graphs for smooth performance' : 'Toggle cinematic graph FX'}
            >
              {cinemaFx ? 'FX ON' : 'FX'}
            </button>
          </div>
          <button className="cti-graph-close" onClick={onClose}>CLOSE</button>
        </div>

        {oracleMode && <OracleDeck intel={intel} selected={selected} onSelect={node => setSelectedId(node.id)} />}

        <div className="cti-graph-body">
          <div className="cti-graph-canvas">
            <div className="cti-depth-grid" />
            <div className="cti-dotted-field">
              {Array.from({ length: ambientDotCount }).map((_, index) => (
                <i
                  key={index}
                  style={{
                    '--dot-index': index,
                    '--dot-left': `${(index * 37) % 100}%`,
                    '--dot-top': `${(index * 61) % 100}%`,
                  } as CSSProperties}
                />
              ))}
            </div>
            <div className="cti-light-curtain" />
            {oracleMode && (
              <>
                <div className="oracle-radar-core" />
                <div className="oracle-scan-plane" />
              </>
            )}
            <svg
              viewBox="0 0 1200 720"
              role="img"
              aria-label="CTI relationship graph"
              onPointerDown={startPan}
              onPointerMove={movePointer}
              onPointerUp={() => setDragging(null)}
              onPointerCancel={() => setDragging(null)}
              onWheel={handleWheel}
            >
              <defs>
                <radialGradient id="graphCoreGlow" cx="50%" cy="45%" r="64%">
                  <stop offset="0%" stopColor="rgba(64, 196, 255, 0.42)" />
                  <stop offset="42%" stopColor="rgba(0, 230, 118, 0.13)" />
                  <stop offset="100%" stopColor="rgba(4, 6, 8, 0)" />
                </radialGradient>
                <linearGradient id="eliteEdgeGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="rgba(64, 196, 255, 0.12)" />
                  <stop offset="42%" stopColor="rgba(0, 230, 118, 0.82)" />
                  <stop offset="100%" stopColor="rgba(234, 128, 252, 0.18)" />
                </linearGradient>
                <filter id="nodeGlow" x="-80%" y="-80%" width="260%" height="260%">
                  <feGaussianBlur stdDeviation="3.5" result="blur" />
                  <feMerge>
                    <feMergeNode in="blur" />
                    <feMergeNode in="SourceGraphic" />
                  </feMerge>
                </filter>
                <filter id="eliteGlow" x="-80%" y="-80%" width="260%" height="260%">
                  <feGaussianBlur stdDeviation="6" result="coloredBlur" />
                  <feColorMatrix
                    in="coloredBlur"
                    type="matrix"
                    values="0 0 0 0 0.1  0 0 0 0 1  0 0 0 0 0.72  0 0 0 0.8 0"
                    result="neon"
                  />
                  <feMerge>
                    <feMergeNode in="neon" />
                    <feMergeNode in="SourceGraphic" />
                  </feMerge>
                </filter>
              </defs>
              <rect className="cti-svg-core" x="0" y="0" width="1200" height="720" fill="url(#graphCoreGlow)" />
              <g transform={`translate(${view.x} ${view.y}) scale(${view.zoom})`}>
                {visibleEdges.map((edge, index) => {
                  const from = nodeById.get(edge.from);
                  const to = nodeById.get(edge.to);
                  if (!from || !to) return null;
                  const active = activeId && (edge.from === activeId || edge.to === activeId);
                  const showTravelFx = active || (richFx && index < 36);
                  return (
                    <g key={edge.id} className={`cti-edge ${active ? 'active' : activeId ? 'dimmed' : ''}`}>
                      {richFx && <line className="cti-edge-shadow" x1={from.x} y1={from.y} x2={to.x} y2={to.y} />}
                      <line className="cti-edge-main" x1={from.x} y1={from.y} x2={to.x} y2={to.y} />
                      <line className={`cti-edge-dots ${showTravelFx ? 'moving' : ''}`} x1={from.x} y1={from.y} x2={to.x} y2={to.y} />
                      <text x={(from.x + to.x) / 2} y={(from.y + to.y) / 2}>{edge.label}</text>
                      {showTravelFx && (
                        <circle className="cti-edge-spark" r={active ? '4' : '2.4'}>
                          <animateMotion dur={active ? '1.45s' : '3.8s'} repeatCount="indefinite" path={`M ${from.x} ${from.y} L ${to.x} ${to.y}`} />
                        </circle>
                      )}
                      {active && (
                        <>
                          <circle className="cti-edge-pulse" r="3.4">
                            <animateMotion dur="1.1s" repeatCount="indefinite" path={`M ${from.x} ${from.y} L ${to.x} ${to.y}`} />
                          </circle>
                          <circle className="cti-edge-pulse cti-edge-pulse-late" r="2.6">
                            <animateMotion dur="1.1s" begin="0.52s" repeatCount="indefinite" path={`M ${from.x} ${from.y} L ${to.x} ${to.y}`} />
                          </circle>
                        </>
                      )}
                    </g>
                  );
                })}
                {visibleNodes.map(node => {
                  const related = !activeId || node.id === activeId || neighbors.has(node.id);
                  const radius = nodeRadius(node);
                  return (
                    <g
                      key={node.id}
                      className={`cti-node ${selected?.id === node.id ? 'selected' : ''} ${hoverId === node.id ? 'hovered' : ''} ${related ? '' : 'dimmed'}`}
                      transform={`translate(${node.x} ${node.y})`}
                      onPointerDown={event => startNodeDrag(event, node)}
                      onPointerEnter={() => setHoverId(node.id)}
                      onPointerLeave={() => setHoverId('')}
                      onDoubleClick={() => setView({ x: 600 - node.x, y: 360 - node.y, zoom: 1.42 })}
                    >
                      <circle r={radius + 18} className="cti-node-aura" style={{ '--node-tone': nodeColor(node.type) } as CSSProperties} />
                      {richFx && <circle r={radius + 10} className="cti-node-dotted-orbit" />}
                      <circle r={radius} fill={nodeColor(node.type)} filter={richFx ? 'url(#eliteGlow)' : undefined} />
                      <circle r={radius + 7} className="cti-node-ring" />
                      {richFx && <circle r="2.2" cx={radius + 11} cy="0" className="cti-node-moon" style={{ '--node-tone': nodeColor(node.type) } as CSSProperties} />}
                      <text y={radius + 20}>{shortLabel(node.label, 22)}</text>
                    </g>
                  );
                })}
                {oracleMode && selected && (
                  <g className="oracle-target-reticle" transform={`translate(${selected.x} ${selected.y})`}>
                    <circle r="38" />
                    <circle r="58" />
                    <line x1="-72" y1="0" x2="-44" y2="0" />
                    <line x1="44" y1="0" x2="72" y2="0" />
                    <line x1="0" y1="-72" x2="0" y2="-44" />
                    <line x1="0" y1="44" x2="0" y2="72" />
                  </g>
                )}
              </g>
              {visibleNodes.length === 0 && (
                <g className="cti-no-results">
                  <text x="600" y="360">NO MATCHING NODES</text>
                </g>
              )}
            </svg>
          </div>

          <aside className="cti-node-panel">
            {selected ? (
              <>
                <div className="cti-node-kicker">{selected.type}</div>
                <h2>{selected.label}</h2>
                <div className="cti-node-risk" style={{ color: riskTone(selected.risk) }}>
                  risk {selected.risk}
                </div>
                {oracleMode && (
                  <div className="oracle-brief">
                    <span>ORACLE ASSESSMENT</span>
                    <p>{oracleNodeBrief(selected, neighbors.size)}</p>
                  </div>
                )}
                <div className="cti-node-actions">
                  <button onClick={() => navigator.clipboard.writeText(selected.label).catch(() => {})}>COPY</button>
                  <button onClick={() => setView({ x: 600 - selected.x, y: 360 - selected.y, zoom: 1.42 })}>FOCUS</button>
                </div>
                <div className="cti-node-neighbors">
                  {Array.from(connectedNodeIds(selected.id, graph.edges))
                    .map(id => nodeById.get(id))
                    .filter((node): node is GraphNode => Boolean(node))
                    .slice(0, 12)
                    .map(node => (
                      <button key={node.id} onClick={() => setSelectedId(node.id)}>
                        {shortLabel(node.label, 28)}
                      </button>
                    ))}
                </div>
                <div className="cti-data-list">
                  {Object.entries(selected.data).map(([key, value]) => (
                    <DataRow key={key} label={key} value={value} />
                  ))}
                </div>
              </>
            ) : (
              <div className="cti-empty">No graph data yet.</div>
            )}
          </aside>
        </div>
      </div>
    </div>
  );
}

type DragState =
  | { kind: 'node'; id: string; offsetX: number; offsetY: number }
  | { kind: 'pan'; startX: number; startY: number; viewX: number; viewY: number };

interface OracleIntel {
  threatLevel: string;
  score: number;
  brief: string;
  stats: Array<{ label: string; value: string | number; tone: string }>;
  priority: GraphNode[];
  anomalies: string[];
}

function OracleDeck({ intel, selected, onSelect }: { intel: OracleIntel; selected?: GraphNode; onSelect: (node: GraphNode) => void }) {
  return (
    <div className="oracle-deck">
      <div className="oracle-card oracle-status-card">
        <span>ORACLE THREAT FUSION</span>
        <strong>{intel.threatLevel}</strong>
        <p>{intel.brief}</p>
      </div>
      <div className="oracle-metrics">
        {intel.stats.map(stat => (
          <div key={stat.label} className="oracle-metric" style={{ '--metric-tone': stat.tone } as CSSProperties}>
            <span>{stat.label}</span>
            <strong>{stat.value}</strong>
          </div>
        ))}
      </div>
      <div className="oracle-card oracle-priority">
        <span>ENTITY QUEUE</span>
        <div>
          {intel.priority.slice(0, 6).map(node => (
            <button key={node.id} className={selected?.id === node.id ? 'active' : ''} onClick={() => onSelect(node)}>
              <b>{node.type}</b>
              {shortLabel(node.label, 26)}
              <i>{node.risk}</i>
            </button>
          ))}
        </div>
      </div>
      <div className="oracle-card oracle-anomalies">
        <span>ANOMALIES</span>
        {intel.anomalies.map(item => <small key={item}>{item}</small>)}
      </div>
    </div>
  );
}

function DataRow({ label, value }: { label: string; value: unknown }) {
  const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  return (
    <div className="cti-data-row">
      <span>{label}</span>
      <button onClick={() => navigator.clipboard.writeText(text || '').catch(() => {})}>
        {text || '-'}
      </button>
    </div>
  );
}

function buildGraph(results: ScanResult[], pivots: URLScanPivotResponse[]) {
  const nodes = new Map<string, Omit<GraphNode, 'x' | 'y'>>();
  const edges = new Map<string, GraphEdge>();
  const addNode = (id: string, node: Omit<GraphNode, 'id' | 'x' | 'y'>) => {
    if (!id || nodes.has(id)) return;
    nodes.set(id, { id, ...node });
  };
  const addEdge = (from: string, to: string, label: string) => {
    if (!from || !to || from === to) return;
    const id = `${from}->${to}:${label}`;
    if (!edges.has(id)) edges.set(id, { id, from, to, label });
  };

  for (const result of results) {
    const intel = result.intelligence;
    const scanId = `scan:${result.domain}`;
    const root = intel?.rootDomain || result.domain;
    const rootId = `root:${root}`;
    addNode(scanId, {
      label: result.domain,
      type: 'scan',
      risk: intel?.riskScore || 0,
      data: {
        domain: result.domain,
        url: result.url,
        status: result.status,
        title: result.title,
        server: result.server,
        ipAddress: intel?.ipAddress,
        rootDomain: root,
        brandCandidate: intel?.brandCandidate,
        categories: intel?.categories,
        indicators: intel?.indicators,
        technologies: intel?.technologies,
        redirectUrl: result.redirectUrl,
        redirectChain: result.redirectChain,
        contentLength: result.contentLength,
        durationMs: result.durationMs,
        timestamp: result.timestamp,
        tls: result.tls,
      },
    });
    addNode(rootId, {
      label: root,
      type: 'root',
      risk: intel?.riskScore || 0,
      data: { rootDomain: root, source: 'ReconVision root domain' },
    });
    addEdge(rootId, scanId, 'subdomain');

    if (intel?.ipAddress) {
      const ipId = `ip:${intel.ipAddress}`;
      addNode(ipId, {
        label: intel.ipAddress,
        type: 'ip',
        risk: intel.riskScore,
        data: { ipAddress: intel.ipAddress, source: 'ReconVision DNS resolution' },
      });
      addEdge(scanId, ipId, 'resolves');
    }
    if (intel?.brandCandidate) {
      const brandId = `brand:${intel.brandCandidate}`;
      addNode(brandId, {
        label: intel.brandCandidate,
        type: 'brand',
        risk: intel.riskScore,
        data: { brand: intel.brandCandidate, source: 'ReconVision local intelligence' },
      });
      addEdge(scanId, brandId, 'impersonates');
    }
  }

  for (const pivot of pivots) {
    const pivotRootId = `${pivot.type}:${pivot.indicator}`;
    addNode(pivotRootId, {
      label: pivot.indicator,
      type: pivot.type === 'ip' ? 'ip' : pivot.type === 'brand' ? 'brand' : 'root',
      risk: 0,
      data: {
        indicator: pivot.indicator,
        type: pivot.type,
        query: pivot.query,
        total: pivot.total,
        days: pivot.days,
        rateLimit: pivot.rateLimit,
      },
    });

    for (const hit of safeArray(pivot.results).slice(0, 80)) {
      addURLScanHit(hit, pivotRootId, addNode, addEdge);
    }
  }

  const laidOut = layoutNodes(Array.from(nodes.values()), Array.from(edges.values()));
  return {
    nodes: laidOut,
    edges: Array.from(edges.values()),
    nodeById: new Map(laidOut.map(node => [node.id, node])),
  };
}

function addURLScanHit(
  hit: URLScanPivotHit,
  pivotRootId: string,
  addNode: (id: string, node: Omit<GraphNode, 'id' | 'x' | 'y'>) => void,
  addEdge: (from: string, to: string, label: string) => void,
) {
  const hitId = `urlscan:${hit.result || hit.url || hit.domain}`;
  addNode(hitId, {
    label: hit.domain || hit.url,
    type: 'urlscan',
    risk: hit.malicious ? 90 : hit.suspicious ? 65 : 20,
    data: {
      domain: hit.domain,
      url: hit.url,
      ip: hit.ip,
      asn: hit.asn,
      asnName: hit.asnName,
      title: hit.title,
      country: hit.country,
      malicious: hit.malicious,
      suspicious: hit.suspicious,
      brands: hit.brands,
      relatedTags: hit.relatedTags,
      result: hit.result,
      screenshot: hit.screenshot,
      time: hit.time,
      source: 'urlscan.io',
    },
  });
  addEdge(pivotRootId, hitId, 'urlscan');

  if (hit.ip) {
    const ipId = `ip:${hit.ip}`;
    addNode(ipId, { label: hit.ip, type: 'ip', risk: 0, data: { ip: hit.ip, source: 'urlscan.io' } });
    addEdge(hitId, ipId, 'ip');
  }
  if (hit.asn) {
    const asnId = `asn:${hit.asn}`;
    addNode(asnId, { label: hit.asn, type: 'asn', risk: 0, data: { asn: hit.asn, asnName: hit.asnName, source: 'urlscan.io' } });
    addEdge(hitId, asnId, 'asn');
  }
  for (const brand of hit.brands || []) {
    const brandId = `brand:${brand}`;
    addNode(brandId, { label: brand, type: 'brand', risk: 0, data: { brand, source: 'urlscan.io' } });
    addEdge(hitId, brandId, 'brand');
  }
}

function layoutNodes(baseNodes: Omit<GraphNode, 'x' | 'y'>[], edges: GraphEdge[]): GraphNode[] {
  const centerX = 600;
  const centerY = 360;
  const centerCandidates = baseNodes.filter(node => node.type === 'root' || node.type === 'brand').slice(0, 18);
  const rest = baseNodes.filter(node => !centerCandidates.includes(node));
  const ordered = [...centerCandidates, ...rest].slice(0, 240);
  const degree = new Map<string, number>();
  for (const edge of edges) {
    degree.set(edge.from, (degree.get(edge.from) || 0) + 1);
    degree.set(edge.to, (degree.get(edge.to) || 0) + 1);
  }

  return ordered.map((node, index) => {
    const ring = index < centerCandidates.length ? 0 : Math.floor((index - centerCandidates.length) / 54) + 1;
    const ringIndex = index < centerCandidates.length ? index : (index - centerCandidates.length) % 54;
    const ringSize = index < centerCandidates.length ? Math.max(centerCandidates.length, 1) : 54;
    const radius = index < centerCandidates.length ? 92 + centerCandidates.length * 3 : 190 + ring * 105;
    const angle = (Math.PI * 2 * ringIndex) / ringSize - Math.PI / 2;
    const pull = Math.min((degree.get(node.id) || 0) * 3, 42);
    return {
      ...node,
      x: centerX + Math.cos(angle) * Math.max(46, radius - pull),
      y: centerY + Math.sin(angle) * Math.max(46, radius - pull),
    };
  });
}

function connectedNodeIds(nodeId: string, edges: GraphEdge[]): Set<string> {
  const ids = new Set<string>();
  if (!nodeId) return ids;
  for (const edge of edges) {
    if (edge.from === nodeId) ids.add(edge.to);
    if (edge.to === nodeId) ids.add(edge.from);
  }
  return ids;
}

function buildOracleIntel(nodes: GraphNode[], edges: GraphEdge[], pivots: URLScanPivotResponse[]): OracleIntel {
  const degree = new Map<string, number>();
  for (const edge of edges) {
    degree.set(edge.from, (degree.get(edge.from) || 0) + 1);
    degree.set(edge.to, (degree.get(edge.to) || 0) + 1);
  }

  const maliciousHits = nodes.filter(node => node.type === 'urlscan' && node.risk >= 80).length;
  const suspiciousHits = nodes.filter(node => node.type === 'urlscan' && node.risk >= 55 && node.risk < 80).length;
  const brandNodes = nodes.filter(node => node.type === 'brand').length;
  const sharedInfra = nodes.filter(node => (node.type === 'ip' || node.type === 'asn') && (degree.get(node.id) || 0) >= 3).length;
  const maxRisk = Math.max(0, ...nodes.map(node => node.risk));
  const density = nodes.length > 0 ? Math.round((edges.length / nodes.length) * 10) : 0;
  const score = clamp(maxRisk + maliciousHits * 6 + suspiciousHits * 3 + sharedInfra * 5 + Math.min(density, 20), 0, 100);

  const threatLevel = score >= 85 ? 'SEVERE' : score >= 65 ? 'ELEVATED' : score >= 40 ? 'WATCH' : 'LOW';
  const priority = [...nodes]
    .map(node => ({ node, rank: node.risk + (degree.get(node.id) || 0) * 4 + typeWeight(node.type) }))
    .sort((a, b) => b.rank - a.rank)
    .map(item => item.node)
    .slice(0, 14);

  const anomalies: string[] = [];
  if (maliciousHits > 0) anomalies.push(`${maliciousHits} malicious URLScan hit${maliciousHits === 1 ? '' : 's'} connected`);
  if (suspiciousHits > 0) anomalies.push(`${suspiciousHits} suspicious URLScan observation${suspiciousHits === 1 ? '' : 's'}`);
  if (sharedInfra > 0) anomalies.push(`${sharedInfra} shared infrastructure hub${sharedInfra === 1 ? '' : 's'}`);
  if (brandNodes > 0) anomalies.push(`${brandNodes} brand impersonation cluster${brandNodes === 1 ? '' : 's'}`);
  if (pivots.length === 0) anomalies.push('URLScan enrichment not loaded yet');
  if (anomalies.length === 0) anomalies.push('No high-signal anomalies in current graph');

  return {
    threatLevel,
    score,
    brief: buildOracleBrief(threatLevel, nodes.length, edges.length, maliciousHits, sharedInfra),
    stats: [
      { label: 'SCORE', value: score, tone: riskTone(score) },
      { label: 'MAL', value: maliciousHits, tone: 'var(--red)' },
      { label: 'SUS', value: suspiciousHits, tone: 'var(--amber)' },
      { label: 'HUBS', value: sharedInfra, tone: 'var(--blue)' },
      { label: 'BRANDS', value: brandNodes, tone: 'var(--purple)' },
    ],
    priority,
    anomalies,
  };
}

function typeWeight(type: GraphNodeType): number {
  if (type === 'urlscan') return 18;
  if (type === 'brand') return 14;
  if (type === 'ip' || type === 'asn') return 12;
  if (type === 'scan') return 8;
  return 5;
}

function buildOracleBrief(level: string, nodes: number, edges: number, malicious: number, hubs: number): string {
  if (level === 'SEVERE') {
    return `High-confidence campaign shape detected across ${nodes} entities and ${edges} links. Prioritize malicious URLScan hits and shared infrastructure hubs.`;
  }
  if (level === 'ELEVATED') {
    return `Multiple suspicious relationships detected. ${malicious} malicious hits and ${hubs} infrastructure hubs should be reviewed first.`;
  }
  if (level === 'WATCH') {
    return 'Graph has meaningful signal. Review brand and IP relationships before widening the pivot window.';
  }
  return 'Graph is stable with low current signal. Run PIVOT LIVE to enrich with URLScan observations.';
}

function oracleNodeBrief(node: GraphNode, neighborCount: number): string {
  if (node.type === 'urlscan') {
    return node.risk >= 80
      ? `URLScan marks this as high-risk. It has ${neighborCount} direct relationship${neighborCount === 1 ? '' : 's'} worth tracing.`
      : `URLScan observation connected to ${neighborCount} related entit${neighborCount === 1 ? 'y' : 'ies'}.`;
  }
  if (node.type === 'ip' || node.type === 'asn') {
    return 'Infrastructure node. Shared hosting, ASN overlap, or repeated relationships may indicate campaign reuse.';
  }
  if (node.type === 'brand') {
    return 'Brand signal. Check attached domains for impersonation language, login pages, and redirects.';
  }
  if (node.type === 'scan') {
    return 'Live scan result with local evidence. Compare screenshot, title, IP, and URLScan neighbors.';
  }
  return 'Root entity. Use connected subdomains and URLScan hits to map the campaign boundary.';
}

function visibleNodeIds(
  nodes: GraphNode[],
  query: string,
  types: Record<GraphNodeType, boolean>,
  selectedId?: string,
): Set<string> {
  const normalized = query.trim().toLowerCase();
  const ids = new Set<string>();
  for (const node of nodes) {
    if (!types[node.type] && node.id !== selectedId) continue;
    if (normalized && !nodeMatches(node, normalized) && node.id !== selectedId) continue;
    ids.add(node.id);
  }
  return ids;
}

function nodeMatches(node: GraphNode, query: string): boolean {
  if (node.label.toLowerCase().includes(query) || node.id.toLowerCase().includes(query)) return true;
  return Object.values(node.data).some(value => {
    if (value == null) return false;
    const text = typeof value === 'string' ? value : JSON.stringify(value);
    return text.toLowerCase().includes(query);
  });
}

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

function nodeRadius(node: GraphNode): number {
  if (node.type === 'root') return 14;
  if (node.type === 'urlscan') return 11;
  if (node.type === 'scan') return 10;
  return 9;
}

function nodeColor(type: GraphNodeType): string {
  if (type === 'scan') return 'var(--green)';
  if (type === 'urlscan') return 'var(--blue)';
  if (type === 'ip' || type === 'asn') return 'var(--amber)';
  if (type === 'brand') return 'var(--purple)';
  return 'var(--text-sec)';
}

function riskTone(risk: number): string {
  if (risk >= 80) return 'var(--red)';
  if (risk >= 55) return '#ff6d00';
  if (risk >= 30) return 'var(--amber)';
  return 'var(--green)';
}

function shortLabel(value: string, max: number): string {
  const text = String(value || '');
  return text.length > max ? `${text.slice(0, max - 1)}...` : text;
}

function safeArray<T>(value: T[] | null | undefined): T[] {
  return Array.isArray(value) ? value : [];
}
