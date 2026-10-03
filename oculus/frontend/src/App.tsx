import { useMemo, useState, type CSSProperties, type PointerEvent } from 'react';
import { TopBar } from './components/TopBar';
import { FilterPanel } from './components/FilterPanel';
import { ResultGrid } from './components/ResultGrid';
import { MetadataPanel } from './components/MetadataPanel';
import { ScanProgress } from './components/ScanProgress';
import { CTIGraph } from './components/CTIGraph';
import { BrandLogoWatch } from './components/BrandLogoWatch';
import { DeepPivot } from './components/DeepPivot';
import { ReconTrails } from './components/ReconTrails';
import { OffsecBountyPanel } from './components/OffsecBountyPanel';
import { useScan } from './hooks/useScan';
import { useFilters } from './hooks/useFilters';
import type { ScanResult, ScanConfig, URLScanClusterItem, URLScanPivotResponse } from './types';

const API_BASE = import.meta.env.VITE_API_URL || '';

export default function App() {
  const { results, progress, isScanning, jobId, error, startScan, stopScan, clearResults } = useScan();
  const {
    filters, filtered, sortField, sortDir,
    updateFilter, resetFilters, toggleStatusCode, toggleKeyword,
    toggleRiskLevel, setSortField, setSortDir,
  } = useFilters(results);

  const [selected, setSelected] = useState<ScanResult | null>(null);
  const [showGraph, setShowGraph] = useState(false);
  const [showBrandWatch, setShowBrandWatch] = useState(false);
  const [showDeepPivot, setShowDeepPivot] = useState(false);
  const [showReconTrails, setShowReconTrails] = useState(false);
  const [showOffsecBounty, setShowOffsecBounty] = useState(false);
  const [deepPivotSeeds, setDeepPivotSeeds] = useState<string[]>([]);
  const [reconTrailsSeeds, setReconTrailsSeeds] = useState<string[]>([]);
  const [showCommandDeck, setShowCommandDeck] = useState(false);
  const [pivotEvidence, setPivotEvidence] = useState<URLScanPivotResponse[]>([]);
  const [bulkPivot, setBulkPivot] = useState<BulkPivotState>({
    running: false,
    done: 0,
    total: 0,
    hits: 0,
    domains: [],
    ips: [],
    brands: [],
    errors: [],
  });

  const livePivotTargets = useMemo(() => buildLivePivotTargets(results), [results]);

  const handlePointerMove = (event: PointerEvent<HTMLDivElement>) => {
    const x = Math.round((event.clientX / window.innerWidth) * 100);
    const y = Math.round((event.clientY / window.innerHeight) * 100);
    event.currentTarget.style.setProperty('--pointer-x', `${x}%`);
    event.currentTarget.style.setProperty('--pointer-y', `${y}%`);
    event.currentTarget.style.setProperty('--tilt-x', `${(y - 50) / -18}deg`);
    event.currentTarget.style.setProperty('--tilt-y', `${(x - 50) / 18}deg`);
  };

  const handleExport = async (format: string) => {
    if (!jobId) return;
    const url = `${API_BASE}/api/scan/${jobId}/export?format=${format}`;
    const a = document.createElement('a');
    a.href = url;
    a.download = `reconvision_${jobId}.${format}`;
    a.click();
  };

  const handleExportCurrent = (format: string) => {
    const content = formatScanResultsExport(filtered, format);
    const mime = format === 'json' ? 'application/json' : format === 'csv' ? 'text/csv' : 'text/plain';
    downloadText(`reconvision_current_${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.${format}`, content, mime);
  };

  const handlePivotLive = async () => {
    if (bulkPivot.running || livePivotTargets.length === 0) return;

    const domainCounts = new Map<string, number>();
    const ipCounts = new Map<string, number>();
    const brandCounts = new Map<string, number>();
    const errors: string[] = [];
    const pivotResponses: URLScanPivotResponse[] = [];
    let hits = 0;

    setBulkPivot({
      running: true,
      done: 0,
      total: livePivotTargets.length,
      hits: 0,
      domains: [],
      ips: [],
      brands: [],
      errors: [],
      active: livePivotTargets[0],
    });

    for (let index = 0; index < livePivotTargets.length; index += 1) {
      const target = livePivotTargets[index];
      setBulkPivot(prev => ({ ...prev, active: target }));

      try {
        const res = await fetch(`${API_BASE}/api/urlscan/pivot`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ type: 'domain', indicator: target, days: 30, size: 10 }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.error || `URLScan returned ${res.status}`);

        const pivot = data as URLScanPivotResponse;
        pivotResponses.push(pivot);
        setPivotEvidence([...pivotResponses]);
        hits += safeArray(pivot.results).length;
        mergeCounts(domainCounts, safeArray(pivot.clusters?.domains));
        mergeCounts(ipCounts, safeArray(pivot.clusters?.ips));
        mergeCounts(brandCounts, safeArray(pivot.clusters?.brands));
      } catch (err) {
        errors.push(`${target}: ${err instanceof Error ? err.message : 'pivot failed'}`);
      }

      setBulkPivot({
        running: index + 1 < livePivotTargets.length,
        done: index + 1,
        total: livePivotTargets.length,
        hits,
        domains: topItems(domainCounts, 12),
        ips: topItems(ipCounts, 10),
        brands: topItems(brandCounts, 10),
        errors: errors.slice(-5),
        active: index + 1 < livePivotTargets.length ? livePivotTargets[index + 1] : undefined,
      });
    }
  };

  return (
    <div
      className="app-shell flex flex-col h-screen overflow-hidden"
      onPointerMove={handlePointerMove}
      style={{ background: 'var(--bg-void)' } as CSSProperties}
    >
      <div className="ambient-depth depth-layer-a" />
      <div className="ambient-depth depth-layer-b" />
      <div className="ambient-depth depth-layer-c" />
      {/* Noise overlay */}
      <div className="noise-overlay" />

      {/* Top bar */}
      <TopBar
        isScanning={isScanning}
        jobId={jobId}
        resultCount={results.length}
        onStartScan={startScan}
        onStopScan={stopScan}
        onClear={() => { clearResults(); setSelected(null); setPivotEvidence([]); }}
        onExport={handleExport}
        onExportCurrent={handleExportCurrent}
        liveCount={livePivotTargets.length}
        isPivoting={bulkPivot.running}
        onPivotLive={handlePivotLive}
        onOpenGraph={() => setShowGraph(true)}
        onOpenBrandWatch={() => setShowBrandWatch(true)}
        onOpenDeepPivot={() => { setDeepPivotSeeds([]); setShowDeepPivot(true); }}
        onOpenReconTrails={() => { setReconTrailsSeeds([]); setShowReconTrails(true); }}
        onOpenOffsecBounty={() => setShowOffsecBounty(true)}
      />

      <BulkPivotPanel state={bulkPivot} onClose={() => setBulkPivot(prev => ({ ...prev, done: 0, total: 0, hits: 0, errors: [], active: undefined }))} />
      <AnalystCommandDeck
        visible={showCommandDeck}
        results={results}
        filtered={filtered}
        isPivoting={bulkPivot.running}
        onToggle={() => setShowCommandDeck(prev => !prev)}
        onOpenGraph={() => setShowGraph(true)}
        onPivotLive={handlePivotLive}
      />

      {/* Progress bar */}
      <ScanProgress progress={progress} isScanning={isScanning} />

      {/* Error banner */}
      {error && (
        <div className="px-4 py-2 text-xs flex items-center gap-2"
          style={{ background: 'rgba(255,23,68,0.1)', borderBottom: '1px solid rgba(255,23,68,0.3)', color: 'var(--red)' }}>
          <span>⚠</span>
          <span>{error}</span>
        </div>
      )}

      <div className="flex flex-1 overflow-hidden">
        <ModuleRail results={results} />

        {/* Filter panel */}
        <FilterPanel
          filters={filters}
          resultCount={results.length}
          filteredCount={filtered.length}
          sortField={sortField}
          sortDir={sortDir}
          onToggleStatus={toggleStatusCode}
          onToggleKeyword={toggleKeyword}
          onToggleRiskLevel={toggleRiskLevel}
          onUpdateFilter={updateFilter}
          onReset={resetFilters}
          onSortField={setSortField}
          onSortDir={setSortDir}
        />

        {/* Result grid */}
        <main className="workspace-main flex flex-1 flex-col overflow-hidden">
          <IntelSummary results={filtered} totalResults={results.length} />
          <ResultGrid
            results={filtered}
            selected={selected}
            isScanning={isScanning}
            onSelect={r => setSelected(prev => prev?.id === r.id ? null : r)}
          />
        </main>

        {/* Metadata detail panel */}
        <MetadataPanel
          result={selected}
          onClose={() => setSelected(null)}
          onDeepPivot={seeds => {
            setDeepPivotSeeds(seeds);
            setShowDeepPivot(true);
          }}
        />
      </div>

      {showGraph && (
        <CTIGraph
          results={results}
          pivots={pivotEvidence}
          onClose={() => setShowGraph(false)}
        />
      )}

      {showBrandWatch && (
        <BrandLogoWatch
          onClose={() => setShowBrandWatch(false)}
          onDeepPivot={seeds => {
            setDeepPivotSeeds(seeds);
            setShowDeepPivot(true);
          }}
        />
      )}

      {showDeepPivot && (
        <DeepPivot onClose={() => setShowDeepPivot(false)} initialSeeds={deepPivotSeeds} />
      )}

      {showReconTrails && (
        <ReconTrails
          onClose={() => setShowReconTrails(false)}
          initialSeeds={reconTrailsSeeds}
          onDeepPivot={seeds => {
            setDeepPivotSeeds(seeds);
            setShowDeepPivot(true);
          }}
        />
      )}

      {showOffsecBounty && (
        <OffsecBountyPanel
          results={filtered}
          onClose={() => setShowOffsecBounty(false)}
          onDeepPivot={seeds => {
            setDeepPivotSeeds(seeds);
            setShowDeepPivot(true);
          }}
          onReconTrails={seeds => {
            setReconTrailsSeeds(seeds);
            setShowReconTrails(true);
          }}
        />
      )}

      {/* Status bar */}
      <div
        className="flex items-center justify-between px-4 py-1"
        style={{ borderTop: '1px solid var(--border)', background: 'var(--bg-deep)' }}
      >
        <span className="text-xs" style={{ color: 'var(--text-dim)', fontSize: 10, letterSpacing: '0.08em' }}>
          RECONVISION - FOR AUTHORIZED SECURITY TESTING ONLY
        </span>
        <div className="flex items-center gap-4">
          <span className="text-xs" style={{ color: 'var(--text-dim)', fontSize: 10 }}>
            {filtered.length.toLocaleString()} results
          </span>
          {isScanning && (
            <span className="text-xs flex items-center gap-1" style={{ color: 'var(--green)', fontSize: 10 }}>
              <span className="pulse-dot inline-block w-1.5 h-1.5 rounded-full" style={{ background: 'var(--green)' }} />
              ACTIVE
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

function ModuleRail({ results }: { results: ScanResult[] }) {
  const risky = results.filter(r => (r.intelligence?.riskScore || 0) >= 45).length;
  const modules = [
    ['SCAN', 'SC'],
    ['PHISH', 'PH'],
    ['MYTHOS', 'MY'],
    ['EVIDENCE', 'EV'],
    ['EXPORT', 'EX'],
  ];
  return (
    <nav className="module-rail flex flex-col items-center py-3 gap-2" style={{ width: 72, minWidth: 72, background: 'var(--bg-deep)', borderRight: '1px solid var(--border)' }}>
      {modules.map(([label, icon], index) => (
        <button
          key={label}
          className="module-button flex flex-col items-center justify-center gap-1"
          style={{
            width: 58,
            height: 48,
            border: '1px solid',
            borderColor: index === 0 ? 'var(--green)' : 'var(--border-dim)',
            background: index === 0 ? 'rgba(0,230,118,0.08)' : 'transparent',
            color: index === 0 ? 'var(--green)' : 'var(--text-dim)',
            fontSize: 9,
            letterSpacing: '0.08em',
          }}
          title={label}
        >
          <span style={{ fontSize: 16, lineHeight: 1 }}>{icon}</span>
          <span>{label}</span>
        </button>
      ))}
      <div className="risk-orb mt-auto text-center px-1">
        <div style={{ color: risky > 0 ? 'var(--amber)' : 'var(--text-dim)', fontSize: 18, fontFamily: 'var(--font-ui)', fontWeight: 700 }}>{risky}</div>
        <div style={{ color: 'var(--text-dim)', fontSize: 9, letterSpacing: '0.08em' }}>RISKY</div>
      </div>
    </nav>
  );
}

function IntelSummary({ results, totalResults }: { results: ScanResult[]; totalResults: number }) {
  const stats = {
    critical: results.filter(r => r.intelligence?.riskLevel === 'critical').length,
    high: results.filter(r => r.intelligence?.riskLevel === 'high').length,
    phishing: results.filter(r => r.intelligence?.categories?.includes('phishing')).length,
    brand: results.filter(r => r.intelligence?.categories?.includes('brand')).length,
  };
  const avgRisk = results.length
    ? Math.round(results.reduce((sum, r) => sum + (r.intelligence?.riskScore || 0), 0) / results.length)
    : 0;

  return (
    <div className="intel-summary grid grid-cols-5 gap-px" style={{ background: 'var(--border-dim)', borderBottom: '1px solid var(--border)' }}>
      <IntelTile label="VISIBLE SET" value={`${results.length}/${totalResults}`} tone="var(--blue)" />
      <IntelTile label="AVG RISK" value={avgRisk} tone={avgRisk >= 45 ? 'var(--amber)' : 'var(--green)'} />
      <IntelTile label="CRITICAL" value={stats.critical} tone="var(--red)" />
      <IntelTile label="PHISH SIGNALS" value={stats.phishing} tone="var(--amber)" />
      <IntelTile label="BRAND CLUES" value={stats.brand} tone="var(--purple)" />
    </div>
  );
}

function IntelTile({ label, value, tone }: { label: string; value: string | number; tone: string }) {
  return (
    <div className="intel-tile px-3 py-2" style={{ background: 'var(--bg-panel)' }}>
      <div style={{ color: 'var(--text-dim)', fontSize: 9, letterSpacing: '0.12em' }}>{label}</div>
      <div style={{ color: tone, fontFamily: 'var(--font-ui)', fontWeight: 700, fontSize: 22, lineHeight: 1.1 }}>{value}</div>
      <div className="tile-depth-line" style={{ background: tone }} />
    </div>
  );
}

function AnalystCommandDeck({
  visible,
  results,
  filtered,
  isPivoting,
  onToggle,
  onOpenGraph,
  onPivotLive,
}: {
  visible: boolean;
  results: ScanResult[];
  filtered: ScanResult[];
  isPivoting: boolean;
  onToggle: () => void;
  onOpenGraph: () => void;
  onPivotLive: () => void;
}) {
  const live = results.filter(result => result.status > 0 && !result.error);
  const suspicious = results.filter(result =>
    (result.intelligence?.riskScore || 0) >= 45 ||
    result.intelligence?.categories?.includes('phishing') ||
    result.intelligence?.brandCandidate
  );
  const brands = new Set(results.map(result => result.intelligence?.brandCandidate).filter(Boolean));
  const ips = new Set(results.map(result => result.intelligence?.ipAddress).filter(Boolean));
  const critical = results.filter(result => result.intelligence?.riskLevel === 'critical').length;
  const brief = buildMissionBrief(results.length, live.length, suspicious.length, brands.size, ips.size);

  const copyLive = () => copyLines(live.map(result => result.url || result.domain));
  const copySuspicious = () => copyLines(suspicious.map(result => result.domain));
  const copyVisible = () => copyLines(filtered.map(result => `${result.status || 'ERR'} ${result.domain} ${result.title || ''}`.trim()));

  return (
    <>
      <button className="command-orb" onClick={onToggle} title="Open analyst command deck">
        <span>{visible ? 'CLOSE' : 'OPS'}</span>
        <strong>{suspicious.length}</strong>
      </button>
      {visible && (
        <div className="command-deck">
          <div className="command-deck-header">
            <div>
              <span>RECONVISION COMMAND DECK</span>
              <strong>{brief.title}</strong>
            </div>
            <button onClick={onToggle}>X</button>
          </div>
          <p>{brief.body}</p>
          <div className="command-metrics">
            <CommandMetric label="LIVE" value={live.length} tone="var(--green)" />
            <CommandMetric label="SUSPICIOUS" value={suspicious.length} tone="var(--amber)" />
            <CommandMetric label="CRITICAL" value={critical} tone="var(--red)" />
            <CommandMetric label="BRANDS" value={brands.size} tone="var(--purple)" />
            <CommandMetric label="IPS" value={ips.size} tone="var(--blue)" />
          </div>
          <div className="command-actions">
            <button onClick={copyLive}>COPY LIVE URLS</button>
            <button onClick={copySuspicious}>COPY SUSPICIOUS</button>
            <button onClick={copyVisible}>COPY VISIBLE SET</button>
            <button onClick={onOpenGraph}>OPEN CTI GRAPH</button>
            <button onClick={onPivotLive} disabled={isPivoting || live.length === 0}>
              {isPivoting ? 'PIVOTING...' : 'PIVOT LIVE'}
            </button>
          </div>
          <div className="signal-lanes">
            <span style={{ '--lane-tone': 'var(--green)' } as CSSProperties} />
            <span style={{ '--lane-tone': 'var(--blue)' } as CSSProperties} />
            <span style={{ '--lane-tone': 'var(--purple)' } as CSSProperties} />
          </div>
        </div>
      )}
    </>
  );
}

function CommandMetric({ label, value, tone }: { label: string; value: number; tone: string }) {
  return (
    <div className="command-metric" style={{ '--metric-tone': tone } as CSSProperties}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function copyLines(lines: string[]) {
  navigator.clipboard.writeText(lines.filter(Boolean).join('\n')).catch(() => {});
}

function buildMissionBrief(total: number, live: number, suspicious: number, brands: number, ips: number) {
  if (total === 0) {
    return { title: 'NO ACTIVE DATASET', body: 'Load targets and run a scan to initialize the analyst command layer.' };
  }
  if (suspicious > 0) {
    return {
      title: 'SIGNAL DETECTED',
      body: `${suspicious} suspicious assets across ${live} live hosts. ${brands} brand signals and ${ips} IP clusters are ready for graph review.`,
    };
  }
  return {
    title: 'BASELINE MONITORING',
    body: `${live} live hosts from ${total} results. No high-risk local indicators yet; URLScan pivot can enrich the campaign map.`,
  };
}

interface BulkPivotState {
  running: boolean;
  done: number;
  total: number;
  hits: number;
  domains: URLScanClusterItem[];
  ips: URLScanClusterItem[];
  brands: URLScanClusterItem[];
  errors: string[];
  active?: string;
}

function BulkPivotPanel({ state, onClose }: { state: BulkPivotState; onClose: () => void }) {
  if (state.total === 0 && !state.running) return null;
  const progress = state.total > 0 ? Math.round((state.done / state.total) * 100) : 0;

  return (
    <div className="bulk-pivot-strip">
      <div className="bulk-pivot-head">
        <div>
          <div className="bulk-pivot-title">URLSCAN LIVE PIVOT</div>
          <div className="bulk-pivot-sub">
            {state.running ? `pivoting ${state.active || 'live domains'}` : 'campaign pivot complete'}
          </div>
        </div>
        <div className="bulk-pivot-actions">
          <span>{state.done}/{state.total}</span>
          <span>{state.hits} hits</span>
          {!state.running && <button onClick={onClose}>HIDE</button>}
        </div>
      </div>
      <div className="bulk-pivot-track">
        <div className="bulk-pivot-fill" style={{ width: `${progress}%` }} />
      </div>
      <div className="bulk-pivot-grid">
        <BulkPivotGroup label="RELATED DOMAINS" items={state.domains} />
        <BulkPivotGroup label="RELATED IPS" items={state.ips} />
        <BulkPivotGroup label="BRANDS" items={state.brands} />
        {state.errors.length > 0 && (
          <div className="bulk-pivot-errors">
            <span>ERRORS</span>
            {state.errors.map(error => <small key={error}>{error}</small>)}
          </div>
        )}
      </div>
    </div>
  );
}

function BulkPivotGroup({ label, items }: { label: string; items: URLScanClusterItem[] }) {
  return (
    <div className="bulk-pivot-group">
      <span>{label}</span>
      <div>
        {items.length === 0
          ? <small>-</small>
          : items.slice(0, 8).map(item => (
            <button
              key={item.value}
              onClick={() => navigator.clipboard.writeText(item.value).catch(() => {})}
              title="Click to copy"
            >
              {shortPivotValue(item.value, 24)} <b>{item.count}</b>
            </button>
          ))}
      </div>
    </div>
  );
}

function buildLivePivotTargets(results: ScanResult[]): string[] {
  const targets = new Set<string>();
  for (const result of results) {
    if (result.status <= 0 || result.error) continue;
    const root = result.intelligence?.rootDomain || result.domain;
    const clean = root.trim().toLowerCase();
    if (clean && clean !== '-') targets.add(clean);
  }
  return Array.from(targets).slice(0, 100);
}

function mergeCounts(target: Map<string, number>, items: URLScanClusterItem[]) {
  for (const item of items || []) {
    if (!item.value) continue;
    target.set(item.value, (target.get(item.value) || 0) + item.count);
  }
}

function topItems(source: Map<string, number>, limit: number): URLScanClusterItem[] {
  return Array.from(source.entries())
    .map(([value, count]) => ({ value, count }))
    .sort((a, b) => b.count - a.count || a.value.localeCompare(b.value))
    .slice(0, limit);
}

function shortPivotValue(value: string, max: number): string {
  const text = String(value || '');
  return text.length > max ? `${text.slice(0, max - 1)}...` : text;
}

function safeArray<T>(value: T[] | null | undefined): T[] {
  return Array.isArray(value) ? value : [];
}

function formatScanResultsExport(results: ScanResult[], format: string): string {
  const safeResults = safeArray(results);
  if (format === 'json') {
    return JSON.stringify(safeResults, null, 2);
  }
  if (format === 'csv') {
    const rows = [
      ['domain', 'url', 'status', 'title', 'server', 'ip', 'root', 'brand', 'riskScore', 'riskLevel', 'tls', 'durationMs', 'timestamp', 'keywords', 'indicators'],
      ...safeResults.map(result => [
        result.domain,
        result.url,
        String(result.status || ''),
        result.title,
        result.server,
        result.intelligence?.ipAddress || '',
        result.intelligence?.rootDomain || '',
        result.intelligence?.brandCandidate || '',
        String(result.intelligence?.riskScore || 0),
        result.intelligence?.riskLevel || '',
        result.tls ? 'true' : 'false',
        String(result.durationMs || 0),
        result.timestamp,
        safeArray(result.keywords).join('|'),
        safeArray(result.intelligence?.indicators).join('|'),
      ]),
    ];
    return rows.map(row => row.map(cell => `"${String(cell || '').replace(/"/g, '""')}"`).join(',')).join('\n');
  }
  if (format === 'md') {
    return [
      '# ReconVision Current Results',
      '',
      `Generated: ${new Date().toISOString()}`,
      `Count: ${safeResults.length}`,
      '',
      '| Domain | Status | Risk | Brand | IP | Title |',
      '| --- | ---: | --- | --- | --- | --- |',
      ...safeResults.map(result => `| ${mdCell(result.domain)} | ${result.status || 'ERR'} | ${result.intelligence?.riskLevel || '-'} ${result.intelligence?.riskScore || 0} | ${mdCell(result.intelligence?.brandCandidate || '-')} | ${mdCell(result.intelligence?.ipAddress || '-')} | ${mdCell(result.title || '-')} |`),
    ].join('\n');
  }
  return safeResults.map(result => [
    result.domain,
    `  url: ${result.url || '-'}`,
    `  status: ${result.status || 'ERR'}`,
    `  title: ${result.title || '-'}`,
    `  ip: ${result.intelligence?.ipAddress || '-'}`,
    `  risk: ${result.intelligence?.riskLevel || '-'} ${result.intelligence?.riskScore || 0}`,
    `  brand: ${result.intelligence?.brandCandidate || '-'}`,
    `  indicators: ${safeArray(result.intelligence?.indicators).join('; ') || '-'}`,
  ].join('\n')).join('\n\n');
}

function mdCell(value: string): string {
  return String(value || '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
}

function downloadText(filename: string, text: string, type: string) {
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
