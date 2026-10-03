import { useEffect, useMemo, useRef, useState, type ChangeEvent, type ReactNode } from 'react';
import type { DeepPivotAsset, DeepPivotResponse, URLScanClusterItem, URLScanPivotIndicator } from '../types';

const API_BASE = import.meta.env.VITE_API_URL || '';

interface DeepPivotProps {
  onClose: () => void;
  initialSeeds?: string[];
}

type ViewMode = 'assets' | 'screens' | 'intel';

export function DeepPivot({ onClose, initialSeeds = [] }: DeepPivotProps) {
  const [indicator, setIndicator] = useState(safeArray(initialSeeds).join('\n'));
  const [type, setType] = useState('domain');
  const [days, setDays] = useState(30);
  const [size, setSize] = useState(40);
  const [mode, setMode] = useState<ViewMode>('assets');
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState('');
  const [error, setError] = useState('');
  const [data, setData] = useState<DeepPivotResponse | null>(null);
  const [selected, setSelected] = useState<DeepPivotAsset | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const seedCount = parsePivotSeeds(indicator).length;

  useEffect(() => {
    if (safeArray(initialSeeds).length > 0) {
      setIndicator(uniqueStrings(safeArray(initialSeeds)).join('\n'));
      setType('domain');
    }
  }, [safeArray(initialSeeds).join('|')]);

  const totals = useMemo(() => ({
    assets: data?.assets?.length || 0,
    screens: data?.screens?.length || 0,
    dns: data?.dns?.length || 0,
    certs: data?.certs?.length || 0,
    wayback: data?.wayback?.length || 0,
  }), [data]);

  const runPivot = async (next?: URLScanPivotIndicator) => {
    const pivotType = next?.type || type;
    const seeds = next ? [next.value] : parsePivotSeeds(indicator);
    const pivotValue = seeds[0] || '';
    if (!pivotValue.trim()) return;
    setLoading(true);
    setProgress('querying public sources...');
    setError('');
    setSelected(null);
    try {
      const res = await fetch(`${API_BASE}/api/deep-pivot`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: pivotType, indicator: pivotValue, seeds, days, size }),
      });
      setProgress('building asset graph...');
      const payload = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(payload.error || `Deep pivot failed with ${res.status}`);
      const normalized = normalizeDeepPivot(payload);
      setData(normalized);
      setIndicator(String(normalized.indicator || pivotValue).split(', ').join('\n'));
      setType(normalized.type || pivotType);
      setProgress('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Deep pivot failed');
    } finally {
      setLoading(false);
    }
  };

  const handleImport = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = ev => {
      const imported = parsePivotSeeds(String(ev.target?.result || ''));
      if (imported.length > 0) setIndicator(imported.join('\n'));
    };
    reader.readAsText(file);
    event.target.value = '';
  };

  const exportJSON = () => {
    if (!data) return;
    downloadText(`reconvision_deep_pivot_${safeName(data.indicator)}.json`, JSON.stringify(data, null, 2), 'application/json');
  };

  const exportTXT = () => {
    if (!data) return;
    const lines = [
      `ReconVision Deep Pivot: ${data.type}:${data.indicator}`,
      `Generated: ${data.generated}`,
      '',
      'Assets',
      ...safeArray(data.assets).map(asset => `${asset.domain}\t${asset.ip || '-'}\t${asset.source}\t${asset.url || '-'}`),
      '',
      'Next pivots',
      ...safeArray(data.nextPivots).map(p => `${p.type}\t${p.value}\t${p.count}`),
    ];
    downloadText(`reconvision_deep_pivot_${safeName(data.indicator)}.txt`, lines.join('\n'), 'text/plain');
  };

  return (
    <div className="deep-pivot-overlay">
      <div className="deep-pivot-shell">
        <header className="deep-pivot-head">
          <div>
            <div className="deep-eyebrow">PUBLIC OSINT PIVOT ENGINE</div>
            <h1>DEEP PIVOT</h1>
            <p>Correlates one or many domains across URLScan screenshots, certificate transparency, DNS, RDAP, and Wayback evidence.</p>
          </div>
          <div className="deep-actions">
            <button onClick={() => fileRef.current?.click()}>IMPORT</button>
            <input ref={fileRef} type="file" accept=".txt,.csv" onChange={handleImport} className="hidden" />
            <button onClick={exportTXT} disabled={!data}>TXT</button>
            <button onClick={exportJSON} disabled={!data}>JSON</button>
            <button onClick={onClose}>CLOSE</button>
          </div>
        </header>

        <section className="deep-controls">
          <select value={type} onChange={event => setType(event.target.value)}>
            <option value="domain">domain</option>
            <option value="ip">ip</option>
            <option value="asn">asn</option>
            <option value="brand">brand</option>
            <option value="hash">hash</option>
          </select>
          <textarea value={indicator} onChange={event => setIndicator(event.target.value)} placeholder="Single or multiple domains / URLs / IPs, one per line" />
          <select value={days} onChange={event => setDays(Number(event.target.value))}>
            <option value={7}>7d</option>
            <option value={30}>30d</option>
            <option value={90}>90d</option>
            <option value={365}>1y</option>
          </select>
          <select value={size} onChange={event => setSize(Number(event.target.value))}>
            <option value={20}>20</option>
            <option value={40}>40</option>
            <option value={80}>80</option>
          </select>
          <button className="deep-run" onClick={() => runPivot()} disabled={loading || !indicator.trim()}>
            {loading ? 'PIVOTING' : `RUN DEEP PIVOT${seedCount > 1 ? ` (${seedCount})` : ''}`}
          </button>
        </section>

        {loading && (
          <div className="deep-progress">
            <span>{progress || 'working...'}</span>
            <b />
          </div>
        )}
        {error && <div className="deep-error">{error}</div>}

        <section className="deep-metrics">
          <Metric label="ASSETS" value={totals.assets} />
          <Metric label="SCREENSHOTS" value={totals.screens} />
          <Metric label="DNS" value={totals.dns} />
          <Metric label="CERTS" value={totals.certs} />
          <Metric label="WAYBACK" value={totals.wayback} />
        </section>

        <section className="deep-body">
          <aside className="deep-left">
            <div className="deep-tabs">
              <button className={mode === 'assets' ? 'active' : ''} onClick={() => setMode('assets')}>ASSETS</button>
              <button className={mode === 'screens' ? 'active' : ''} onClick={() => setMode('screens')}>SCREENS</button>
              <button className={mode === 'intel' ? 'active' : ''} onClick={() => setMode('intel')}>INTEL</button>
            </div>

            {!data && !loading && (
              <div className="deep-empty">
                Start with one domain or paste many domains/URLs, one per line. Brand Watch and scan results can send domains here directly.
              </div>
            )}

            {data && mode === 'assets' && (
              <AssetTable assets={data.assets} selected={selected} onSelect={setSelected} />
            )}
            {data && mode === 'screens' && (
              <div className="deep-screen-grid">
                {safeArray(data.screens).map((screen, index) => (
                  <button key={`${screen.screenshot}-${index}`} onClick={() => setSelected(safeArray(data.assets).find(a => a.screenshot === screen.screenshot) || null)}>
                    <img src={screen.screenshot} alt={screen.domain} loading="lazy" />
                    <span>{screen.domain || screen.title || 'screenshot'}</span>
                  </button>
                ))}
              </div>
            )}
            {data && mode === 'intel' && <IntelPane data={data} onPivot={runPivot} />}
          </aside>

          <aside className="deep-right">
            {selected ? (
              <AssetDetail asset={selected} />
            ) : data ? (
              <PivotSummary data={data} onPivot={runPivot} />
            ) : (
              <div className="deep-empty compact">Select an asset after pivoting to inspect screenshot, URLScan result, DNS, and infrastructure evidence.</div>
            )}
          </aside>
        </section>
      </div>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div className="deep-metric">
      <span>{label}</span>
      <strong>{value.toLocaleString()}</strong>
    </div>
  );
}

function AssetTable({ assets, selected, onSelect }: { assets: DeepPivotAsset[]; selected: DeepPivotAsset | null; onSelect: (asset: DeepPivotAsset) => void }) {
  const safeAssets = safeArray(assets);
  if (!safeAssets.length) return <div className="deep-empty">No assets came back from the selected public sources.</div>;
  return (
    <div className="deep-table">
      <div className="deep-row head">
        <span>Domain</span><span>IP</span><span>ASN</span><span>Source</span><span>Evidence</span>
      </div>
      {safeAssets.map((asset, index) => (
        <button key={`${asset.domain}-${asset.url}-${index}`} className={`deep-row ${selected === asset ? 'selected' : ''}`} onClick={() => onSelect(asset)}>
          <span title={asset.domain}>{asset.domain || '-'}</span>
          <span>{asset.ip || '-'}</span>
          <span title={asset.asnName}>{asset.asn || '-'}</span>
          <span>{asset.source}</span>
          <span>{asset.screenshot ? 'screenshot' : asset.url ? 'url' : 'record'}</span>
        </button>
      ))}
    </div>
  );
}

function AssetDetail({ asset }: { asset: DeepPivotAsset }) {
  return (
    <div className="deep-detail">
      {asset.screenshot && <img src={asset.screenshot} alt={asset.domain} />}
      <h2>{asset.domain || 'Asset'}</h2>
      <p>{asset.title || asset.url || asset.source}</p>
      <div className="deep-button-row">
        {asset.result && <a href={asset.result} target="_blank" rel="noopener noreferrer">URLSCAN</a>}
        {asset.url && <a href={asset.url} target="_blank" rel="noopener noreferrer">LIVE URL</a>}
        <button onClick={() => navigator.clipboard.writeText(asset.url || asset.domain).catch(() => {})}>COPY</button>
      </div>
      <KV label="IP" value={asset.ip} />
      <KV label="ASN" value={`${asset.asn || ''} ${asset.asnName || ''}`.trim()} />
      <KV label="Country" value={asset.country} />
      <KV label="Source" value={asset.source} />
      <KV label="Time" value={asset.time} />
      {!!safeArray(asset.signals).length && (
        <div className="deep-chip-wrap">
          {safeArray(asset.signals).slice(0, 10).map(signal => <span key={signal}>{signal}</span>)}
        </div>
      )}
    </div>
  );
}

function IntelPane({ data, onPivot }: { data: DeepPivotResponse; onPivot: (next?: URLScanPivotIndicator) => void }) {
  return (
    <div className="deep-intel">
      <Section title="Source health">
        {safeArray(data.sources).map(source => (
          <div className="deep-source" key={source.name}>
            <b>{source.name}</b><span>{source.status}</span><strong>{source.count}</strong>
          </div>
        ))}
      </Section>
      <Section title="DNS">
        {safeArray(data.dns).slice(0, 30).map(record => <Line key={`${record.type}-${record.value}`} left={record.type} right={record.value} />)}
      </Section>
      <Section title="Certificates">
        {safeArray(data.certs).slice(0, 30).map(cert => <Line key={`${cert.domain}-${cert.notBefore}`} left={cert.domain} right={cert.issuer || cert.source} />)}
      </Section>
      <Section title="Wayback URLs">
        {safeArray(data.wayback).slice(0, 30).map(item => <Line key={item.url} left={item.status || '-'} right={item.url} />)}
      </Section>
      <Section title="Next pivots">
        <div className="deep-chip-wrap">
          {safeArray(data.nextPivots).map(next => <button key={`${next.type}:${next.value}`} onClick={() => onPivot(next)}>{next.type}:{short(next.value, 22)} ({next.count})</button>)}
        </div>
      </Section>
    </div>
  );
}

function PivotSummary({ data, onPivot }: { data: DeepPivotResponse; onPivot: (next?: URLScanPivotIndicator) => void }) {
  return (
    <div className="deep-detail">
      <h2>{data.indicator}</h2>
      <p>{data.type} pivot across {safeArray(data.sources).length} public sources.</p>
      <KV label="Registrar" value={data.rdap?.registrar} />
      <KV label="Created" value={data.rdap?.created} />
      <KV label="Updated" value={data.rdap?.updated} />
      <Cluster title="Domains" items={data.clusters.domains} />
      <Cluster title="IPs" items={data.clusters.ips} />
      <Cluster title="ASNs" items={data.clusters.asns} />
      <div className="deep-chip-wrap">
        {safeArray(data.nextPivots).slice(0, 12).map(next => <button key={`${next.type}:${next.value}`} onClick={() => onPivot(next)}>{next.type}:{short(next.value, 18)}</button>)}
      </div>
      {!!safeArray(data.errors).length && <div className="deep-warn">{safeArray(data.errors).slice(0, 4).join('\n')}</div>}
    </div>
  );
}

function Cluster({ title, items }: { title: string; items: URLScanClusterItem[] }) {
  const safeItems = safeArray(items);
  if (!safeItems.length) return null;
  return (
    <div className="deep-cluster">
      <h3>{title}</h3>
      {safeItems.slice(0, 8).map(item => <Line key={item.value} left={String(item.count)} right={item.value} />)}
    </div>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return <div className="deep-section"><h3>{title}</h3>{children}</div>;
}

function Line({ left, right }: { left: string; right: string }) {
  return <div className="deep-line"><span>{left}</span><b title={right}>{right}</b></div>;
}

function KV({ label, value }: { label: string; value?: string }) {
  if (!value) return null;
  return <div className="deep-kv"><span>{label}</span><b>{value}</b></div>;
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

function safeName(value: string) {
  return String(value || '').replace(/[^a-z0-9.-]+/gi, '_').slice(0, 80) || 'pivot';
}

function short(value: string, max: number) {
  const text = String(value || '');
  return text.length > max ? `${text.slice(0, max - 1)}...` : text;
}

function parsePivotSeeds(value: string): string[] {
  return uniqueStrings(String(value || '').split(/[\n\r,;\t ]+/).map(item => item.trim()).filter(Boolean)).slice(0, 12);
}

function uniqueStrings(values: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const value of values) {
    const clean = value.trim();
    const key = clean.toLowerCase();
    if (!clean || seen.has(key)) continue;
    seen.add(key);
    out.push(clean);
  }
  return out;
}

function safeArray<T>(value: T[] | null | undefined): T[] {
  return Array.isArray(value) ? value : [];
}

function normalizeDeepPivot(value: any): DeepPivotResponse {
  return {
    indicator: String(value?.indicator || ''),
    type: String(value?.type || 'domain'),
    days: Number(value?.days || 30),
    sources: safeArray(value?.sources),
    assets: safeArray(value?.assets).map((asset: any) => ({
      domain: String(asset?.domain || ''),
      url: String(asset?.url || ''),
      title: String(asset?.title || ''),
      ip: String(asset?.ip || ''),
      asn: String(asset?.asn || ''),
      asnName: String(asset?.asnName || ''),
      country: String(asset?.country || ''),
      source: String(asset?.source || ''),
      screenshot: String(asset?.screenshot || ''),
      result: String(asset?.result || ''),
      time: String(asset?.time || ''),
      tags: safeArray(asset?.tags),
      signals: safeArray(asset?.signals),
    })),
    screens: safeArray(value?.screens),
    dns: safeArray(value?.dns),
    certs: safeArray(value?.certs),
    wayback: safeArray(value?.wayback),
    rdap: {
      ...(value?.rdap || {}),
      nameservers: safeArray(value?.rdap?.nameservers),
      rawAvailable: Boolean(value?.rdap?.rawAvailable),
    },
    clusters: {
      domains: safeArray(value?.clusters?.domains),
      ips: safeArray(value?.clusters?.ips),
      asns: safeArray(value?.clusters?.asns),
      sources: safeArray(value?.clusters?.sources),
    },
    nextPivots: safeArray(value?.nextPivots),
    errors: safeArray(value?.errors),
    generated: String(value?.generated || ''),
  };
}
