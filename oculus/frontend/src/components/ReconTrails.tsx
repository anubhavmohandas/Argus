import { useEffect, useMemo, useRef, useState, type ChangeEvent } from 'react';
import type { ReconTrailsResponse, ReconTrailsSubdomain } from '../types';

const API_BASE = import.meta.env.VITE_API_URL || '';

interface ReconTrailsProps {
  onClose: () => void;
  onDeepPivot: (seeds: string[]) => void;
  initialSeeds?: string[];
}

type TrailsTab = 'subdomains' | 'screens' | 'dns' | 'certs' | 'urls' | 'neighbors';

export function ReconTrails({ onClose, onDeepPivot, initialSeeds = [] }: ReconTrailsProps) {
  const [input, setInput] = useState(safeArray(initialSeeds).join('\n'));
  const [days, setDays] = useState(30);
  const [size, setSize] = useState(80);
  const [tab, setTab] = useState<TrailsTab>('subdomains');
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState('');
  const [error, setError] = useState('');
  const [data, setData] = useState<ReconTrailsResponse | null>(null);
  const [selected, setSelected] = useState<ReconTrailsSubdomain | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const parsed = useMemo(() => parseSeeds(input), [input]);

  useEffect(() => {
    if (safeArray(initialSeeds).length > 0) {
      setInput(uniqueStrings(safeArray(initialSeeds)).join('\n'));
    }
  }, [safeArray(initialSeeds).join('|')]);

  const run = async () => {
    if (parsed.unique.length === 0 || loading) return;
    setLoading(true);
    setError('');
    setProgress('querying DNS, RDAP, CT logs, Wayback, and URLScan...');
    setSelected(null);
    try {
      const res = await fetch(`${API_BASE}/api/recon-trails/domain`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domains: parsed.unique, days, size }),
      });
      setProgress('normalizing relationships and screenshots...');
      const payload = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(payload.error || `ReconTrails failed with ${res.status}`);
      const normalized = normalizeReconTrails(payload);
      setData(normalized);
      setInput(safeArray(normalized.domains).join('\n'));
      setTab('subdomains');
      setProgress('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'ReconTrails failed');
    } finally {
      setLoading(false);
    }
  };

  const handleImport = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = ev => {
      const imported = parseSeeds(String(ev.target?.result || '')).unique;
      if (imported.length) setInput(prev => uniqueStrings([...parseSeeds(prev).unique, ...imported]).join('\n'));
    };
    reader.readAsText(file);
    event.target.value = '';
  };

  const pasteClipboard = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) setInput(prev => uniqueStrings([...parseSeeds(prev).unique, ...parseSeeds(text).unique]).join('\n'));
    } catch {
      setError('Clipboard read was blocked by the browser.');
    }
  };

  const dedupeInput = () => setInput(parsed.unique.join('\n'));
  const exportJSON = () => data && downloadText(`reconvision_recontrails_${safeName(safeArray(data.domains).join('_'))}.json`, JSON.stringify(data, null, 2), 'application/json');
  const exportTXT = () => data && downloadText(`reconvision_recontrails_${safeName(safeArray(data.domains).join('_'))}.txt`, buildTXT(data), 'text/plain');
  const exportCSV = () => data && downloadText(`reconvision_recontrails_${safeName(safeArray(data.domains).join('_'))}.csv`, buildCSV(data), 'text/csv');
  const exportSTIX = () => data && downloadText(`reconvision_recontrails_${safeName(safeArray(data.domains).join('_'))}.stix.json`, JSON.stringify(buildSTIX(data), null, 2), 'application/json');
  const pivotAll = () => onDeepPivot(uniqueStrings(safeArray(data?.subdomains).map(item => item.domain)).slice(0, 12));

  return (
    <div className="recontrails-overlay">
      <div className="recontrails-shell">
        <header className="recontrails-head">
          <div>
            <span>PUBLIC DOMAIN INTELLIGENCE</span>
            <h1>RECONTRAILS</h1>
            <p>SecurityTrails-style domain profile built from public sources: DNS, RDAP, CT logs, Wayback, URLScan screenshots, observed IP neighbors, exports, and connected pivots.</p>
          </div>
          <div className="recontrails-actions">
            <button onClick={() => fileRef.current?.click()}>IMPORT</button>
            <input ref={fileRef} type="file" accept=".txt,.csv" onChange={handleImport} className="hidden" />
            <button onClick={exportCSV} disabled={!data}>CSV</button>
            <button onClick={exportTXT} disabled={!data}>TXT</button>
            <button onClick={exportJSON} disabled={!data}>JSON</button>
            <button onClick={exportSTIX} disabled={!data}>STIX</button>
            <button onClick={onClose}>CLOSE</button>
          </div>
        </header>

        <section className="recontrails-controls">
          <textarea value={input} onChange={event => setInput(event.target.value)} placeholder="paypal.com&#10;example.com&#10;target.tld" />
          <select value={days} onChange={event => setDays(Number(event.target.value))}>
            <option value={7}>7d</option>
            <option value={30}>30d</option>
            <option value={90}>90d</option>
            <option value={365}>1y</option>
          </select>
          <select value={size} onChange={event => setSize(Number(event.target.value))}>
            <option value={30}>30</option>
            <option value={80}>80</option>
          </select>
          <button onClick={pasteClipboard}>PASTE</button>
          <button onClick={dedupeInput} disabled={parsed.raw === 0}>DE-DUP</button>
          <button className="recontrails-run" onClick={run} disabled={loading || parsed.unique.length === 0}>
            {loading ? 'RUNNING' : `SEARCH (${parsed.unique.length})`}
          </button>
        </section>

        <div className="recontrails-import-status">
          imported {parsed.raw.toLocaleString()} / unique {parsed.unique.length.toLocaleString()} / duplicates {parsed.duplicates.toLocaleString()}
        </div>

        {loading && <div className="recontrails-progress"><span>{progress || 'working...'}</span><b /></div>}
        {error && <div className="recontrails-error">{error}</div>}

        <section className="recontrails-metrics">
          <TrailMetric label="DOMAINS" value={data?.summary.domainCount || 0} />
          <TrailMetric label="SUBDOMAINS" value={data?.summary.subdomainCount || 0} />
          <TrailMetric label="DNS" value={data?.summary.dnsCount || 0} />
          <TrailMetric label="CERTS" value={data?.summary.certificateCount || 0} />
          <TrailMetric label="SCREENSHOTS" value={data?.summary.screenshotCount || 0} />
          <TrailMetric label="IP NEIGHBORS" value={data?.summary.ipNeighborCount || 0} />
        </section>

        <section className="recontrails-body">
          <main className="recontrails-main">
            <nav className="recontrails-tabs">
              {(['subdomains', 'screens', 'dns', 'certs', 'urls', 'neighbors'] as TrailsTab[]).map(item => (
                <button key={item} className={tab === item ? 'active' : ''} onClick={() => setTab(item)}>{item.toUpperCase()}</button>
              ))}
              <button onClick={pivotAll} disabled={!safeArray(data?.subdomains).length}>DICT PIVOT ALL</button>
            </nav>

            {!data && !loading && <div className="recontrails-empty">Import or paste domains, de-dup, then run ReconTrails to build the domain intelligence profile.</div>}
            {data && tab === 'subdomains' && <SubdomainTable data={data} selected={selected} onSelect={setSelected} onDeepPivot={onDeepPivot} />}
            {data && tab === 'screens' && <ScreenshotGrid data={data} onSelect={setSelected} />}
            {data && tab === 'dns' && <RecordTable rows={safeArray(data.dns).map(record => [record.name, record.type, record.value, record.source])} head={['Name', 'Type', 'Value', 'Source']} />}
            {data && tab === 'certs' && <RecordTable rows={safeArray(data.certificates).map(cert => [cert.domain, cert.issuer || '-', cert.notBefore || '-', cert.notAfter || '-'])} head={['Domain', 'Issuer', 'Not Before', 'Not After']} />}
            {data && tab === 'urls' && <RecordTable rows={safeArray(data.urls).map(item => [item.status || '-', item.mimeType || '-', item.timestamp || '-', item.url])} head={['Status', 'Mime', 'Timestamp', 'URL']} />}
            {data && tab === 'neighbors' && <RecordTable rows={safeArray(data.ipNeighbors).map(item => [item.ip, item.asn || '-', String(item.count), safeArray(item.domains).slice(0, 8).join(', ')])} head={['IP', 'ASN', 'Domains', 'Observed Hosts']} />}
          </main>

          <aside className="recontrails-detail">
            {selected ? (
              <TrailDetail item={selected} onDeepPivot={onDeepPivot} />
            ) : data ? (
              <TrailOverview data={data} onDeepPivot={onDeepPivot} />
            ) : (
              <div className="recontrails-empty compact">Selected domains and pivots will appear here.</div>
            )}
          </aside>
        </section>
      </div>
    </div>
  );
}

function TrailMetric({ label, value }: { label: string; value: number }) {
  return <div className="recontrails-metric"><span>{label}</span><strong>{value.toLocaleString()}</strong></div>;
}

function SubdomainTable({ data, selected, onSelect, onDeepPivot }: { data: ReconTrailsResponse; selected: ReconTrailsSubdomain | null; onSelect: (item: ReconTrailsSubdomain) => void; onDeepPivot: (seeds: string[]) => void }) {
  const rows = safeArray(data.subdomains);
  if (!rows.length) return <div className="recontrails-empty">No subdomains survived de-duplication from public sources.</div>;
  return (
    <div className="recontrails-table vertical">
      <div className="recontrails-row head">
        <span>Domain Name</span><span>Keyword</span><span>Indicator</span><span>Status Code</span><span>Brand</span><span>Dict Pivot</span>
      </div>
      {rows.map((row, index) => (
        <button key={`${row.domain}-${index}`} className={`recontrails-row ${selected?.domain === row.domain ? 'selected' : ''}`} onClick={() => onSelect(row)}>
          <span title={row.domain}>{row.domain}</span>
          <span title={safeArray(row.signals).join(', ')}>{firstOf(row.signals, row.sources, '-')}</span>
          <span>{row.ip || row.asn || row.root || '-'}</span>
          <span>{row.screenshot || row.result ? 'observed' : '-'}</span>
          <span>{guessBrand(row.domain, row.title)}</span>
          <span onClick={event => event.stopPropagation()}>
            <button onClick={() => onDeepPivot([row.domain])}>PIVOT</button>
          </span>
        </button>
      ))}
    </div>
  );
}

function ScreenshotGrid({ data, onSelect }: { data: ReconTrailsResponse; onSelect: (item: ReconTrailsSubdomain | null) => void }) {
  const screens = safeArray(data.screens);
  if (!screens.length) return <div className="recontrails-empty">No URLScan screenshots returned for this domain set.</div>;
  return (
    <div className="recontrails-screen-grid">
      {screens.map((screen, index) => (
        <button key={`${screen.screenshot}-${index}`} onClick={() => onSelect(safeArray(data.subdomains).find(item => item.domain === screen.domain) || null)}>
          <img src={screen.screenshot} alt={screen.domain || screen.title || 'screenshot'} loading="lazy" />
          <span>{screen.domain || screen.title || 'screenshot'}</span>
        </button>
      ))}
    </div>
  );
}

function RecordTable({ head, rows }: { head: string[]; rows: string[][] }) {
  if (!rows.length) return <div className="recontrails-empty">No records in this view.</div>;
  return (
    <div className="recontrails-table records">
      <div className="recontrails-record head">{head.map(label => <span key={label}>{label}</span>)}</div>
      {rows.map((row, index) => (
        <div className="recontrails-record" key={`${row.join('|')}-${index}`}>
          {row.map((cell, cellIndex) => <span key={`${cellIndex}-${cell}`} title={cell}>{cell || '-'}</span>)}
        </div>
      ))}
    </div>
  );
}

function TrailDetail({ item, onDeepPivot }: { item: ReconTrailsSubdomain; onDeepPivot: (seeds: string[]) => void }) {
  return (
    <div className="recontrails-card-detail">
      {item.screenshot && <img src={item.screenshot} alt={item.domain} />}
      <h2>{item.domain}</h2>
      <p>{item.title || item.url || item.root}</p>
      <div className="recontrails-button-row">
        {item.result && <a href={item.result} target="_blank" rel="noopener noreferrer">URLSCAN</a>}
        {item.url && <a href={item.url} target="_blank" rel="noopener noreferrer">LIVE URL</a>}
        <button onClick={() => navigator.clipboard.writeText(item.domain).catch(() => {})}>COPY</button>
        <button onClick={() => onDeepPivot([item.domain])}>DEEP PIVOT</button>
      </div>
      <TrailKV label="Root" value={item.root} />
      <TrailKV label="IP" value={item.ip} />
      <TrailKV label="ASN" value={`${item.asn || ''} ${item.asnName || ''}`.trim()} />
      <TrailKV label="Country" value={item.country} />
      <TrailKV label="Sources" value={safeArray(item.sources).join(', ')} />
      <div className="recontrails-chips">{safeArray(item.signals).slice(0, 12).map(signal => <span key={signal}>{signal}</span>)}</div>
    </div>
  );
}

function TrailOverview({ data, onDeepPivot }: { data: ReconTrailsResponse; onDeepPivot: (seeds: string[]) => void }) {
  return (
    <div className="recontrails-card-detail">
      <h2>{safeArray(data.domains).join(', ')}</h2>
      <p>ReconTrails connected public DNS, certificates, archive URLs, URLScan screenshots, and observed IP neighbors.</p>
      <TrailKV label="Registrar" value={data.rdap?.registrar} />
      <TrailKV label="Created" value={data.rdap?.created} />
      <TrailKV label="Updated" value={data.rdap?.updated} />
      <TrailKV label="Generated" value={data.generated} />
      <div className="recontrails-section">
        <h3>Source Health</h3>
        {safeArray(data.sources).slice(0, 12).map(source => (
          <div className="recontrails-source" key={source.name}><b>{source.name}</b><span>{source.status}</span><strong>{source.count}</strong></div>
        ))}
      </div>
      <div className="recontrails-section">
        <h3>Next Pivots</h3>
        <div className="recontrails-chips">
          {safeArray(data.nextPivots).slice(0, 12).map(next => <button key={`${next.type}:${next.value}`} onClick={() => onDeepPivot([next.value])}>{next.type}:{short(next.value, 20)}</button>)}
        </div>
      </div>
      {!!safeArray(data.errors).length && <div className="recontrails-warning">{safeArray(data.errors).slice(0, 5).join('\n')}</div>}
    </div>
  );
}

function TrailKV({ label, value }: { label: string; value?: string }) {
  if (!value) return null;
  return <div className="recontrails-kv"><span>{label}</span><b>{value}</b></div>;
}

function parseSeeds(value: string): { raw: number; unique: string[]; duplicates: number } {
  const seen = new Set<string>();
  const unique: string[] = [];
  let raw = 0;
  for (const token of String(value || '').split(/[\n\r,;\t ]+/)) {
    const clean = normalizeDomain(token);
    if (!clean) continue;
    raw += 1;
    if (seen.has(clean)) continue;
    seen.add(clean);
    unique.push(clean);
  }
  return { raw, unique: unique.slice(0, 12), duplicates: Math.max(0, raw - unique.length) };
}

function normalizeDomain(value: string): string {
  let clean = String(value || '').trim().toLowerCase().replace(/^['"`<({\[]+|['"`>)}\]]+$/g, '');
  if (!clean) return '';
  try {
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(clean)) clean = new URL(clean).hostname;
  } catch {
    return '';
  }
  clean = clean.split('/')[0].split('?')[0].split('#')[0].replace(/:\d+$/, '').replace(/^\*\./, '').replace(/\.+$/, '');
  return clean.includes('.') ? clean : '';
}

function normalizeReconTrails(value: any): ReconTrailsResponse {
  return {
    domains: safeArray(value?.domains).map(String),
    generated: String(value?.generated || ''),
    summary: {
      domainCount: Number(value?.summary?.domainCount || 0),
      subdomainCount: Number(value?.summary?.subdomainCount || 0),
      dnsCount: Number(value?.summary?.dnsCount || 0),
      certificateCount: Number(value?.summary?.certificateCount || 0),
      urlCount: Number(value?.summary?.urlCount || 0),
      screenshotCount: Number(value?.summary?.screenshotCount || 0),
      ipNeighborCount: Number(value?.summary?.ipNeighborCount || 0),
      riskyAssetCount: Number(value?.summary?.riskyAssetCount || 0),
    },
    sources: safeArray(value?.sources),
    subdomains: safeArray(value?.subdomains).map((item: any) => ({
      domain: String(item?.domain || ''),
      root: String(item?.root || ''),
      ip: String(item?.ip || ''),
      asn: String(item?.asn || ''),
      asnName: String(item?.asnName || ''),
      country: String(item?.country || ''),
      title: String(item?.title || ''),
      url: String(item?.url || ''),
      screenshot: String(item?.screenshot || ''),
      result: String(item?.result || ''),
      sources: safeArray(item?.sources).map(String),
      signals: safeArray(item?.signals).map(String),
    })),
    dns: safeArray(value?.dns),
    certificates: safeArray(value?.certificates),
    rdap: { ...(value?.rdap || {}), nameservers: safeArray(value?.rdap?.nameservers), rawAvailable: Boolean(value?.rdap?.rawAvailable) },
    urls: safeArray(value?.urls),
    screens: safeArray(value?.screens),
    assets: safeArray(value?.assets),
    ipNeighbors: safeArray(value?.ipNeighbors),
    nextPivots: safeArray(value?.nextPivots),
    errors: safeArray(value?.errors).map(String),
    exports: {
      json: Boolean(value?.exports?.json),
      csv: Boolean(value?.exports?.csv),
      txt: Boolean(value?.exports?.txt),
      stix: Boolean(value?.exports?.stix),
    },
  };
}

function buildTXT(data: ReconTrailsResponse): string {
  return [
    `ReconVision ReconTrails: ${safeArray(data.domains).join(', ')}`,
    `Generated: ${data.generated}`,
    '',
    'Subdomains',
    ...safeArray(data.subdomains).map(item => `${item.domain}\t${item.ip || '-'}\t${safeArray(item.sources).join(',')}`),
    '',
    'IP neighbors',
    ...safeArray(data.ipNeighbors).map(item => `${item.ip}\t${item.count}\t${safeArray(item.domains).join(',')}`),
  ].join('\n');
}

function buildCSV(data: ReconTrailsResponse): string {
  const rows = [['domain', 'root', 'ip', 'asn', 'country', 'title', 'sources', 'url']];
  for (const item of safeArray(data.subdomains)) {
    rows.push([item.domain, item.root, item.ip, item.asn, item.country, item.title, safeArray(item.sources).join('|'), item.url]);
  }
  return rows.map(row => row.map(cell => `"${String(cell || '').replace(/"/g, '""')}"`).join(',')).join('\n');
}

function buildSTIX(data: ReconTrailsResponse) {
  const now = new Date().toISOString();
  const objects = safeArray(data.subdomains).slice(0, 100).map((item, index) => ({
    type: 'indicator',
    spec_version: '2.1',
    id: `indicator--${pseudoUUID(`${item.domain}-${index}`)}`,
    created: now,
    modified: now,
    name: item.domain,
    pattern: `[domain-name:value = '${item.domain.replace(/'/g, "\\'")}']`,
    pattern_type: 'stix',
    labels: ['recontrails', ...safeArray(item.sources).slice(0, 4)],
  }));
  return {
    type: 'bundle',
    id: `bundle--${pseudoUUID(safeArray(data.domains).join('-') || now)}`,
    objects,
  };
}

function pseudoUUID(seed: string): string {
  let hash = 0;
  for (let index = 0; index < seed.length; index += 1) hash = ((hash << 5) - hash + seed.charCodeAt(index)) | 0;
  const hex = Math.abs(hash).toString(16).padStart(12, '0').slice(0, 12);
  return `00000000-0000-4000-8000-${hex}`;
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
  return String(value || '').replace(/[^a-z0-9.-]+/gi, '_').slice(0, 80) || 'recontrails';
}

function short(value: string, max: number) {
  const text = String(value || '');
  return text.length > max ? `${text.slice(0, max - 1)}...` : text;
}

function firstOf(primary: string[] | undefined, fallback: string[] | undefined, empty: string): string {
  return safeArray(primary)[0] || safeArray(fallback)[0] || empty;
}

function guessBrand(domain: string, title: string): string {
  const text = `${domain} ${title}`.toLowerCase();
  for (const brand of ['paypal', 'netflix', 'openai', 'chatgpt', 'revolut', 'exness', 'binance']) {
    if (text.includes(brand)) return brand;
  }
  return '-';
}

function uniqueStrings(values: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const value of values) {
    const clean = String(value || '').trim();
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
