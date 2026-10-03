import { useEffect, useMemo, useRef, useState, type CSSProperties, type ChangeEvent } from 'react';
import type { BrandDomainAnalysis, BrandLogoHit, BrandWatchBrand, BrandWatchResponse } from '../types';

const API_BASE = import.meta.env.VITE_API_URL || '';
const BRAND_STORAGE_KEY = 'reconvision.brandLogoWatch.brands';

interface BrandLogoWatchProps {
  onClose: () => void;
  onDeepPivot?: (seeds: string[]) => void;
}

export function BrandLogoWatch({ onClose, onDeepPivot }: BrandLogoWatchProps) {
  const [feed, setFeed] = useState<BrandWatchResponse | null>(null);
  const [selected, setSelected] = useState<BrandLogoHit | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [brand, setBrand] = useState('all');
  const [confidence, setConfidence] = useState('all');
  const [maxAge, setMaxAge] = useState(0);
  const [showConfig, setShowConfig] = useState(false);
  const [showExport, setShowExport] = useState(false);
  const [viewMode, setViewMode] = useState<'cards' | 'columns'>('columns');
  const [watchBrands, setWatchBrands] = useState<BrandWatchBrand[]>([]);
  const [newBrand, setNewBrand] = useState('');
  const [newAliases, setNewAliases] = useState('');
  const [newAllowlist, setNewAllowlist] = useState('');
  const [newThreshold, setNewThreshold] = useState(40);
  const [eta, setEta] = useState({ progress: 0, seconds: 0, label: '' });
  const [analysis, setAnalysis] = useState<Record<string, BrandDomainAnalysis>>({});
  const [analysisLoading, setAnalysisLoading] = useState('');
  const importRef = useRef<HTMLInputElement>(null);

  const loadStatus = async () => {
    setError('');
    try {
      const res = await fetch(`${API_BASE}/api/brand-logo-watch/status`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `status failed: ${res.status}`);
      const safeData = normalizeFeed(data);
      setFeed(safeData);
      const saved = loadStoredBrands();
      setWatchBrands(saved.length > 0 ? saved : safeData.brands);
      setSelected(safeData.hits[0] || null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'failed to load Brand Logo Watch');
    }
  };

  const refresh = async () => {
    const sourceBrands = watchBrands.length > 0 ? watchBrands : feed?.brands || [];
    const targetBrand = brand === 'all'
      ? sourceBrands[0]
      : sourceBrands.find(item => item.name === brand);
    if (!targetBrand) {
      setError('Select or add one brand before refresh.');
      return;
    }

    setLoading(true);
    setError('');
    setBrand(targetBrand.name);
    setSelected(null);
    setEta({ progress: 3, seconds: 160, label: `Querying URLScan for ${targetBrand.name}` });
    const startedAt = Date.now();
    const timer = window.setInterval(() => {
      const elapsed = Math.round((Date.now() - startedAt) / 1000);
      const progress = Math.min(92, 6 + elapsed);
      setEta({
        progress,
        seconds: Math.max(0, 160 - elapsed),
        label: progress < 30 ? 'Running expanded URLScan queries' : progress < 84 ? 'OpenAI vision is verifying visible brand logos' : 'Dropping blank pages and false positives',
      });
    }, 1000);
    try {
      const res = await fetch(`${API_BASE}/api/brand-logo-watch/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ days: 30, size: 100, brands: [targetBrand] }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `refresh failed: ${res.status}`);
      const safeData = normalizeFeed(data);
      setFeed(safeData);
      const nextBrands = mergeBrands(sourceBrands, safeData.brands.length > 0 ? safeData.brands : [targetBrand]);
      setWatchBrands(nextBrands);
      storeBrands(nextBrands);
      const targetHits = safeData.hits.filter((hit: BrandLogoHit) => hit.brand === targetBrand.name);
      setSelected(targetHits[0] || null);
      setEta({ progress: 100, seconds: 0, label: `Done: ${targetHits.length} strict ${targetBrand.name} hit${targetHits.length === 1 ? '' : 's'}` });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'URLScan refresh failed');
      setEta({ progress: 100, seconds: 0, label: 'Refresh failed. Check diagnostics.' });
    } finally {
      window.clearInterval(timer);
      setLoading(false);
    }
  };

  useEffect(() => {
    loadStatus();
  }, []);

  const brands = feed?.brands || [];
  const hits = feed?.hits || [];
  const filtered = useMemo(() => hits.filter(hit => {
    if (brand !== 'all' && hit.brand !== brand) return false;
    if (confidence !== 'all' && hit.confidence !== confidence) return false;
    if (maxAge > 0 && hit.domainAgeDays > 0 && hit.domainAgeDays > maxAge) return false;
    return true;
  }), [hits, brand, confidence, maxAge]);

  const stats = {
    high: hits.filter(hit => hit.confidence === 'high').length,
    review: hits.filter(hit => hit.confidence === 'visual').length,
    young: hits.filter(hit => hit.domainAgeDays > 0 && hit.domainAgeDays < 90).length,
    malicious: hits.filter(hit => hit.urlscanMalicious).length,
    aiVerified: hits.filter(hit => hit.aiLogoVerified).length,
  };

  useEffect(() => {
    if (!selected || filtered.some(hit => hit.id === selected.id)) return;
    setSelected(filtered[0] || null);
  }, [filtered, selected]);

  const addBrand = () => {
    const name = newBrand.trim();
    if (!name) return;
    const nextBrand: BrandWatchBrand = {
      name,
      queryNames: uniqueTextLines(`${newAliases}\n${name}`),
      legitDomains: uniqueTextLines(newAllowlist),
      verdictThreshold: newThreshold || 40,
      pollMinutes: 15,
    };
    const next = [...watchBrands.filter(item => item.name.toLowerCase() !== name.toLowerCase()), nextBrand];
    setWatchBrands(next);
    storeBrands(next);
    setBrand(name);
    setConfidence('all');
    setMaxAge(0);
    setNewBrand('');
    setNewAliases('');
    setNewAllowlist('');
    setNewThreshold(40);
  };

  const removeBrand = (name: string) => {
    const next = watchBrands.filter(item => item.name !== name);
    setWatchBrands(next);
    storeBrands(next);
    if (brand === name) setBrand('all');
  };

  const importBrands = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = item => {
      const imported = parseImportedBrands(String(item.target?.result || ''));
      if (imported.length === 0) {
        setError('No brand names found in imported file.');
        return;
      }
      const next = mergeBrands(watchBrands.length > 0 ? watchBrands : brands, imported);
      setWatchBrands(next);
      storeBrands(next);
      setBrand(imported[0].name);
      setShowConfig(true);
      setError('');
    };
    reader.readAsText(file);
    event.target.value = '';
  };

  const exportSTIX = () => {
    const params = new URLSearchParams();
    if (brand !== 'all') params.set('brand', brand);
    if (confidence !== 'all') params.set('confidence', confidence);
    window.open(`${API_BASE}/api/brand-logo-watch/stix?${params.toString()}`, '_blank', 'noopener,noreferrer');
  };

  const exportFiltered = (format: 'csv' | 'json' | 'txt' | 'md' | 'clipboard') => {
    const baseName = `reconvision-logo-watch-${brand === 'all' ? 'all' : brand.toLowerCase()}-${new Date().toISOString().slice(0, 10)}`;
    const content = formatBrandWatchExport(filtered, format === 'clipboard' ? 'txt' : format);
    if (format === 'clipboard') {
      navigator.clipboard.writeText(content).catch(() => {});
      return;
    }
    const mime = format === 'json' ? 'application/json' : format === 'csv' ? 'text/csv' : 'text/plain';
    downloadText(`${baseName}.${format}`, content, mime);
  };

  const pivotAll = () => {
    const seeds = uniqueTextLines(filtered.map(hit => hit.domain).join('\n'));
    if (onDeepPivot && seeds.length > 0) {
      onDeepPivot(seeds);
      return;
    }
    navigator.clipboard.writeText(seeds.join('\n')).catch(() => {});
  };

  const pivotHit = (hit: BrandLogoHit) => {
    if (onDeepPivot) {
      onDeepPivot([hit.domain]);
      return;
    }
    navigator.clipboard.writeText(hit.relatedPivotQuery || hit.domain).catch(() => {});
  };

  const analyzeHit = async (hit: BrandLogoHit) => {
    setAnalysisLoading(hit.id);
    setError('');
    try {
      const res = await fetch(`${API_BASE}/api/brand-logo-watch/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hit }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `analysis failed: ${res.status}`);
      setAnalysis(prev => ({ ...prev, [hit.id]: normalizeAnalysis(data) }));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'AI analysis failed');
    } finally {
      setAnalysisLoading('');
    }
  };

  return (
    <div className="brand-watch-overlay">
      <section className="brand-watch-shell">
        <header className="brand-watch-header">
          <div>
            <span>URLSCAN PRO VISUAL INTEL</span>
            <h1>BRAND LOGO WATCH</h1>
            <p>Strict screenshot-first feed. Results must include URLScan visual logo detection for the selected brand, pass allowlist, live 200 verification, and screenshot evidence.</p>
          </div>
          <div className="brand-watch-actions">
            <button onClick={refresh} disabled={loading || !feed?.configured}>{loading ? 'REFRESHING...' : 'REFRESH'}</button>
            <button onClick={() => importRef.current?.click()}>IMPORT</button>
            <button onClick={() => setShowConfig(prev => !prev)}>{showConfig ? 'HIDE CONFIG' : 'ADD BRAND'}</button>
            <button onClick={() => setViewMode(prev => prev === 'cards' ? 'columns' : 'cards')}>{viewMode === 'cards' ? 'COLUMNS' : 'CARDS'}</button>
            <button onClick={pivotAll} disabled={filtered.length === 0}>PIVOT ALL</button>
            <button onClick={() => setShowExport(prev => !prev)} disabled={filtered.length === 0}>EXPORT</button>
            <button onClick={onClose}>CLOSE</button>
          </div>
          <input ref={importRef} type="file" accept=".txt,.csv,.json" className="hidden" onChange={importBrands} />
        </header>

        {error && <div className="brand-watch-error">{error}</div>}
        {feed && !feed.configured && <div className="brand-watch-error">URLSCAN_API_KEY is not configured. Add it to .env and restart run.bat.</div>}
        {feed?.configured && <div className="brand-watch-ok">STRICT MODE: expanded URLScan queries run for coverage, then OpenAI vision verifies the screenshot contains the selected brand logo before a card appears.</div>}

        {showExport && (
          <div className="brand-watch-export">
            <span>{filtered.length.toLocaleString()} filtered rows</span>
            <button onClick={() => exportFiltered('csv')}>CSV</button>
            <button onClick={() => exportFiltered('json')}>JSON</button>
            <button onClick={() => exportFiltered('txt')}>TXT</button>
            <button onClick={() => exportFiltered('md')}>MD</button>
            <button onClick={exportSTIX}>STIX 2.1</button>
            <button onClick={() => exportFiltered('clipboard')}>COPY</button>
          </div>
        )}

        {(loading || eta.label) && (
          <div className="brand-watch-eta">
            <div className="brand-watch-eta-head">
              <span>{eta.label}</span>
              <b>{loading ? `ETA ${eta.seconds}s` : 'READY'}</b>
            </div>
            <div className="brand-watch-eta-track">
              <div style={{ width: `${eta.progress}%` }} />
            </div>
          </div>
        )}

        {showConfig && (
          <div className="brand-watch-config">
            <div className="brand-watch-config-form">
              <input value={newBrand} onChange={event => setNewBrand(event.target.value)} placeholder="Brand name e.g. Binance" />
              <input value={newAliases} onChange={event => setNewAliases(event.target.value)} placeholder="Aliases / query names, comma or newline separated" />
              <textarea value={newAllowlist} onChange={event => setNewAllowlist(event.target.value)} placeholder="Legit domains allowlist, one per line e.g. binance.com" />
              <input type="number" min={0} max={100} value={newThreshold} onChange={event => setNewThreshold(Number(event.target.value))} />
              <button onClick={addBrand}>ADD / UPDATE BRAND</button>
            </div>
            <div className="brand-watch-brand-list">
              {watchBrands.map(item => (
                <span key={item.name}>
                  <b>{item.name}</b>
                  {item.legitDomains.slice(0, 3).join(', ') || 'no allowlist'}
                  <button onClick={() => removeBrand(item.name)}>X</button>
                </span>
              ))}
            </div>
          </div>
        )}

        <div className="brand-watch-metrics">
          <Metric label="HIGH CONF" value={stats.high} tone="var(--green)" />
          <Metric label="VISUAL ONLY" value={stats.review} tone="var(--amber)" />
          <Metric label="YOUNG DOMAINS" value={stats.young} tone="var(--purple)" />
          <Metric label="MALICIOUS" value={stats.malicious} tone="var(--red)" />
          <Metric label="AI VERIFIED" value={stats.aiVerified} tone="var(--blue)" />
        </div>

        <div className="brand-watch-filters">
          <select value={brand} onChange={event => setBrand(event.target.value)}>
            <option value="all">All brands</option>
            {(watchBrands.length > 0 ? watchBrands : brands).map(item => <option key={item.name} value={item.name}>{item.name}</option>)}
          </select>
          <select value={confidence} onChange={event => setConfidence(event.target.value)}>
            <option value="all">All confidence</option>
            <option value="high">High: visual + classic</option>
            <option value="visual">Visual logo only</option>
          </select>
          <select value={maxAge} onChange={event => setMaxAge(Number(event.target.value))}>
            <option value={90}>Domain age under 90d</option>
            <option value={30}>Domain age under 30d</option>
            <option value={0}>Any domain age</option>
          </select>
          <span>{feed?.lastRefresh ? `last refresh ${new Date(feed.lastRefresh).toLocaleString()}` : 'not refreshed yet'}</span>
          <span>expanded queries / selected brand only / 30d</span>
          {feed?.rateLimit?.remaining && <span>URLScan remaining {feed.rateLimit.remaining}</span>}
        </div>

        <div className="brand-watch-body">
          <div className={viewMode === 'columns' ? 'brand-watch-table-wrap' : 'brand-watch-grid'}>
            {filtered.length === 0 && (
              <div className="brand-watch-empty">
                <strong>No logo impersonation hits in this view.</strong>
                <span>No URLScan visual logo detections survived strict AI logo verification.</span>
              </div>
            )}
            {viewMode === 'columns' && filtered.length > 0 ? (
              <table className="brand-watch-table">
                <thead>
                  <tr>
                    <th>Domain name</th>
                    <th>Keyword</th>
                    <th>Indicator</th>
                    <th>Status code</th>
                    <th>Brand</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map(hit => (
                    <tr key={hit.id} className={selected?.id === hit.id ? 'selected' : ''} onClick={() => setSelected(hit)}>
                      <td>
                        <strong>{hit.domain}</strong>
                        <small>{hit.apexDomain || '-'}</small>
                      </td>
                      <td>
                        <strong>{hit.title || hit.aiLogoReason || '-'}</strong>
                        <small>{hit.aiLogoReason || (hit.signals || []).slice(0, 2).join(', ') || '-'}</small>
                      </td>
                      <td>
                        <button onClick={event => { event.stopPropagation(); navigator.clipboard.writeText(hit.url).catch(() => {}); }}>{hit.url}</button>
                        <small>{[hit.ip, hit.asn].filter(Boolean).join(' / ') || '-'}</small>
                      </td>
                      <td><b>{hit.liveStatus || '-'}</b></td>
                      <td>
                        <strong>{hit.brand}</strong>
                        <small>{hit.aiLogoVerified ? `AI ${Math.round((hit.aiLogoConfidence || 0) * 100)}%` : hit.confidence}</small>
                      </td>
                      <td>
                        <button onClick={event => { event.stopPropagation(); setSelected(hit); }}>VIEW</button>
                        <button onClick={event => { event.stopPropagation(); pivotHit(hit); }}>PIVOT</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : filtered.map(hit => (
                <button
                  key={hit.id}
                  className={`brand-hit-card ${selected?.id === hit.id ? 'selected' : ''}`}
                  onClick={() => setSelected(hit)}
                >
                  <div className="brand-hit-shot">
                    <img src={hit.screenshot} alt={`${hit.brand} screenshot evidence`} loading="lazy" />
                    <span>{hit.liveStatus} OK</span>
                    {hit.aiLogoVerified && <em>AI LOGO</em>}
                  </div>
                  <div className="brand-hit-main">
                    <div>
                      <b>{hit.brand}</b>
                      <i className={hit.confidence === 'high' ? 'high' : 'review'}>
                        {hit.confidence === 'high' ? 'visual+classic' : 'visual'}
                      </i>
                    </div>
                    <strong>{hit.apexDomain || hit.domain}</strong>
                    <small>{hit.title || hit.url}</small>
                  </div>
                  <div className="brand-hit-foot">
                    <span>score {hit.verdictScore}</span>
                    <span>{hit.domainAgeDays > 0 ? `${hit.domainAgeDays}d old` : 'age n/a'}</span>
                    <span>{hit.country || '-'}</span>
                  </div>
                </button>
              ))}
          </div>

          <aside className="brand-watch-detail">
            {selected ? (
              <BrandHitDetail
                hit={selected}
                analysis={analysis[selected.id]}
                analysisLoading={analysisLoading === selected.id}
                onAnalyze={() => analyzeHit(selected)}
              />
            ) : (
              <div className="brand-watch-diagnostics">
                <div className="brand-detail-title">
                  <span>EVIDENCE</span>
                  <h2>No selected hit</h2>
                </div>
                <p>Select a verified logo card to inspect screenshot evidence, pivots, and AI analysis.</p>
              </div>
            )}
          </aside>
        </div>
      </section>
    </div>
  );
}

function BrandHitDetail({
  hit,
  analysis,
  analysisLoading,
  onAnalyze,
}: {
  hit: BrandLogoHit;
  analysis?: BrandDomainAnalysis;
  analysisLoading: boolean;
  onAnalyze: () => void;
}) {
  const classicBrands = Array.isArray(hit.classicBrands) ? hit.classicBrands : [];
  const signals = Array.isArray(hit.signals) ? hit.signals : [];
  const logoAssets = Array.isArray(hit.logoAssets) ? hit.logoAssets : [];
  const reasons = Array.isArray(analysis?.reasons) ? analysis.reasons : [];
  const pivots = Array.isArray(analysis?.pivots) ? analysis.pivots : [];
  const nextSteps = Array.isArray(analysis?.nextSteps) ? analysis.nextSteps : [];
  return (
    <>
      <div className="brand-detail-shot">
        <img src={hit.screenshot} alt={`${hit.brand} visual evidence`} />
      </div>
      <div className="brand-detail-title">
        <span>{hit.confidence === 'high' ? 'HIGH: VISUAL + CLASSIC' : 'VISUAL LOGO MATCH'}</span>
        <h2>{hit.apexDomain || hit.domain}</h2>
      </div>
      <div className="brand-detail-actions">
        <a href={hit.result} target="_blank" rel="noreferrer">URLSCAN</a>
        <a href={hit.url} target="_blank" rel="noreferrer">LIVE URL</a>
        <button onClick={() => navigator.clipboard.writeText(hit.url).catch(() => {})}>COPY URL</button>
        <button onClick={onAnalyze} disabled={analysisLoading}>{analysisLoading ? 'ANALYZING...' : 'AI ANALYZE'}</button>
      </div>
      <div className="brand-detail-data">
        <Row label="brand" value={hit.visibleBrand || hit.brand} />
        <Row label="classic" value={classicBrands.join(', ') || '-'} />
        <Row label="AI logo" value={hit.aiLogoVerified ? `${Math.round((hit.aiLogoConfidence || 0) * 100)}% verified` : 'not verified'} />
        <Row label="AI reason" value={hit.aiLogoReason || '-'} />
        <Row label="domain" value={hit.domain} />
        <Row label="ip" value={hit.ip || '-'} />
        <Row label="asn" value={[hit.asn, hit.asnName].filter(Boolean).join(' ') || '-'} />
        <Row label="country" value={hit.country || '-'} />
        <Row label="age" value={hit.domainAgeDays > 0 ? `${hit.domainAgeDays} days` : 'unknown'} />
        <Row label="score" value={`${hit.verdictScore}`} />
      </div>
      <div className="brand-detail-section">
        <span>SIGNALS</span>
        {signals.map(signal => <small key={signal}>{signal}</small>)}
      </div>
      {analysis && (
        <div className="brand-detail-section brand-ai-analysis">
          <span>AI DOMAIN ANALYSIS {analysis.model ? `/ ${analysis.model}` : ''}</span>
          <strong>{analysis.risk || 'review'}</strong>
          <p>{analysis.summary}</p>
          {reasons.map(item => <small key={`reason-${item}`}>{item}</small>)}
          {pivots.map(item => <button key={`pivot-${item}`} onClick={() => navigator.clipboard.writeText(item).catch(() => {})}>{item}</button>)}
          {nextSteps.map(item => <small key={`step-${item}`}>{item}</small>)}
        </div>
      )}
      <div className="brand-detail-section">
        <span>PIVOTABLE LOGO ASSETS</span>
        {logoAssets.length === 0 && <small>No matching logo image assets surfaced from scan requests.</small>}
        {logoAssets.map(asset => (
          <button key={asset.url} onClick={() => navigator.clipboard.writeText(asset.url).catch(() => {})}>
            <b>{asset.mimeType}</b>
            {asset.url}
          </button>
        ))}
      </div>
      {hit.relatedPivotQuery && (
        <div className="brand-detail-section">
          <span>RELATED INFRA QUERY</span>
          <button onClick={() => navigator.clipboard.writeText(hit.relatedPivotQuery).catch(() => {})}>{hit.relatedPivotQuery}</button>
        </div>
      )}
    </>
  );
}

function Metric({ label, value, tone }: { label: string; value: number; tone: string }) {
  return (
    <div className="brand-watch-metric" style={{ '--metric-tone': tone } as CSSProperties}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="brand-detail-row">
      <span>{label}</span>
      <button onClick={() => navigator.clipboard.writeText(value).catch(() => {})}>{value}</button>
    </div>
  );
}

function uniqueTextLines(value: string): string[] {
  return Array.from(new Set(value.split(/[\n,]+/).map(item => item.trim()).filter(Boolean)));
}

function parseImportedBrands(value: string): BrandWatchBrand[] {
  const byName = new Map<string, BrandWatchBrand>();
  for (const line of value.split(/\r?\n/)) {
    const clean = line.trim();
    if (!clean) continue;
    const parts = clean.split(/[,;\t]+/).map(part => part.trim()).filter(Boolean);
    const name = parts[0]?.replace(/^brand[:=]/i, '').trim();
    if (!name || name.includes('.') || name.length > 60) continue;
    const legitDomains = parts.slice(1).filter(part => part.includes('.')).map(part => part.toLowerCase());
    byName.set(name.toLowerCase(), {
      name,
      queryNames: [name],
      legitDomains,
      verdictThreshold: 40,
      pollMinutes: 15,
    });
  }
  return Array.from(byName.values()).sort((a, b) => a.name.localeCompare(b.name));
}

function loadStoredBrands(): BrandWatchBrand[] {
  try {
    const raw = localStorage.getItem(BRAND_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function storeBrands(brands: BrandWatchBrand[]) {
  localStorage.setItem(BRAND_STORAGE_KEY, JSON.stringify(brands));
}

function mergeBrands(existing: BrandWatchBrand[], incoming: BrandWatchBrand[]): BrandWatchBrand[] {
  const byName = new Map<string, BrandWatchBrand>();
  for (const item of existing) byName.set(item.name.toLowerCase(), item);
  for (const item of incoming) byName.set(item.name.toLowerCase(), item);
  return Array.from(byName.values()).sort((a, b) => a.name.localeCompare(b.name));
}

function formatBrandWatchExport(hits: BrandLogoHit[], format: 'csv' | 'json' | 'txt' | 'md'): string {
  const rows = hits.map(hit => ({
    domain: hit.domain,
    keyword: hit.title || hit.aiLogoReason || '',
    indicator: hit.url,
    statusCode: hit.liveStatus,
    brand: hit.brand,
    ip: hit.ip,
    asn: [hit.asn, hit.asnName].filter(Boolean).join(' '),
    country: hit.country,
    aiLogo: hit.aiLogoVerified ? `${Math.round((hit.aiLogoConfidence || 0) * 100)}%` : '',
    urlscan: hit.result,
    pivot: hit.relatedPivotQuery || hit.domain,
  }));
  if (format === 'json') return JSON.stringify(rows, null, 2);
  if (format === 'txt') {
    return rows.map(row => [
      `domain=${row.domain}`,
      `keyword=${row.keyword}`,
      `indicator=${row.indicator}`,
      `status=${row.statusCode}`,
      `brand=${row.brand}`,
      `pivot=${row.pivot}`,
    ].join(' | ')).join('\n');
  }
  if (format === 'md') {
    const header = '| Domain name | Keyword | Indicator | Status code | Brand | Pivot |';
    const sep = '|---|---|---|---:|---|---|';
    const body = rows.map(row => `| ${mdCell(row.domain)} | ${mdCell(row.keyword)} | ${mdCell(row.indicator)} | ${row.statusCode || ''} | ${mdCell(row.brand)} | ${mdCell(row.pivot)} |`);
    return [header, sep, ...body].join('\n');
  }
  const header = ['domain name', 'keyword', 'indicator', 'status code', 'brand', 'ip', 'asn', 'country', 'ai logo', 'urlscan', 'pivot'];
  return [
    header.map(csvCell).join(','),
    ...rows.map(row => [row.domain, row.keyword, row.indicator, row.statusCode, row.brand, row.ip, row.asn, row.country, row.aiLogo, row.urlscan, row.pivot].map(csvCell).join(',')),
  ].join('\n');
}

function downloadText(filename: string, content: string, mime: string) {
  const blob = new Blob([content], { type: `${mime};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

function csvCell(value: unknown): string {
  const text = String(value ?? '');
  return `"${text.replace(/"/g, '""')}"`;
}

function mdCell(value: unknown): string {
  return String(value ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
}

function normalizeFeed(data: BrandWatchResponse): BrandWatchResponse {
  const hits = Array.isArray(data.hits) ? data.hits.map(normalizeHit) : [];
  return {
    ...data,
    hits,
    brands: Array.isArray(data.brands) ? data.brands : [],
    queryLog: Array.isArray(data.queryLog) ? data.queryLog : [],
  };
}

function normalizeHit(hit: BrandLogoHit): BrandLogoHit {
  return {
    ...hit,
    classicBrands: Array.isArray(hit.classicBrands) ? hit.classicBrands : [],
    logoAssets: Array.isArray(hit.logoAssets) ? hit.logoAssets : [],
    signals: Array.isArray(hit.signals) ? hit.signals : [],
    aiLogoVerified: Boolean(hit.aiLogoVerified),
    aiLogoConfidence: Number(hit.aiLogoConfidence || 0),
    aiLogoReason: hit.aiLogoReason || '',
  };
}

function normalizeAnalysis(data: BrandDomainAnalysis): BrandDomainAnalysis {
  return {
    ...data,
    reasons: Array.isArray(data.reasons) ? data.reasons : [],
    pivots: Array.isArray(data.pivots) ? data.pivots : [],
    nextSteps: Array.isArray(data.nextSteps) ? data.nextSteps : [],
  };
}
