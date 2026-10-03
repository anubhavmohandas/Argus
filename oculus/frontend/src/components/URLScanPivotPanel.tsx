import { useEffect, useMemo, useState } from 'react';
import type { ScanResult, URLScanClusterItem, URLScanPivotIndicator, URLScanPivotResponse } from '../types';

const API_BASE = import.meta.env.VITE_API_URL || '';

interface URLScanPivotPanelProps {
  result: ScanResult;
  onDeepPivot?: (seeds: string[]) => void;
}

type PivotType = 'domain' | 'ip' | 'brand' | 'asn' | 'hash';

interface PivotTarget {
  type: PivotType;
  value: string;
  label: string;
}

export function URLScanPivotPanel({ result, onDeepPivot }: URLScanPivotPanelProps) {
  const [configured, setConfigured] = useState<boolean | null>(null);
  const [days, setDays] = useState(7);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [pivot, setPivot] = useState<URLScanPivotResponse | null>(null);

  const targets = useMemo(() => buildPivotTargets(result), [result]);

  useEffect(() => {
    let alive = true;
    fetch(`${API_BASE}/api/urlscan/status`)
      .then(res => res.json())
      .then(data => {
        if (alive) setConfigured(Boolean(data.configured));
      })
      .catch(() => {
        if (alive) setConfigured(false);
      });
    return () => {
      alive = false;
    };
  }, []);

  const runPivot = async (target: PivotTarget) => {
    setLoading(true);
    setError('');
    setPivot(null);
    try {
      const res = await fetch(`${API_BASE}/api/urlscan/pivot`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: target.type, indicator: target.value, days, size: 25 }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `URLScan returned ${res.status}`);
      setPivot(normalizeURLScanPivot(data));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'URLScan pivot failed');
    } finally {
      setLoading(false);
    }
  };

  const runSuggestedPivot = (next: URLScanPivotIndicator) => {
    runPivot({ type: next.type as PivotType, value: next.value, label: `${next.type}: ${next.value}` });
  };

  return (
    <div className="urlscan-panel px-3 py-3" style={{ borderBottom: '1px solid var(--border)' }}>
      <div className="flex items-center justify-between mb-2">
        <div>
          <div className="text-xs" style={{ color: 'var(--text-dim)', letterSpacing: '0.1em' }}>URLSCAN CAMPAIGN PIVOT</div>
          <div style={{ color: configured ? 'var(--green)' : 'var(--amber)', fontSize: 10, marginTop: 2 }}>
            {configured === null ? 'checking key...' : configured ? 'key ready' : 'key missing'}
          </div>
        </div>
        <select
          value={days}
          onChange={event => setDays(Number(event.target.value))}
          className="scan-input rounded-none px-1 py-1 text-xs"
          style={{ width: 68, background: 'var(--bg-deep)', color: 'var(--text-sec)' }}
          title="Search window"
        >
          <option value={1}>1d</option>
          <option value={7}>7d</option>
          <option value={14}>14d</option>
          <option value={30}>30d</option>
          <option value={90}>90d</option>
        </select>
      </div>

      {!configured && (
        <div className="urlscan-empty">
          Put your key in .env as URLSCAN_API_KEY to unlock pivots.
        </div>
      )}

      <div className="grid grid-cols-2 gap-1 mt-2">
        {onDeepPivot && (
          <button
            onClick={() => onDeepPivot(uniqueTargets(targets.map(target => target.value)))}
            className="urlscan-pivot-button"
            title="Open this result in Deep Pivot"
          >
            <span>DEEP</span>
            <small>multi-source</small>
          </button>
        )}
        {targets.map(target => (
          <button
            key={`${target.type}:${target.value}`}
            onClick={() => runPivot(target)}
            disabled={!configured || loading}
            className="urlscan-pivot-button"
            title={target.value}
          >
            <span>{target.label}</span>
            <small>{shortValue(target.value, 18)}</small>
          </button>
        ))}
      </div>

      {loading && <div className="urlscan-loading mt-3">Pivoting campaign graph...</div>}
      {error && <div className="urlscan-error mt-3">{error}</div>}

      {pivot && (
        <div className="mt-3 flex flex-col gap-3">
          <div className="urlscan-query" title={pivot.query}>{pivot.query}</div>
          <div className="grid grid-cols-3 gap-1">
            <Metric label="TOTAL" value={pivot.total} />
            <Metric label="HITS" value={safeArray(pivot.results).length} />
            <Metric label="LEFT" value={pivot.rateLimit?.remaining || '-'} />
          </div>
          <ClusterGroup title="DOMAINS" items={pivot.clusters.domains} />
          <ClusterGroup title="IPS" items={pivot.clusters.ips} />
          <ClusterGroup title="ASNS" items={pivot.clusters.asns} />
          <ClusterGroup title="BRANDS" items={pivot.clusters.brands} />

          {safeArray(pivot.nextPivots).length > 0 && (
            <div>
              <div className="urlscan-section-label">NEXT PIVOTS</div>
              <div className="flex flex-wrap gap-1">
                {safeArray(pivot.nextPivots).map(next => (
                  <button
                    key={`${next.type}:${next.value}`}
                    onClick={() => runSuggestedPivot(next)}
                    className="urlscan-next"
                    disabled={loading}
                    title={next.query}
                  >
                    {next.type}:{shortValue(next.value, 14)}
                  </button>
                ))}
              </div>
            </div>
          )}

          {safeArray(pivot.results).length > 0 && (
            <div>
              <div className="urlscan-section-label">RECENT SCANS</div>
              <div className="flex flex-col gap-1">
                {safeArray(pivot.results).slice(0, 5).map((hit, index) => (
                  <a
                    key={`${hit.result}-${index}`}
                    className="urlscan-hit"
                    href={hit.result || hit.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    title={hit.url}
                  >
                    <span style={{ color: hit.malicious ? 'var(--red)' : hit.suspicious ? 'var(--amber)' : 'var(--green)' }}>
                      {hit.malicious ? 'MAL' : hit.suspicious ? 'SUS' : 'OBS'}
                    </span>
                    <strong>{hit.domain || '-'}</strong>
                    <small>{hit.ip || hit.country || '-'}</small>
                  </a>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function buildPivotTargets(result: ScanResult): PivotTarget[] {
  const intel = result.intelligence;
  const seen = new Set<string>();
  const targets: PivotTarget[] = [];
  const add = (type: PivotType, value: string | undefined, label: string) => {
    const clean = (value || '').trim();
    const key = `${type}:${clean.toLowerCase()}`;
    if (!clean || clean === '-' || seen.has(key)) return;
    seen.add(key);
    targets.push({ type, value: clean, label });
  };

  add('domain', intel?.rootDomain || result.domain, 'DOMAIN');
  add('ip', intel?.ipAddress, 'IP');
  add('brand', intel?.brandCandidate, 'BRAND');
  return targets;
}

function Metric({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="urlscan-metric">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function ClusterGroup({ title, items }: { title: string; items: URLScanClusterItem[] }) {
  const safeItems = safeArray(items);
  if (!safeItems.length) return null;
  return (
    <div>
      <div className="urlscan-section-label">{title}</div>
      <div className="flex flex-wrap gap-1">
        {safeItems.slice(0, 8).map(item => (
          <span key={item.value} className="urlscan-chip" title={item.value}>
            {shortValue(item.value, 18)} <b>{item.count}</b>
          </span>
        ))}
      </div>
    </div>
  );
}

function shortValue(value: string, max: number): string {
  const text = String(value || '');
  if (!text) return '-';
  return text.length > max ? `${text.slice(0, max - 1)}...` : text;
}

function uniqueTargets(values: string[]): string[] {
  return Array.from(new Set(safeArray(values).map(value => String(value || '').trim()).filter(Boolean).map(value => value.toLowerCase())));
}

function safeArray<T>(value: T[] | null | undefined): T[] {
  return Array.isArray(value) ? value : [];
}

function normalizeURLScanPivot(value: any): URLScanPivotResponse {
  return {
    indicator: String(value?.indicator || ''),
    type: String(value?.type || ''),
    days: Number(value?.days || 7),
    query: String(value?.query || ''),
    total: Number(value?.total || 0),
    results: safeArray(value?.results),
    clusters: {
      domains: safeArray(value?.clusters?.domains),
      ips: safeArray(value?.clusters?.ips),
      asns: safeArray(value?.clusters?.asns),
      brands: safeArray(value?.clusters?.brands),
    },
    nextPivots: safeArray(value?.nextPivots),
    rateLimit: value?.rateLimit || {},
  };
}
