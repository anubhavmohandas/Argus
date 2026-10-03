import type { CSSProperties } from 'react';
import type { ScanResult } from '../types';
import { URLScanPivotPanel } from './URLScanPivotPanel';

interface MetadataPanelProps {
  result: ScanResult | null;
  onClose: () => void;
  onDeepPivot?: (seeds: string[]) => void;
}

export function MetadataPanel({ result, onClose, onDeepPivot }: MetadataPanelProps) {
  if (!result) {
    return (
      <aside
        className="flex flex-col items-center justify-center"
        style={{
          width: 280, minWidth: 280,
          background: 'var(--bg-panel)',
          borderLeft: '1px solid var(--border)',
          color: 'var(--text-dim)',
        }}
      >
        <svg width="32" height="32" viewBox="0 0 32 32" style={{ opacity: 0.2, marginBottom: 8 }}>
          <rect x="4" y="4" width="24" height="24" rx="1" stroke="currentColor" strokeWidth="1" fill="none" />
          <line x1="4" y1="10" x2="28" y2="10" stroke="currentColor" strokeWidth="1" />
          <rect x="8" y="14" width="16" height="10" stroke="currentColor" strokeWidth="0.5" fill="none" />
        </svg>
        <span className="text-xs" style={{ letterSpacing: '0.12em' }}>SELECT A RESULT</span>
      </aside>
    );
  }

  const statusColor = getStatusColor(result.status);
  const intel = result.intelligence;
  const riskLevel = intel?.riskLevel || 'low';
  const riskScore = intel?.riskScore || 0;
  const categories = intel?.categories ?? [];
  const indicators = intel?.indicators ?? [];
  const technologies = intel?.technologies ?? [];

  return (
    <aside
      className="inspector-panel flex flex-col overflow-y-auto"
      style={{
        width: 280, minWidth: 280,
        background: 'var(--bg-panel)',
        borderLeft: '1px solid var(--border)',
      }}
    >
      {/* Header */}
      <div className="flex items-center justify-between px-3 py-2" style={{ borderBottom: '1px solid var(--border)' }}>
        <span className="text-xs" style={{ color: 'var(--text-dim)', letterSpacing: '0.12em' }}>DETAIL</span>
        <button onClick={onClose} className="text-xs" style={{ color: 'var(--text-dim)' }}>X</button>
      </div>

      {/* Screenshot preview */}
      {result.screenshot && (
        <div style={{ height: 160, overflow: 'hidden', borderBottom: '1px solid var(--border)' }}>
          <img
            src={`data:image/png;base64,${result.screenshot}`}
            alt={result.domain}
            style={{ width: '100%', height: '100%', objectFit: 'cover', objectPosition: 'top' }}
          />
        </div>
      )}

      {/* Core metadata */}
      <div className="flex flex-col" style={{ borderBottom: '1px solid var(--border)' }}>
        <div className="px-3 py-3" style={{ borderBottom: '1px solid var(--border-dim)', background: 'linear-gradient(90deg, rgba(0,230,118,0.04), transparent)' }}>
          <div className="flex items-center justify-between">
            <div>
              <div style={{ color: 'var(--text-dim)', fontSize: 9, letterSpacing: '0.12em' }}>MYTHOS RISK</div>
              <div style={{ color: riskColor(riskLevel), fontFamily: 'var(--font-ui)', fontWeight: 700, fontSize: 34, lineHeight: 1 }}>
                {riskScore}
              </div>
            </div>
            <div className="risk-meter" style={{
              width: 72,
              height: 72,
              borderRadius: 72,
              border: `3px solid ${riskColor(riskLevel)}`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: riskColor(riskLevel),
              fontSize: 10,
              letterSpacing: '0.08em',
              textTransform: 'uppercase',
              '--risk-color': riskColor(riskLevel),
            } as CSSProperties}>
              {riskLevel}
            </div>
          </div>
        </div>
        <MetaRow label="DOMAIN" value={result.domain} mono copyable />
        <MetaRow label="URL" value={result.url} mono copyable truncate />
        <MetaRow label="ROOT" value={intel?.rootDomain || '-'} mono copyable />
        <MetaRow label="IP" value={intel?.ipAddress || '-'} mono copyable />
        <MetaRow label="BRAND" value={intel?.brandCandidate || '-'} color={intel?.brandCandidate ? 'var(--purple)' : undefined} />
        <MetaRow label="STATUS" value={String(result.status || 'ERROR')}
          color={statusColor} mono />
        <MetaRow label="TITLE" value={result.title || '-'} />
        <MetaRow label="SERVER" value={result.server || '-'} mono />
        <MetaRow label="SIZE" value={result.contentLength > 0 ? formatSize(result.contentLength) : '-'} mono />
        <MetaRow label="TLS" value={result.tls ? 'YES' : 'NO'}
          color={result.tls ? 'var(--green)' : 'var(--text-dim)'} />
        <MetaRow label="DURATION" value={`${result.durationMs}ms`} mono />
        <MetaRow label="TIME" value={formatTimestamp(result.timestamp)} mono />
      </div>

      <div className="px-3 py-2" style={{ borderBottom: '1px solid var(--border)' }}>
        <div className="text-xs mb-2" style={{ color: 'var(--text-dim)', letterSpacing: '0.1em' }}>EXPORT CURRENT RESULT</div>
        <div className="flex flex-wrap gap-1">
          {(['json', 'txt', 'md'] as const).map(format => (
            <button
              key={format}
              onClick={() => exportSingleResult(result, format)}
              className="px-2 py-1 text-xs"
              style={{
                border: '1px solid var(--border)',
                color: 'var(--green)',
                background: 'rgba(0,230,118,0.05)',
                letterSpacing: '0.08em',
              }}
            >
              {format.toUpperCase()}
            </button>
          ))}
          <button
            onClick={() => navigator.clipboard.writeText(formatSingleResult(result, 'txt')).catch(() => {})}
            className="px-2 py-1 text-xs"
            style={{
              border: '1px solid var(--border)',
              color: 'var(--blue)',
              background: 'rgba(64,196,255,0.05)',
              letterSpacing: '0.08em',
            }}
          >
            COPY
          </button>
        </div>
      </div>

      {intel && (
        <div className="px-3 py-2" style={{ borderBottom: '1px solid var(--border)' }}>
          <div className="text-xs mb-2" style={{ color: 'var(--text-dim)', letterSpacing: '0.1em' }}>EVIDENCE</div>
          <div className="flex flex-wrap gap-1 mb-2">
            {categories.map(category => (
              <span key={category} className="kw-badge" style={{ color: category === 'phishing' ? 'var(--amber)' : undefined }}>
                {category}
              </span>
            ))}
          </div>
          <div className="flex flex-col gap-1">
            {indicators.map((indicator, index) => (
              <div key={`${indicator}-${index}`} className="text-xs" style={{ color: 'var(--text-sec)', fontSize: 10, lineHeight: 1.45 }}>
                <span style={{ color: riskColor(riskLevel) }}>-</span> {indicator}
              </div>
            ))}
          </div>
          {technologies.length > 0 && (
            <div className="mt-3">
              <div className="text-xs mb-1" style={{ color: 'var(--text-dim)', letterSpacing: '0.1em' }}>TECH</div>
              <div className="flex flex-wrap gap-1">
                {technologies.map(tech => (
                  <span key={tech} className="kw-badge" style={{ color: 'var(--blue)' }}>{tech}</span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      <URLScanPivotPanel result={result} onDeepPivot={onDeepPivot} />

      {/* Redirect info */}
      {result.redirectUrl && (
        <div style={{ borderBottom: '1px solid var(--border)' }}>
          <div className="px-3 py-2">
            <div className="text-xs mb-1" style={{ color: 'var(--text-dim)', letterSpacing: '0.1em' }}>REDIRECT</div>
            <span className="text-xs break-all" style={{ color: 'var(--amber)', fontFamily: 'var(--font-mono)' }}>
              {result.redirectUrl}
            </span>
          </div>
          {result.redirectChain && result.redirectChain.length > 1 && (
            <div className="px-3 pb-2">
              <div className="text-xs mb-1" style={{ color: 'var(--text-dim)', letterSpacing: '0.1em' }}>CHAIN</div>
              {result.redirectChain.map((url, i) => (
                <div key={i} className="text-xs break-all py-0.5"
                  style={{ color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', fontSize: 10 }}>
                  {i + 1}. {url}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Keywords */}
      {result.keywords && result.keywords.length > 0 && (
        <div className="px-3 py-2" style={{ borderBottom: '1px solid var(--border)' }}>
          <div className="text-xs mb-2" style={{ color: 'var(--text-dim)', letterSpacing: '0.1em' }}>DETECTED KEYWORDS</div>
          <div className="flex flex-wrap gap-1">
            {result.keywords.map(kw => (
              <span key={kw} className="kw-badge">{kw}</span>
            ))}
          </div>
        </div>
      )}

      {/* Error */}
      {result.error && (
        <div className="px-3 py-2">
          <div className="text-xs mb-1" style={{ color: 'var(--red)', letterSpacing: '0.1em' }}>ERROR</div>
          <span className="text-xs break-all" style={{ color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
            {result.error}
          </span>
        </div>
      )}

      {/* Open in browser */}
      {result.url && (
        <div className="px-3 py-3 mt-auto" style={{ borderTop: '1px solid var(--border)' }}>
          <a
            href={result.url}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center justify-center gap-2 py-2 text-xs w-full"
            style={{
              border: '1px solid var(--green)',
              color: 'var(--green)',
              background: 'rgba(0,230,118,0.06)',
              letterSpacing: '0.1em',
              textDecoration: 'none',
            }}
          >
            OPEN IN BROWSER
          </a>
        </div>
      )}
    </aside>
  );
}

function MetaRow({ label, value, color, mono, copyable, truncate }: {
  label: string; value: string;
  color?: string; mono?: boolean; copyable?: boolean; truncate?: boolean;
}) {
  const handleCopy = () => {
    if (copyable && value) navigator.clipboard.writeText(value).catch(() => {});
  };

  return (
    <div
      className="flex items-start px-3 py-1.5 gap-2"
      onClick={copyable ? handleCopy : undefined}
      title={copyable ? 'Click to copy' : undefined}
      style={{ cursor: copyable ? 'pointer' : 'default', borderBottom: '1px solid var(--border-dim)' }}
    >
      <span className="text-xs flex-shrink-0 w-16"
        style={{ color: 'var(--text-dim)', letterSpacing: '0.08em', fontSize: 9, paddingTop: 2 }}>
        {label}
      </span>
      <span
        className={`text-xs flex-1 ${truncate ? 'truncate' : 'break-all'}`}
        style={{
          color: color || (mono ? 'var(--text-code)' : 'var(--text-pri)'),
          fontFamily: mono ? 'var(--font-mono)' : 'inherit',
          fontSize: 11,
        }}
        title={value}
      >
        {value || '-'}
      </span>
    </div>
  );
}

function getStatusColor(status: number): string {
  if (status >= 200 && status < 300) return 'var(--green)';
  if (status >= 300 && status < 400) return 'var(--amber)';
  if (status >= 400 && status < 500) return '#ff6d00';
  if (status >= 500) return 'var(--red)';
  return 'var(--text-dim)';
}

function riskColor(level: string): string {
  if (level === 'critical') return 'var(--red)';
  if (level === 'high') return '#ff6d00';
  if (level === 'medium') return 'var(--amber)';
  return 'var(--green)';
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function formatTimestamp(ts: string): string {
  if (!ts) return '-';
  try {
    return new Date(ts).toLocaleTimeString();
  } catch {
    return ts;
  }
}

function exportSingleResult(result: ScanResult, format: 'json' | 'txt' | 'md') {
  const content = formatSingleResult(result, format);
  const mime = format === 'json' ? 'application/json' : 'text/plain';
  downloadText(`reconvision_result_${safeFileName(result.domain || result.id)}.${format}`, content, mime);
}

function formatSingleResult(result: ScanResult, format: 'json' | 'txt' | 'md'): string {
  const intel = result.intelligence;
  if (format === 'json') {
    return JSON.stringify(result, null, 2);
  }
  if (format === 'md') {
    return [
      `# ReconVision Result: ${result.domain || result.url}`,
      '',
      `- URL: ${result.url || '-'}`,
      `- Status: ${result.status || 'ERROR'}`,
      `- Title: ${result.title || '-'}`,
      `- Server: ${result.server || '-'}`,
      `- IP: ${intel?.ipAddress || '-'}`,
      `- Root: ${intel?.rootDomain || '-'}`,
      `- Brand: ${intel?.brandCandidate || '-'}`,
      `- Risk: ${intel?.riskLevel || '-'} ${intel?.riskScore || 0}`,
      `- TLS: ${result.tls ? 'YES' : 'NO'}`,
      `- Duration: ${result.durationMs || 0}ms`,
      '',
      '## Indicators',
      ...(intel?.indicators?.length ? intel.indicators.map(item => `- ${item}`) : ['- none']),
      '',
      '## Keywords',
      ...(result.keywords?.length ? result.keywords.map(item => `- ${item}`) : ['- none']),
      result.redirectUrl ? ['', '## Redirect', result.redirectUrl].join('\n') : '',
      result.error ? ['', '## Error', result.error].join('\n') : '',
    ].filter(Boolean).join('\n');
  }
  return [
    `ReconVision current result`,
    `Domain: ${result.domain || '-'}`,
    `URL: ${result.url || '-'}`,
    `Status: ${result.status || 'ERROR'}`,
    `Title: ${result.title || '-'}`,
    `Server: ${result.server || '-'}`,
    `IP: ${intel?.ipAddress || '-'}`,
    `Root: ${intel?.rootDomain || '-'}`,
    `Brand: ${intel?.brandCandidate || '-'}`,
    `Risk: ${intel?.riskLevel || '-'} ${intel?.riskScore || 0}`,
    `TLS: ${result.tls ? 'YES' : 'NO'}`,
    `Duration: ${result.durationMs || 0}ms`,
    `Time: ${result.timestamp || '-'}`,
    `Indicators: ${intel?.indicators?.join('; ') || '-'}`,
    `Keywords: ${result.keywords?.join('; ') || '-'}`,
    `Redirect: ${result.redirectUrl || '-'}`,
    `Error: ${result.error || '-'}`,
  ].join('\n');
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

function safeFileName(value: string) {
  return String(value || 'result').replace(/[^a-z0-9.-]+/gi, '_').slice(0, 80) || 'result';
}
