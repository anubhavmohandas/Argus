import { useState } from 'react';
import type { ScanResult } from '../types';

interface ResultCardProps {
  result: ScanResult;
  isSelected: boolean;
  onSelect: (r: ScanResult) => void;
}

export function ResultCard({ result, isSelected, onSelect }: ResultCardProps) {
  const [imgError, setImgError] = useState(false);

  const statusClass = getStatusClass(result.status);
  const risk = result.intelligence?.riskScore || 0;
  const riskLevel = result.intelligence?.riskLevel || 'low';
  const indicators = result.intelligence?.indicators ?? [];

  return (
    <div
      className="result-card depth-card relative cursor-pointer flex flex-col"
      onClick={() => onSelect(result)}
      style={{
        background: isSelected ? 'var(--bg-hover)' : 'var(--bg-card)',
        border: '1px solid',
        borderColor: isSelected ? 'var(--green)' : risk >= 45 ? riskColor(riskLevel) : result.interesting ? 'rgba(255,171,0,0.3)' : 'var(--border-dim)',
        transition: 'border-color 0.15s, background 0.15s',
        position: 'relative',
        overflow: 'hidden',
      }}
      onMouseEnter={e => {
        if (!isSelected) (e.currentTarget as HTMLElement).style.borderColor = 'var(--border)';
      }}
      onMouseLeave={e => {
        if (!isSelected) (e.currentTarget as HTMLElement).style.borderColor =
          risk >= 45 ? riskColor(riskLevel) : result.interesting ? 'rgba(255,171,0,0.3)' : 'var(--border-dim)';
      }}
    >
      {/* Interesting badge */}
      {result.interesting && (
        <div className="absolute top-0 right-0 z-10 px-1.5 py-0.5 text-xs"
          style={{ background: 'var(--amber)', color: '#000', fontSize: 9, letterSpacing: '0.08em' }}>
          !
        </div>
      )}

      <div className="absolute top-0 left-0 z-10 px-1.5 py-0.5 text-xs"
        style={{ background: riskColor(riskLevel), color: riskLevel === 'low' ? '#00150a' : '#000', fontSize: 9, letterSpacing: '0.08em', fontWeight: 700 }}>
        RISK {risk}
      </div>

      {/* Screenshot */}
      <div style={{ height: 160, overflow: 'hidden', background: 'var(--bg-deep)', position: 'relative' }}>
        {result.screenshot && !imgError ? (
          <img
            src={`data:image/png;base64,${result.screenshot}`}
            alt={result.domain}
            style={{ width: '100%', height: '100%', objectFit: 'cover', objectPosition: 'top' }}
            onError={() => setImgError(true)}
            loading="lazy"
          />
        ) : (
          <div className="flex flex-col items-center justify-center h-full" style={{ gap: 4 }}>
            {result.error ? (
              <>
                <span style={{ fontSize: 18, color: 'var(--text-dim)' }}>X</span>
                <span className="text-xs" style={{ color: 'var(--text-dim)', fontSize: 10, textAlign: 'center', padding: '0 8px' }}>
                  {result.error.length > 60 ? result.error.slice(0, 60) + '…' : result.error}
                </span>
              </>
            ) : result.status === 0 ? (
              <>
                <span style={{ fontSize: 18, color: 'var(--text-dim)' }}>⊘</span>
                <span style={{ fontSize: 10, color: 'var(--text-dim)' }}>No response</span>
              </>
            ) : (
              <>
                <span style={{ fontSize: 18, color: 'var(--text-dim)' }}>◫</span>
                <span style={{ fontSize: 10, color: 'var(--text-dim)' }}>No screenshot</span>
              </>
            )}
          </div>
        )}

        {/* TLS badge */}
        {result.tls && (
          <div className="absolute bottom-1 left-1 px-1 py-0.5"
            style={{ background: 'rgba(0,0,0,0.75)', fontSize: 9, color: 'var(--green)', letterSpacing: '0.05em' }}>
            HTTPS
          </div>
        )}
      </div>

      {/* Metadata */}
      <div className="flex flex-col gap-1 p-2">
        {/* Domain + status */}
        <div className="flex items-center justify-between gap-2">
          <span
            className="text-xs truncate"
            style={{ color: 'var(--text-pri)', fontFamily: 'var(--font-mono)', fontSize: 11 }}
            title={result.domain}
          >
            {result.domain}
          </span>
          <span
            className={`text-xs px-1.5 py-0.5 flex-shrink-0 ${statusClass}`}
            style={{ border: '1px solid', fontSize: 10, letterSpacing: '0.05em' }}
          >
            {result.status || 'ERR'}
          </span>
        </div>

        {/* Title */}
        {result.title && (
          <span className="text-xs truncate" style={{ color: 'var(--text-sec)', fontSize: 10 }} title={result.title}>
            {result.title}
          </span>
        )}

        {/* Footer row */}
        <div className="flex items-center justify-between mt-0.5">
          <div className="flex items-center gap-2">
            {result.server && (
              <span style={{ fontSize: 9, color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                {truncate(result.server, 20)}
              </span>
            )}
            {result.contentLength > 0 && (
              <span style={{ fontSize: 9, color: 'var(--text-dim)' }}>
                {formatSize(result.contentLength)}
              </span>
            )}
          </div>
          <span style={{ fontSize: 9, color: 'var(--text-dim)' }}>
            {result.durationMs}ms
          </span>
        </div>

        {/* Keywords */}
        {result.keywords && result.keywords.length > 0 && (
          <div className="flex flex-wrap gap-1 mt-0.5">
            {result.keywords.slice(0, 4).map(kw => (
              <span key={kw} className="kw-badge">{kw}</span>
            ))}
            {result.keywords.length > 4 && (
              <span className="kw-badge">+{result.keywords.length - 4}</span>
            )}
          </div>
        )}

        {indicators.length > 0 && (
          <div className="mt-1 pt-1" style={{ borderTop: '1px solid var(--border-dim)' }}>
            <div className="flex items-center justify-between gap-2">
              <span style={{ fontSize: 9, color: riskColor(riskLevel), textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                {riskLevel}
              </span>
              {result.intelligence.brandCandidate && (
                <span style={{ fontSize: 9, color: 'var(--purple)' }}>
                  brand: {result.intelligence.brandCandidate}
                </span>
              )}
            </div>
            <span className="block truncate" style={{ fontSize: 9, color: 'var(--text-dim)' }} title={indicators.join(' | ')}>
              {indicators[0]}
            </span>
          </div>
        )}
      </div>

      {/* Selection indicator */}
      <div className="card-scan-depth" />
      <div className="card-glow" />
    </div>
  );
}

function getStatusClass(status: number): string {
  if (status >= 200 && status < 300) return 'status-2xx';
  if (status >= 300 && status < 400) return 'status-3xx';
  if (status >= 400 && status < 500) return 'status-4xx';
  if (status >= 500) return 'status-5xx';
  return 'status-err';
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes}B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}K`;
  return `${(bytes / 1024 / 1024).toFixed(1)}M`;
}

function riskColor(level: string): string {
  if (level === 'critical') return 'var(--red)';
  if (level === 'high') return '#ff6d00';
  if (level === 'medium') return 'var(--amber)';
  return 'var(--green)';
}

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n) + '…' : s;
}
