import { useMemo } from 'react';
import { ResultCard } from './ResultCard';
import type { ScanResult } from '../types';

interface ResultGridProps {
  results: ScanResult[];
  selected: ScanResult | null;
  isScanning: boolean;
  onSelect: (r: ScanResult) => void;
}

export function ResultGrid({ results, selected, isScanning, onSelect }: ResultGridProps) {
  if (results.length === 0) {
    return (
      <div className="empty-state flex flex-col items-center justify-center flex-1"
        style={{ color: 'var(--text-dim)', gap: 12 }}>
        {isScanning ? (
          <>
            <ScanSpinner />
            <span className="text-xs" style={{ letterSpacing: '0.15em' }}>SCANNING TARGETS...</span>
          </>
        ) : (
          <>
            <TargetReticle />
            <span className="text-xs" style={{ letterSpacing: '0.15em' }}>NO RESULTS YET</span>
            <span className="text-xs" style={{ color: 'var(--text-dim)', opacity: 0.5 }}>
              Upload targets and run a scan
            </span>
          </>
        )}
      </div>
    );
  }

  return (
    <div className="results-viewport flex-1 overflow-y-auto p-0">
      <div className="result-grid">
        {results.map(r => (
          <ResultCard
            key={r.id || r.domain}
            result={r}
            isSelected={selected?.id === r.id}
            onSelect={onSelect}
          />
        ))}
      </div>
    </div>
  );
}

function ScanSpinner() {
  return (
    <svg width="40" height="40" viewBox="0 0 40 40">
      <circle cx="20" cy="20" r="16" stroke="var(--border)" strokeWidth="1.5" fill="none" />
      <circle cx="20" cy="20" r="16" stroke="var(--green)" strokeWidth="1.5" fill="none"
        strokeDasharray="25 75" strokeLinecap="round">
        <animateTransform attributeName="transform" type="rotate"
          from="0 20 20" to="360 20 20" dur="1s" repeatCount="indefinite" />
      </circle>
      <circle cx="20" cy="20" r="3" fill="var(--green)" opacity="0.5" />
    </svg>
  );
}

function TargetReticle() {
  return (
    <svg width="60" height="60" viewBox="0 0 60 60" style={{ opacity: 0.3 }}>
      <circle cx="30" cy="30" r="28" stroke="var(--green)" strokeWidth="0.5" fill="none" />
      <circle cx="30" cy="30" r="18" stroke="var(--green)" strokeWidth="0.5" fill="none" />
      <circle cx="30" cy="30" r="8" stroke="var(--green)" strokeWidth="0.5" fill="none" />
      <line x1="30" y1="0" x2="30" y2="12" stroke="var(--green)" strokeWidth="0.5" />
      <line x1="30" y1="48" x2="30" y2="60" stroke="var(--green)" strokeWidth="0.5" />
      <line x1="0" y1="30" x2="12" y2="30" stroke="var(--green)" strokeWidth="0.5" />
      <line x1="48" y1="30" x2="60" y2="30" stroke="var(--green)" strokeWidth="0.5" />
    </svg>
  );
}
