import type { ProgressEvent } from '../types';

interface ScanProgressProps {
  progress: ProgressEvent;
  isScanning: boolean;
}

export function ScanProgress({ progress, isScanning }: ScanProgressProps) {
  const { total, processed, live, errors } = progress;
  if (total === 0) return null;

  const pct = total > 0 ? Math.round((processed / total) * 100) : 0;
  const dead = processed - live - errors;

  return (
    <div className="px-4 py-2 flex items-center gap-4" style={{ borderBottom: '1px solid var(--border)', background: 'var(--bg-deep)' }}>
      {/* Status dot */}
      <div className="flex items-center gap-2">
        <div
          className={isScanning ? 'pulse-dot' : ''}
          style={{
            width: 6, height: 6, borderRadius: '50%',
            background: isScanning ? 'var(--green)' : processed === total ? 'var(--blue)' : 'var(--text-dim)',
          }}
        />
        <span className="text-xs" style={{ color: 'var(--text-dim)', letterSpacing: '0.1em' }}>
          {isScanning ? 'SCANNING' : 'COMPLETE'}
        </span>
      </div>

      {/* Progress bar */}
      <div className="flex-1 progress-track">
        <div className="progress-fill" style={{ width: `${pct}%` }} />
        {isScanning && <div className="progress-scan-line" />}
      </div>

      {/* Stats */}
      <div className="flex items-center gap-4 text-xs" style={{ fontFamily: 'var(--font-mono)' }}>
        <Stat label="TOTAL" value={total.toLocaleString()} color="var(--text-sec)" />
        <Stat label="DONE" value={processed.toLocaleString()} color="var(--text-pri)" />
        <Stat label="LIVE" value={live.toLocaleString()} color="var(--green)" />
        <Stat label="DEAD" value={dead.toLocaleString()} color="var(--text-dim)" />
        <Stat label="ERR" value={errors.toLocaleString()} color="var(--red)" />
        <span style={{ color: 'var(--text-dim)' }}>{pct}%</span>
      </div>
    </div>
  );
}

function Stat({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <span className="flex items-center gap-1">
      <span style={{ color: 'var(--text-dim)', fontSize: 9, letterSpacing: '0.12em' }}>{label}</span>
      <span style={{ color }}>{value}</span>
    </span>
  );
}
