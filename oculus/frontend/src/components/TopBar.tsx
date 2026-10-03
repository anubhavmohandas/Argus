import React, { useState, useRef } from 'react';
import type { ScanConfig } from '../types';

interface TopBarProps {
  isScanning: boolean;
  jobId: string | null;
  resultCount: number;
  onStartScan: (domains: string[], config: ScanConfig) => void;
  onStopScan: () => void;
  onClear: () => void;
  onExport: (format: string) => void;
  onExportCurrent: (format: string) => void;
  liveCount: number;
  isPivoting: boolean;
  onPivotLive: () => void;
  onOpenGraph: () => void;
  onOpenBrandWatch: () => void;
  onOpenDeepPivot: () => void;
  onOpenReconTrails: () => void;
  onOpenOffsecBounty: () => void;
}

const DEFAULT_CONFIG: ScanConfig = {
  concurrency: 150,
  screenWorkers: 6,
  timeoutSeconds: 10,
  screenshotMode: 'viewport',
  maxRetries: 1,
  skipScreenshots: false,
  onlyLive: false,
  followRedirects: true,
};

export function TopBar({
  isScanning,
  jobId,
  resultCount,
  onStartScan,
  onStopScan,
  onClear,
  onExport,
  onExportCurrent,
  liveCount,
  isPivoting,
  onPivotLive,
  onOpenGraph,
  onOpenBrandWatch,
  onOpenDeepPivot,
  onOpenReconTrails,
  onOpenOffsecBounty,
}: TopBarProps) {
  const [showInput, setShowInput] = useState(false);
  const [showConfig, setShowConfig] = useState(false);
  const [domains, setDomains] = useState('');
  const [config, setConfig] = useState<ScanConfig>(DEFAULT_CONFIG);
  const fileRef = useRef<HTMLInputElement>(null);

  const handleFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = ev => {
      setDomains(prev => {
        const add = ev.target?.result as string ?? '';
        return prev ? prev + '\n' + add : add;
      });
      setShowInput(true);
    };
    reader.readAsText(file);
    e.target.value = '';
  };

  const parseDomains = () => parseTargetText(domains).unique;

  const handleStart = () => {
    const parsed = parseDomains();
    if (parsed.length === 0) return;
    onStartScan(parsed, config);
    setShowInput(false);
  };

  const handlePasteClipboard = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (!text) return;
      setDomains(prev => prev ? `${prev}\n${text}` : text);
      setShowInput(true);
    } catch {
      // Clipboard permission may be blocked by the browser.
    }
  };

  const handleDedupe = () => {
    const parsed = parseTargetText(domains);
    setDomains(parsed.unique.join('\n'));
  };

  const targetStats = parseTargetText(domains);
  const domainCount = targetStats.unique.length;

  return (
    <header className="topbar flex flex-col border-b" style={{ background: 'var(--bg-panel)', borderColor: 'var(--border)' }}>
      {/* Main bar */}
      <div className="flex items-center gap-2 px-4 py-2">
        {/* Logo */}
        <div className="flex items-center gap-2 mr-4">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
            <circle cx="12" cy="12" r="10" stroke="var(--green)" strokeWidth="1.5"/>
            <circle cx="12" cy="12" r="4" stroke="var(--green)" strokeWidth="1"/>
            <line x1="12" y1="2" x2="12" y2="5" stroke="var(--green)" strokeWidth="1.5"/>
            <line x1="12" y1="19" x2="12" y2="22" stroke="var(--green)" strokeWidth="1.5"/>
            <line x1="2" y1="12" x2="5" y2="12" stroke="var(--green)" strokeWidth="1.5"/>
            <line x1="19" y1="12" x2="22" y2="12" stroke="var(--green)" strokeWidth="1.5"/>
          </svg>
          <span style={{ fontFamily: 'var(--font-ui)', fontSize: 16, fontWeight: 700, color: 'var(--text-pri)', letterSpacing: '0.12em' }}>
            RECONVISION
          </span>
          <span style={{ fontSize: 9, color: 'var(--green)', opacity: 0.7, letterSpacing: '0.1em' }}>v1.0</span>
        </div>

        {/* Divider */}
        <div className="h-6 w-px" style={{ background: 'var(--border)' }} />

        {/* Input controls */}
        <button
          onClick={() => setShowInput(!showInput)}
          className="topbar-button flex items-center gap-2 px-3 py-1.5 text-xs transition-colors"
          style={{
            background: showInput ? 'rgba(0,230,118,0.1)' : 'transparent',
            border: '1px solid',
            borderColor: showInput ? 'var(--green)' : 'var(--border)',
            color: showInput ? 'var(--green)' : 'var(--text-sec)',
          }}
        >
          <span>+</span> TARGETS
        </button>

        <button
          onClick={() => fileRef.current?.click()}
          className="topbar-button flex items-center gap-2 px-3 py-1.5 text-xs transition-colors"
          style={{ border: '1px solid var(--border)', color: 'var(--text-sec)', background: 'transparent' }}
        >
          IMPORT
        </button>
        <input ref={fileRef} type="file" accept=".txt,.csv" onChange={handleFile} className="hidden" />

        <button
          onClick={() => setShowConfig(!showConfig)}
          className="topbar-button flex items-center gap-2 px-3 py-1.5 text-xs transition-colors"
          style={{
            border: '1px solid',
            borderColor: showConfig ? 'var(--amber)' : 'var(--border)',
            color: showConfig ? 'var(--amber)' : 'var(--text-sec)',
            background: showConfig ? 'rgba(255, 171, 0, 0.08)' : 'transparent',
          }}
        >
          CONFIG
        </button>

        <div className="flex-1" />

        {/* Scan status */}
        {jobId && (
          <span className="text-xs" style={{ color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
            {jobId}
          </span>
        )}

        {/* Export */}
        {resultCount > 0 && !isScanning && (
          <div className="flex items-center gap-1">
            <span className="text-xs" style={{ color: 'var(--text-dim)', fontSize: 9, letterSpacing: '0.08em' }}>
              CURRENT
            </span>
            {['csv', 'json', 'txt', 'md'].map(fmt => (
              <button
                key={`current-${fmt}`}
                onClick={() => onExportCurrent(fmt)}
                className="px-2 py-1 text-xs transition-colors"
                style={{
                  border: '1px solid var(--border)',
                  color: 'var(--green)',
                  background: 'rgba(0,230,118,0.04)',
                  letterSpacing: '0.05em',
                }}
                title="Export current visible/filtered results"
              >
                {fmt.toUpperCase()}
              </button>
            ))}
            {jobId && (
              <span className="text-xs ml-2" style={{ color: 'var(--text-dim)', fontSize: 9, letterSpacing: '0.08em' }}>
                JOB
              </span>
            )}
            {['csv', 'json', 'txt', 'md'].map(fmt => (
              <button
                key={fmt}
                onClick={() => onExport(fmt)}
                disabled={!jobId}
                className="px-2 py-1 text-xs transition-colors"
                style={{
                  border: '1px solid var(--border)',
                  color: jobId ? 'var(--text-dim)' : 'rgba(61,81,102,0.45)',
                  background: 'transparent',
                  letterSpacing: '0.05em',
                }}
                title="Export full scan job"
                onMouseEnter={e => { (e.target as HTMLButtonElement).style.color = 'var(--blue)'; (e.target as HTMLButtonElement).style.borderColor = 'var(--blue)'; }}
                onMouseLeave={e => { (e.target as HTMLButtonElement).style.color = 'var(--text-dim)'; (e.target as HTMLButtonElement).style.borderColor = 'var(--border)'; }}
              >
                {fmt.toUpperCase()}
              </button>
            ))}
          </div>
        )}

        {resultCount > 0 && !isScanning && (
          <button
            onClick={onOpenGraph}
            className="topbar-button flex items-center gap-2 px-3 py-1.5 text-xs font-semibold"
            style={{
              border: '1px solid var(--purple)',
              color: 'var(--purple)',
              background: 'rgba(234,128,252,0.06)',
              letterSpacing: '0.08em',
            }}
            title="Open CTI relationship graph"
          >
            CTI GRAPH
          </button>
        )}

        <button
          onClick={onOpenBrandWatch}
          className="topbar-button flex items-center gap-2 px-3 py-1.5 text-xs font-semibold"
          style={{
            border: '1px solid var(--amber)',
            color: 'var(--amber)',
            background: 'rgba(255,171,0,0.06)',
            letterSpacing: '0.08em',
          }}
          title="Open URLScan Brand Logo Watch"
        >
          LOGO WATCH
        </button>

        <button
          onClick={onOpenDeepPivot}
          className="topbar-button flex items-center gap-2 px-3 py-1.5 text-xs font-semibold"
          style={{
            border: '1px solid var(--blue)',
            color: 'var(--blue)',
            background: 'rgba(64,196,255,0.06)',
            letterSpacing: '0.08em',
          }}
          title="Open multi-source public OSINT pivot workspace"
        >
          DEEP PIVOT
        </button>

        <button
          onClick={onOpenReconTrails}
          className="topbar-button flex items-center gap-2 px-3 py-1.5 text-xs font-semibold"
          style={{
            border: '1px solid var(--green)',
            color: 'var(--green)',
            background: 'rgba(0,230,118,0.06)',
            letterSpacing: '0.08em',
          }}
          title="Open ReconTrails public domain intelligence"
        >
          RECONTRAILS
        </button>

        <button
          onClick={onOpenOffsecBounty}
          className="topbar-button flex items-center gap-2 px-3 py-1.5 text-xs font-semibold"
          style={{
            border: '1px solid #ff6d00',
            color: '#ffab40',
            background: 'rgba(255,109,0,0.07)',
            letterSpacing: '0.08em',
          }}
          title="Open authorized bug bounty triage workbench"
        >
          OFFSEC
        </button>

        {resultCount > 0 && !isScanning && (
          <button
            onClick={onPivotLive}
            disabled={liveCount === 0 || isPivoting}
            className="topbar-button flex items-center gap-2 px-3 py-1.5 text-xs font-semibold"
            style={{
              border: '1px solid',
              borderColor: liveCount > 0 ? 'var(--blue)' : 'var(--border)',
              color: liveCount > 0 ? 'var(--blue)' : 'var(--text-dim)',
              background: isPivoting ? 'rgba(64,196,255,0.14)' : 'rgba(64,196,255,0.06)',
              cursor: liveCount > 0 && !isPivoting ? 'pointer' : 'not-allowed',
              letterSpacing: '0.08em',
            }}
            title="Pivot every live result through URLScan"
          >
            {isPivoting ? 'PIVOTING' : 'PIVOT LIVE'}
            <span style={{ opacity: 0.75 }}>({liveCount.toLocaleString()})</span>
          </button>
        )}

        {/* Clear */}
        {resultCount > 0 && !isScanning && (
          <button
            onClick={onClear}
            className="px-3 py-1.5 text-xs transition-colors"
            style={{ border: '1px solid var(--border)', color: 'var(--text-dim)', background: 'transparent' }}
          >
            CLEAR
          </button>
        )}

        {/* Scan button */}
        {!isScanning ? (
          <button
            onClick={handleStart}
            disabled={domainCount === 0 || !showInput}
            className="flex items-center gap-2 px-4 py-1.5 text-xs font-semibold transition-all"
            style={{
              background: domainCount > 0 && showInput ? 'var(--green)' : 'var(--border)',
              color: domainCount > 0 && showInput ? '#000' : 'var(--text-dim)',
              border: 'none',
              cursor: domainCount > 0 && showInput ? 'pointer' : 'not-allowed',
              letterSpacing: '0.1em',
            }}
          >
            RUN SCAN
            {domainCount > 0 && (
              <span style={{ opacity: 0.7 }}>({domainCount.toLocaleString()})</span>
            )}
          </button>
        ) : (
          <button
            onClick={onStopScan}
            className="flex items-center gap-2 px-4 py-1.5 text-xs font-semibold"
            style={{ background: 'var(--red)', color: '#fff', border: 'none', letterSpacing: '0.1em' }}
          >
            ■ STOP
          </button>
        )}
      </div>

      {/* Target input panel */}
      {showInput && (
        <div className="px-4 pb-3 flex gap-3" style={{ borderTop: '1px solid var(--border-dim)' }}>
          <div className="flex-1 pt-3">
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs" style={{ color: 'var(--text-dim)', letterSpacing: '0.1em' }}>
                TARGETS - ONE PER LINE OR COMMA-SEPARATED
              </span>
              <span className="text-xs" style={{ color: domainCount > 0 ? 'var(--green)' : 'var(--text-dim)' }}>
                {domainCount.toLocaleString()} unique / {targetStats.duplicates.toLocaleString()} duplicate
              </span>
            </div>
            <div className="flex items-center gap-2 mb-2">
              <button
                onClick={() => fileRef.current?.click()}
                className="topbar-button px-3 py-1 text-xs"
                style={{ border: '1px solid var(--border)', color: 'var(--text-sec)', background: 'transparent' }}
              >
                IMPORT TXT/CSV
              </button>
              <button
                onClick={handlePasteClipboard}
                className="topbar-button px-3 py-1 text-xs"
                style={{ border: '1px solid var(--border)', color: 'var(--text-sec)', background: 'transparent' }}
              >
                PASTE CLIPBOARD
              </button>
              <button
                onClick={handleDedupe}
                disabled={targetStats.raw === 0}
                className="topbar-button px-3 py-1 text-xs"
                style={{
                  border: '1px solid',
                  borderColor: targetStats.duplicates > 0 ? 'var(--amber)' : 'var(--border)',
                  color: targetStats.duplicates > 0 ? 'var(--amber)' : 'var(--text-dim)',
                  background: targetStats.duplicates > 0 ? 'rgba(255,171,0,0.08)' : 'transparent',
                }}
              >
                DE-DUP / NORMALIZE
              </button>
              <span className="text-xs" style={{ color: 'var(--text-dim)' }}>
                imported {targetStats.raw.toLocaleString()} / removed {targetStats.duplicates.toLocaleString()}
              </span>
            </div>
            <textarea
              className="scan-input w-full rounded-none"
              rows={6}
              placeholder={'sub1.example.com\nadmin.target.com\ntest.example.com\n...'}
              value={domains}
              onChange={e => setDomains(e.target.value)}
              style={{ padding: '8px 10px' }}
            />
          </div>
        </div>
      )}

      {/* Config panel */}
      {showConfig && (
        <div className="px-4 pb-3 pt-3 grid grid-cols-4 gap-4" style={{ borderTop: '1px solid var(--border-dim)' }}>
          <ConfigField label="PROBE WORKERS" type="number"
            value={config.concurrency} min={1} max={500}
            onChange={v => setConfig(c => ({ ...c, concurrency: +v }))} />
          <ConfigField label="SCREEN WORKERS" type="number"
            value={config.screenWorkers} min={1} max={20}
            onChange={v => setConfig(c => ({ ...c, screenWorkers: +v }))} />
          <ConfigField label="TIMEOUT (SEC)" type="number"
            value={config.timeoutSeconds} min={3} max={60}
            onChange={v => setConfig(c => ({ ...c, timeoutSeconds: +v }))} />
          <ConfigField label="MAX RETRIES" type="number"
            value={config.maxRetries} min={0} max={5}
            onChange={v => setConfig(c => ({ ...c, maxRetries: +v }))} />
          <div>
            <label className="block text-xs mb-1" style={{ color: 'var(--text-dim)', letterSpacing: '0.1em' }}>SCREENSHOT MODE</label>
            <select
              className="scan-input w-full rounded-none px-2 py-1.5 text-xs"
              value={config.screenshotMode}
              onChange={e => setConfig(c => ({ ...c, screenshotMode: e.target.value as ScanConfig['screenshotMode'] }))}
              style={{ background: 'var(--bg-deep)' }}
            >
              <option value="viewport">Viewport (1280x800)</option>
              <option value="fullpage">Full Page</option>
              <option value="mobile">Mobile (390x844)</option>
            </select>
          </div>
          <div className="flex flex-col gap-2 pt-4">
            <label className="flex items-center gap-2 text-xs cursor-pointer" style={{ color: 'var(--text-sec)' }}>
              <input type="checkbox" checked={config.skipScreenshots}
                onChange={e => setConfig(c => ({ ...c, skipScreenshots: e.target.checked }))} />
              Skip Screenshots
            </label>
            <label className="flex items-center gap-2 text-xs cursor-pointer" style={{ color: 'var(--text-sec)' }}>
              <input type="checkbox" checked={config.onlyLive}
                onChange={e => setConfig(c => ({ ...c, onlyLive: e.target.checked }))} />
              Live Hosts Only
            </label>
          </div>
        </div>
      )}
    </header>
  );
}

function parseTargetText(value: string): { raw: number; unique: string[]; duplicates: number } {
  const seen = new Set<string>();
  const unique: string[] = [];
  let raw = 0;
  for (const token of value.split(/[\n,\s;]+/)) {
    const clean = normalizeTarget(token);
    if (!clean || !clean.includes('.')) continue;
    raw += 1;
    if (seen.has(clean)) continue;
    seen.add(clean);
    unique.push(clean);
  }
  return { raw, unique, duplicates: Math.max(0, raw - unique.length) };
}

function normalizeTarget(value: string): string {
  let clean = value.trim().toLowerCase();
  if (!clean) return '';
  clean = clean.replace(/^['"`<({\[]+|['"`>)}\]]+$/g, '');
  try {
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(clean)) {
      const parsed = new URL(clean);
      clean = parsed.hostname;
    }
  } catch {
    // Keep falling through to hostname cleanup.
  }
  clean = clean.replace(/^www\./, 'www.');
  clean = clean.split('/')[0].split('?')[0].split('#')[0];
  clean = clean.replace(/:\d+$/, '');
  clean = clean.replace(/^\*\./, '');
  clean = clean.replace(/\.+$/, '');
  return clean;
}

function ConfigField({ label, value, min, max, onChange, type = 'text' }: {
  label: string; value: number | string; min?: number; max?: number;
  onChange: (v: string) => void; type?: string;
}) {
  return (
    <div>
      <label className="block text-xs mb-1" style={{ color: 'var(--text-dim)', letterSpacing: '0.1em' }}>{label}</label>
      <input
        type={type} value={value} min={min} max={max}
        onChange={e => onChange(e.target.value)}
        className="scan-input w-full px-2 py-1.5 text-xs rounded-none"
        style={{ background: 'var(--bg-deep)' }}
      />
    </div>
  );
}
