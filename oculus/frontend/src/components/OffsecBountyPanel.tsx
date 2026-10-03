import { useMemo, useState } from 'react';
import type { ScanResult } from '../types';

interface OffsecBountyPanelProps {
  results: ScanResult[];
  onClose: () => void;
  onDeepPivot: (seeds: string[]) => void;
  onReconTrails: (seeds: string[]) => void;
}

type BountyFinding = {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: string;
  domain: string;
  url: string;
  status: number;
  evidence: string[];
  recommendation: string;
  result: ScanResult;
};

export function OffsecBountyPanel({ results, onClose, onDeepPivot, onReconTrails }: OffsecBountyPanelProps) {
  const [selectedId, setSelectedId] = useState('');
  const [filter, setFilter] = useState('all');
  const findings = useMemo(() => buildFindings(results), [results]);
  const filtered = filter === 'all' ? findings : findings.filter(finding => finding.severity === filter || finding.category === filter);
  const selected = findings.find(finding => finding.id === selectedId) || filtered[0] || null;
  const targets = uniqueStrings(filtered.map(finding => finding.result.intelligence?.rootDomain || finding.domain)).slice(0, 12);

  const exportReport = (format: 'json' | 'txt' | 'md') => {
    const content = formatBountyReport(filtered, format);
    downloadText(`reconvision_offsec_${new Date().toISOString().slice(0, 10)}.${format}`, content, format === 'json' ? 'application/json' : 'text/plain');
  };

  return (
    <div className="offsec-overlay">
      <div className="offsec-shell">
        <header className="offsec-head">
          <div>
            <span>AUTHORIZED BUG BOUNTY TRIAGE</span>
            <h1>OFFSEC WORKBENCH</h1>
            <p>Prioritizes safe, reportable reconnaissance signals from your current scan: exposed admin surfaces, auth gates, weak transport, brand-risk pages, server errors, interesting titles, and screenshot-backed evidence.</p>
          </div>
          <div className="offsec-actions">
            <button onClick={() => exportReport('md')} disabled={!filtered.length}>MD</button>
            <button onClick={() => exportReport('txt')} disabled={!filtered.length}>TXT</button>
            <button onClick={() => exportReport('json')} disabled={!filtered.length}>JSON</button>
            <button onClick={() => onReconTrails(targets)} disabled={!targets.length}>RECONTRAILS</button>
            <button onClick={() => onDeepPivot(targets)} disabled={!targets.length}>DEEP PIVOT</button>
            <button onClick={onClose}>CLOSE</button>
          </div>
        </header>

        <section className="offsec-metrics">
          <Metric label="FINDINGS" value={findings.length} tone="var(--green)" />
          <Metric label="CRITICAL" value={countBy(findings, 'critical')} tone="var(--red)" />
          <Metric label="HIGH" value={countBy(findings, 'high')} tone="#ff6d00" />
          <Metric label="AUTH / ADMIN" value={findings.filter(f => f.category === 'access-control' || f.category === 'admin-surface').length} tone="var(--amber)" />
          <Metric label="SCREENSHOTS" value={findings.filter(f => f.result.screenshot).length} tone="var(--blue)" />
        </section>

        <section className="offsec-controls">
          {['all', 'critical', 'high', 'medium', 'admin-surface', 'access-control', 'transport', 'brand-risk', 'server-error'].map(item => (
            <button key={item} className={filter === item ? 'active' : ''} onClick={() => setFilter(item)}>{item.toUpperCase()}</button>
          ))}
        </section>

        <section className="offsec-body">
          <main className="offsec-list">
            {!filtered.length && <div className="offsec-empty">No bug bounty signals in the current view. Run a scan or loosen filters.</div>}
            {filtered.map(finding => (
              <button key={finding.id} className={`offsec-row ${selected?.id === finding.id ? 'selected' : ''}`} onClick={() => setSelectedId(finding.id)}>
                <span className={`offsec-sev ${finding.severity}`}>{finding.severity}</span>
                <span title={finding.domain}>{finding.domain}</span>
                <span>{finding.category}</span>
                <span>{finding.status || 'ERR'}</span>
                <b title={finding.title}>{finding.title}</b>
              </button>
            ))}
          </main>

          <aside className="offsec-detail">
            {selected ? (
              <FindingDetail finding={selected} onDeepPivot={onDeepPivot} onReconTrails={onReconTrails} />
            ) : (
              <div className="offsec-empty compact">Select a finding to inspect evidence and prepare report notes.</div>
            )}
          </aside>
        </section>
      </div>
    </div>
  );
}

function FindingDetail({ finding, onDeepPivot, onReconTrails }: { finding: BountyFinding; onDeepPivot: (seeds: string[]) => void; onReconTrails: (seeds: string[]) => void }) {
  const root = finding.result.intelligence?.rootDomain || finding.domain;
  return (
    <div className="offsec-finding">
      {finding.result.screenshot && <img src={`data:image/png;base64,${finding.result.screenshot}`} alt={finding.domain} />}
      <span className={`offsec-sev ${finding.severity}`}>{finding.severity}</span>
      <h2>{finding.title}</h2>
      <p>{finding.url || finding.domain}</p>
      <div className="offsec-actions inline">
        <button onClick={() => navigator.clipboard.writeText(formatBountyReport([finding], 'md')).catch(() => {})}>COPY REPORT</button>
        <button onClick={() => onReconTrails([root])}>RECONTRAILS</button>
        <button onClick={() => onDeepPivot([root])}>DEEP PIVOT</button>
        {finding.url && <a href={finding.url} target="_blank" rel="noopener noreferrer">OPEN</a>}
      </div>
      <KV label="Domain" value={finding.domain} />
      <KV label="Status" value={String(finding.status || 'ERROR')} />
      <KV label="Risk" value={`${finding.result.intelligence?.riskLevel || '-'} ${finding.result.intelligence?.riskScore || 0}`} />
      <KV label="IP" value={finding.result.intelligence?.ipAddress || '-'} />
      <KV label="Server" value={finding.result.server || '-'} />
      <KV label="Root" value={root} />
      <section>
        <h3>Evidence</h3>
        {finding.evidence.map(item => <div className="offsec-evidence" key={item}>{item}</div>)}
      </section>
      <section>
        <h3>Report Guidance</h3>
        <div className="offsec-note">{finding.recommendation}</div>
      </section>
    </div>
  );
}

function buildFindings(results: ScanResult[]): BountyFinding[] {
  const findings: BountyFinding[] = [];
  for (const result of safeArray(results)) {
    const intel = result.intelligence;
    const domain = result.domain || intel?.hostname || '';
    const url = result.url || domain;
    const joined = `${domain} ${url} ${result.title} ${safeArray(result.keywords).join(' ')} ${safeArray(intel?.indicators).join(' ')}`.toLowerCase();
    const add = (title: string, severity: BountyFinding['severity'], category: string, evidence: string[], recommendation: string) => {
      findings.push({
        id: `${domain}-${category}-${findings.length}`,
        title,
        severity,
        category,
        domain,
        url,
        status: result.status,
        evidence: uniqueStrings(evidence.filter(Boolean)),
        recommendation,
        result,
      });
    };

    if (result.status === 401 || result.status === 403) {
      add('Restricted or authenticated surface discovered', 'medium', 'access-control', [
        `HTTP ${result.status}`,
        result.title ? `Title: ${result.title}` : '',
        intel?.rootDomain ? `Root domain: ${intel.rootDomain}` : '',
      ], 'Validate this is in scope and document the exposed auth boundary. Do not brute force. Capture screenshot, headers, and business impact if the panel reveals product or internal environment context.');
    }
    if (/\b(admin|dashboard|console|manager|cpanel|phpmyadmin|grafana|jenkins|jira|gitlab|kibana|sonar|vault)\b/.test(joined)) {
      add('Administrative or sensitive tool surface', riskFromScore(intel?.riskScore || 0, 'high'), 'admin-surface', [
        `Matched keywords: ${safeArray(result.keywords).join(', ') || 'title/domain match'}`,
        result.title ? `Title: ${result.title}` : '',
        result.server ? `Server: ${result.server}` : '',
      ], 'Confirm authorization and capture non-invasive evidence only: URL, title, status, screenshot, and why the surface may be sensitive. Avoid login attempts unless the program explicitly permits testing.');
    }
    if (!result.tls && result.status > 0) {
      add('Live host without TLS', 'low', 'transport', [
        'HTTP service responded without TLS',
        `Status: ${result.status}`,
      ], 'Report only when the program treats missing HTTPS as valid impact, or when combined with login/session handling. Include the exact URL and screenshot.');
    }
    if ((intel?.brandCandidate || '') && safeArray(intel?.categories).includes('brand')) {
      add('Brand impersonation signal', riskFromScore(intel?.riskScore || 0, 'high'), 'brand-risk', [
        `Brand candidate: ${intel?.brandCandidate}`,
        ...safeArray(intel?.indicators).slice(0, 4),
      ], 'Use Brand Logo Watch for visual verification before reporting. Attach screenshot evidence and explain why the domain is not an authorized brand property.');
    }
    if (result.status >= 500) {
      add('Server error response on live host', 'low', 'server-error', [
        `HTTP ${result.status}`,
        result.server ? `Server: ${result.server}` : '',
        result.title ? `Title: ${result.title}` : '',
      ], 'Usually informational by itself. Prioritize if the response leaks stack traces, environment names, or debug data in the screenshot/title.');
    }
    if (joined.includes('staging') || joined.includes('dev') || joined.includes('test') || joined.includes('internal')) {
      add('Non-production environment exposed', riskFromScore(intel?.riskScore || 0, 'medium'), 'environment', [
        'Environment keyword detected',
        result.title ? `Title: ${result.title}` : '',
        domain ? `Domain: ${domain}` : '',
      ], 'Confirm whether the asset is in scope. Non-production systems can be high value when they expose real data, weaker auth, or debug panels.');
    }
  }
  return dedupeFindings(findings).sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.domain.localeCompare(b.domain));
}

function formatBountyReport(findings: BountyFinding[], format: 'json' | 'txt' | 'md'): string {
  if (format === 'json') {
    return JSON.stringify(findings.map(finding => ({
      title: finding.title,
      severity: finding.severity,
      category: finding.category,
      domain: finding.domain,
      url: finding.url,
      status: finding.status,
      evidence: finding.evidence,
      recommendation: finding.recommendation,
    })), null, 2);
  }
  if (format === 'md') {
    return [
      '# ReconVision OffSec Bug Bounty Triage',
      '',
      `Generated: ${new Date().toISOString()}`,
      `Findings: ${findings.length}`,
      '',
      ...findings.map(finding => [
        `## ${finding.severity.toUpperCase()} - ${finding.title}`,
        '',
        `- Domain: ${finding.domain}`,
        `- URL: ${finding.url || '-'}`,
        `- Status: ${finding.status || 'ERROR'}`,
        `- Category: ${finding.category}`,
        '',
        'Evidence:',
        ...finding.evidence.map(item => `- ${item}`),
        '',
        `Recommendation: ${finding.recommendation}`,
      ].join('\n')),
    ].join('\n\n');
  }
  return findings.map(finding => [
    `${finding.severity.toUpperCase()} ${finding.title}`,
    `Domain: ${finding.domain}`,
    `URL: ${finding.url || '-'}`,
    `Status: ${finding.status || 'ERROR'}`,
    `Category: ${finding.category}`,
    `Evidence: ${finding.evidence.join('; ')}`,
    `Recommendation: ${finding.recommendation}`,
  ].join('\n')).join('\n\n');
}

function Metric({ label, value, tone }: { label: string; value: number; tone: string }) {
  return <div className="offsec-metric"><span>{label}</span><strong style={{ color: tone }}>{value.toLocaleString()}</strong></div>;
}

function KV({ label, value }: { label: string; value: string }) {
  return <div className="offsec-kv"><span>{label}</span><b title={value}>{value}</b></div>;
}

function countBy(findings: BountyFinding[], severity: BountyFinding['severity']) {
  return findings.filter(finding => finding.severity === severity).length;
}

function riskFromScore(score: number, fallback: BountyFinding['severity']): BountyFinding['severity'] {
  if (score >= 70) return 'critical';
  if (score >= 45) return 'high';
  if (score >= 20) return 'medium';
  return fallback;
}

function severityRank(severity: BountyFinding['severity']): number {
  return { low: 1, medium: 2, high: 3, critical: 4 }[severity] || 0;
}

function dedupeFindings(findings: BountyFinding[]): BountyFinding[] {
  const seen = new Set<string>();
  const out: BountyFinding[] = [];
  for (const finding of findings) {
    const key = `${finding.domain}|${finding.category}|${finding.title}`.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(finding);
  }
  return out;
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

function downloadText(filename: string, text: string, type: string) {
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
