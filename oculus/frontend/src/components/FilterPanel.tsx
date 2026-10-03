import type { FilterState, SortField, SortDir } from '../types';

const STATUS_FILTERS = [
  { code: 200, label: '200 OK', cls: 'status-2xx' },
  { code: 301, label: '301 Moved', cls: 'status-3xx' },
  { code: 302, label: '302 Found', cls: 'status-3xx' },
  { code: 401, label: '401 Unauth', cls: 'status-4xx' },
  { code: 403, label: '403 Forbidden', cls: 'status-4xx' },
  { code: 404, label: '404 Not Found', cls: 'status-4xx' },
  { code: 500, label: '500 Error', cls: 'status-5xx' },
  { code: 503, label: '503 Unavail', cls: 'status-5xx' },
];

const KEYWORD_FILTERS = [
  'admin', 'login', 'dashboard', 'panel', 'api',
  'staging', 'dev', 'internal', 'test', 'console',
  'grafana', 'jenkins', 'gitlab', 'jira', 'kibana',
  'vault', 'phpmyadmin', 'cpanel',
];

const RISK_FILTERS: FilterState['riskLevels'] = ['critical', 'high', 'medium', 'low'];
const CATEGORY_FILTERS = ['phishing', 'brand', 'credential', 'exposure', 'transport', 'baseline'];

interface FilterPanelProps {
  filters: FilterState;
  resultCount: number;
  filteredCount: number;
  sortField: SortField;
  sortDir: SortDir;
  onToggleStatus: (code: number) => void;
  onToggleKeyword: (kw: string) => void;
  onToggleRiskLevel: (level: FilterState['riskLevels'][number]) => void;
  onUpdateFilter: <K extends keyof FilterState>(k: K, v: FilterState[K]) => void;
  onReset: () => void;
  onSortField: (f: SortField) => void;
  onSortDir: (d: SortDir) => void;
}

export function FilterPanel({
  filters, resultCount, filteredCount,
  sortField, sortDir,
  onToggleStatus, onToggleKeyword, onUpdateFilter, onReset,
  onToggleRiskLevel,
  onSortField, onSortDir,
}: FilterPanelProps) {
  const activeFilters = filters.statusCodes.length + filters.keywords.length +
    (filters.interesting ? 1 : 0) + (filters.liveOnly ? 1 : 0) +
    (filters.errorOnly ? 1 : 0) + (filters.hasScreenshot ? 1 : 0) +
    filters.riskLevels.length + (filters.minRisk > 0 ? 1 : 0) + (filters.category ? 1 : 0);

  return (
    <aside
      className="flex flex-col overflow-y-auto"
      style={{
        width: 220, minWidth: 220,
        background: 'var(--bg-panel)',
        borderRight: '1px solid var(--border)',
      }}
    >
      {/* Header */}
      <div className="flex items-center justify-between px-3 py-2" style={{ borderBottom: '1px solid var(--border)' }}>
        <span className="text-xs" style={{ color: 'var(--text-dim)', letterSpacing: '0.12em' }}>FILTERS</span>
        <div className="flex items-center gap-2">
          {activeFilters > 0 && (
            <span className="text-xs px-1.5 py-0.5"
              style={{ background: 'rgba(0,230,118,0.12)', color: 'var(--green)', border: '1px solid rgba(0,230,118,0.2)' }}>
              {activeFilters}
            </span>
          )}
          {activeFilters > 0 && (
            <button onClick={onReset} className="text-xs" style={{ color: 'var(--text-dim)' }}>
              reset
            </button>
          )}
        </div>
      </div>

      {/* Result count */}
      <div className="px-3 py-2" style={{ borderBottom: '1px solid var(--border-dim)' }}>
        <span className="text-xs" style={{ color: 'var(--text-dim)' }}>
          showing{' '}
          <span style={{ color: 'var(--text-pri)' }}>{filteredCount.toLocaleString()}</span>
          {' '}of{' '}
          <span style={{ color: 'var(--text-sec)' }}>{resultCount.toLocaleString()}</span>
        </span>
      </div>

      <div className="flex flex-col gap-0 overflow-y-auto flex-1">
        {/* Search */}
        <Section label="SEARCH">
          <input
            type="text"
            placeholder="domain / title / server..."
            value={filters.search}
            onChange={e => onUpdateFilter('search', e.target.value)}
            className="scan-input w-full px-2 py-1.5 text-xs rounded-none"
            style={{ background: 'var(--bg-deep)' }}
          />
        </Section>

        {/* Quick filters */}
        <Section label="QUICK">
          {[
            { key: 'liveOnly' as keyof FilterState, label: 'Live only' },
            { key: 'interesting' as keyof FilterState, label: 'Interesting' },
            { key: 'hasScreenshot' as keyof FilterState, label: 'Has screenshot' },
            { key: 'errorOnly' as keyof FilterState, label: 'Errors only' },
          ].map(({ key, label }) => (
            <label key={key} className="flex items-center gap-2 cursor-pointer py-0.5">
              <input
                type="checkbox"
                checked={!!filters[key]}
                onChange={e => onUpdateFilter(key, e.target.checked as FilterState[typeof key])}
                style={{ accentColor: 'var(--green)' }}
              />
              <span className="text-xs" style={{ color: filters[key] ? 'var(--green)' : 'var(--text-sec)' }}>
                {label}
              </span>
            </label>
          ))}
        </Section>

        <Section label="MYTHOS RISK">
          <div className="grid grid-cols-2 gap-1">
            {RISK_FILTERS.map(level => (
              <button
                key={level}
                onClick={() => onToggleRiskLevel(level)}
                className="px-2 py-1 text-xs"
                style={{
                  border: '1px solid',
                  borderColor: filters.riskLevels.includes(level) ? riskColor(level) : 'var(--border)',
                  color: filters.riskLevels.includes(level) ? riskColor(level) : 'var(--text-dim)',
                  background: filters.riskLevels.includes(level) ? 'rgba(255,255,255,0.04)' : 'transparent',
                  textTransform: 'uppercase',
                  fontSize: 10,
                }}
              >
                {level}
              </button>
            ))}
          </div>
          <label className="block text-xs mt-3 mb-1" style={{ color: 'var(--text-dim)' }}>MIN SCORE</label>
          <input
            type="range"
            min={0}
            max={100}
            value={filters.minRisk}
            onChange={e => onUpdateFilter('minRisk', +e.target.value)}
            className="w-full"
            style={{ accentColor: 'var(--amber)' }}
          />
          <div className="flex justify-between text-xs" style={{ color: 'var(--text-dim)', fontSize: 10 }}>
            <span>0</span><span>{filters.minRisk}</span><span>100</span>
          </div>
          <select
            value={filters.category}
            onChange={e => onUpdateFilter('category', e.target.value)}
            className="scan-input w-full px-2 py-1.5 text-xs rounded-none mt-2"
            style={{ background: 'var(--bg-deep)' }}
          >
            <option value="">All categories</option>
            {CATEGORY_FILTERS.map(category => (
              <option key={category} value={category}>{category}</option>
            ))}
          </select>
        </Section>

        {/* HTTP Status */}
        <Section label="STATUS CODE">
          <div className="flex flex-col gap-0.5">
            {STATUS_FILTERS.map(({ code, label, cls }) => (
              <button
                key={code}
                onClick={() => onToggleStatus(code)}
                className={`flex items-center gap-2 px-2 py-1 text-xs text-left transition-colors ${filters.statusCodes.includes(code) ? 'filter-active' : ''}`}
                style={{
                  background: filters.statusCodes.includes(code) ? undefined : 'transparent',
                  border: '1px solid',
                  borderColor: filters.statusCodes.includes(code) ? undefined : 'transparent',
                }}
              >
                <span className={`text-xs font-mono ${cls}`}>{code}</span>
                <span style={{ color: 'var(--text-dim)' }}>{label.split(' ').slice(1).join(' ')}</span>
              </button>
            ))}
          </div>
        </Section>

        {/* Keywords */}
        <Section label="KEYWORDS">
          <div className="flex flex-wrap gap-1">
            {KEYWORD_FILTERS.map(kw => (
              <button
                key={kw}
                onClick={() => onToggleKeyword(kw)}
                className="text-xs px-1.5 py-0.5 transition-all"
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: 10,
                  border: '1px solid',
                  borderColor: filters.keywords.includes(kw) ? 'var(--green)' : 'var(--border)',
                  background: filters.keywords.includes(kw) ? 'rgba(0,230,118,0.1)' : 'transparent',
                  color: filters.keywords.includes(kw) ? 'var(--green)' : 'var(--text-dim)',
                }}
              >
                {kw}
              </button>
            ))}
          </div>
        </Section>

        {/* Size filter */}
        <Section label="RESPONSE SIZE">
          <div className="flex gap-2">
            <input
              type="number" placeholder="Min"
              value={filters.minSize || ''}
              onChange={e => onUpdateFilter('minSize', +e.target.value)}
              className="scan-input flex-1 px-2 py-1 text-xs rounded-none"
              style={{ background: 'var(--bg-deep)' }}
            />
            <input
              type="number" placeholder="Max"
              value={filters.maxSize || ''}
              onChange={e => onUpdateFilter('maxSize', +e.target.value)}
              className="scan-input flex-1 px-2 py-1 text-xs rounded-none"
              style={{ background: 'var(--bg-deep)' }}
            />
          </div>
          <span className="text-xs" style={{ color: 'var(--text-dim)' }}>bytes</span>
        </Section>

        {/* Sort */}
        <Section label="SORT">
          <select
            value={sortField}
            onChange={e => onSortField(e.target.value as SortField)}
            className="scan-input w-full px-2 py-1.5 text-xs rounded-none"
            style={{ background: 'var(--bg-deep)' }}
          >
            <option value="timestamp">Timestamp</option>
            <option value="riskScore">Risk Score</option>
            <option value="domain">Domain</option>
            <option value="status">Status</option>
            <option value="title">Title</option>
            <option value="contentLength">Size</option>
            <option value="durationMs">Duration</option>
          </select>
          <div className="flex gap-1 mt-1">
            {(['asc', 'desc'] as SortDir[]).map(d => (
              <button key={d} onClick={() => onSortDir(d)}
                className="flex-1 py-1 text-xs"
                style={{
                  border: '1px solid',
                  borderColor: sortDir === d ? 'var(--green)' : 'var(--border)',
                  color: sortDir === d ? 'var(--green)' : 'var(--text-dim)',
                  background: sortDir === d ? 'rgba(0,230,118,0.08)' : 'transparent',
                }}>
                {d === 'asc' ? 'ASC' : 'DESC'}
              </button>
            ))}
          </div>
        </Section>
      </div>
    </aside>
  );
}

function riskColor(level: string): string {
  if (level === 'critical') return 'var(--red)';
  if (level === 'high') return '#ff6d00';
  if (level === 'medium') return 'var(--amber)';
  return 'var(--green)';
}

function Section({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="px-3 py-3" style={{ borderBottom: '1px solid var(--border-dim)' }}>
      <div className="text-xs mb-2" style={{ color: 'var(--text-dim)', letterSpacing: '0.12em' }}>{label}</div>
      {children}
    </div>
  );
}
