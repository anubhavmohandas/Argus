import { useState, useMemo } from 'react';
import type { ScanResult, FilterState, SortField, SortDir } from '../types';

const DEFAULT_FILTERS: FilterState = {
  search: '',
  statusCodes: [],
  interesting: false,
  hasScreenshot: false,
  minSize: 0,
  maxSize: 0,
  keywords: [],
  errorOnly: false,
  liveOnly: false,
  riskLevels: [],
  minRisk: 0,
  category: '',
};

export function useFilters(results: ScanResult[]) {
  const [filters, setFilters] = useState<FilterState>(DEFAULT_FILTERS);
  const [sortField, setSortField] = useState<SortField>('timestamp');
  const [sortDir, setSortDir] = useState<SortDir>('desc');

  const filtered = useMemo(() => {
    let out = [...results];

    // Search: match domain, title, URL
    if (filters.search) {
      const q = filters.search.toLowerCase();
      out = out.filter(r =>
        r.domain.toLowerCase().includes(q) ||
        r.title?.toLowerCase().includes(q) ||
        r.url?.toLowerCase().includes(q) ||
        r.server?.toLowerCase().includes(q) ||
        r.intelligence?.indicators?.some(i => i.toLowerCase().includes(q)) ||
        r.intelligence?.brandCandidate?.toLowerCase().includes(q)
      );
    }

    // Status codes
    if (filters.statusCodes.length > 0) {
      out = out.filter(r => filters.statusCodes.includes(r.status));
    }

    // Interesting only
    if (filters.interesting) {
      out = out.filter(r => r.interesting);
    }

    // Has screenshot
    if (filters.hasScreenshot) {
      out = out.filter(r => r.screenshot && r.screenshot.length > 0);
    }

    // Error only
    if (filters.errorOnly) {
      out = out.filter(r => !!r.error);
    }

    // Live only (status > 0, no error)
    if (filters.liveOnly) {
      out = out.filter(r => r.status > 0 && !r.error);
    }

    // Min size
    if (filters.minSize > 0) {
      out = out.filter(r => r.contentLength >= filters.minSize);
    }

    // Max size
    if (filters.maxSize > 0) {
      out = out.filter(r => r.contentLength <= filters.maxSize);
    }

    // Keywords
    if (filters.keywords.length > 0) {
      out = out.filter(r =>
        filters.keywords.some(kw => r.keywords?.includes(kw) || r.intelligence?.categories?.includes(kw))
      );
    }

    if (filters.riskLevels.length > 0) {
      out = out.filter(r => filters.riskLevels.includes(r.intelligence?.riskLevel || 'low'));
    }

    if (filters.minRisk > 0) {
      out = out.filter(r => (r.intelligence?.riskScore || 0) >= filters.minRisk);
    }

    if (filters.category) {
      out = out.filter(r => r.intelligence?.categories?.includes(filters.category));
    }

    // Sort
    out.sort((a, b) => {
      let av: string | number = sortField === 'riskScore' ? (a.intelligence?.riskScore || 0) : (a[sortField] as string | number ?? '');
      let bv: string | number = sortField === 'riskScore' ? (b.intelligence?.riskScore || 0) : (b[sortField] as string | number ?? '');
      if (sortDir === 'asc') return av < bv ? -1 : av > bv ? 1 : 0;
      return av > bv ? -1 : av < bv ? 1 : 0;
    });

    return out;
  }, [results, filters, sortField, sortDir]);

  const updateFilter = <K extends keyof FilterState>(key: K, value: FilterState[K]) => {
    setFilters(prev => ({ ...prev, [key]: value }));
  };

  const resetFilters = () => setFilters(DEFAULT_FILTERS);

  const toggleStatusCode = (code: number) => {
    setFilters(prev => ({
      ...prev,
      statusCodes: prev.statusCodes.includes(code)
        ? prev.statusCodes.filter(c => c !== code)
        : [...prev.statusCodes, code],
    }));
  };

  const toggleKeyword = (kw: string) => {
    setFilters(prev => ({
      ...prev,
      keywords: prev.keywords.includes(kw)
        ? prev.keywords.filter(k => k !== kw)
        : [...prev.keywords, kw],
    }));
  };

  const toggleRiskLevel = (level: FilterState['riskLevels'][number]) => {
    setFilters(prev => ({
      ...prev,
      riskLevels: prev.riskLevels.includes(level)
        ? prev.riskLevels.filter(item => item !== level)
        : [...prev.riskLevels, level],
    }));
  };

  return {
    filters, filtered, sortField, sortDir,
    updateFilter, resetFilters, toggleStatusCode, toggleKeyword,
    toggleRiskLevel, setSortField, setSortDir,
  };
}
