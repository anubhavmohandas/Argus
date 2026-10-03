import { useState, useRef, useCallback } from 'react';
import type { ScanResult, ScanConfig, ProgressEvent } from '../types';

const API_BASE = import.meta.env.VITE_API_URL || '';

interface UseScanReturn {
  results: ScanResult[];
  progress: ProgressEvent;
  isScanning: boolean;
  jobId: string | null;
  error: string | null;
  startScan: (domains: string[], config: ScanConfig) => void;
  stopScan: () => void;
  clearResults: () => void;
}

export function useScan(): UseScanReturn {
  const [results, setResults] = useState<ScanResult[]>([]);
  const [progress, setProgress] = useState<ProgressEvent>({ total: 0, processed: 0, live: 0, errors: 0 });
  const [isScanning, setIsScanning] = useState(false);
  const [jobId, setJobId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const startScan = useCallback(async (domains: string[], config: ScanConfig) => {
    if (isScanning) return;

    setResults([]);
    setError(null);
    setIsScanning(true);
    setProgress({ total: domains.length, processed: 0, live: 0, errors: 0 });

    abortRef.current = new AbortController();

    try {
      const response = await fetch(`${API_BASE}/api/scan/stream`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domains, config }),
        signal: abortRef.current.signal,
      });

      if (!response.ok) {
        const msg = await response.text();
        throw new Error(`Server error: ${msg}`);
      }

      const reader = response.body?.getReader();
      if (!reader) throw new Error('No response body');

      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const events = buffer.split('\n\n');
        buffer = events.pop() || '';

        for (const event of events) {
          if (!event.trim()) continue;

          const lines = event.split('\n');
          let eventType = '';
          let dataStr = '';

          for (const line of lines) {
            if (line.startsWith('event: ')) eventType = line.slice(7);
            if (line.startsWith('data: ')) dataStr = line.slice(6);
          }

          if (!dataStr) continue;

          try {
            const data = JSON.parse(dataStr);

            switch (eventType) {
              case 'start':
                setJobId(data.jobId);
                break;
              case 'result':
                setResults(prev => {
                  const key = resultKey(data);
                  return [data, ...prev.filter(item => resultKey(item) !== key)];
                });
                setProgress(prev => ({
                  ...prev,
                  processed: prev.processed + 1,
                  live: data.status > 0 && !data.error ? prev.live + 1 : prev.live,
                  errors: data.error ? prev.errors + 1 : prev.errors,
                }));
                break;
              case 'progress':
                setProgress(data);
                break;
              case 'done':
                setProgress({
                  total: data.total,
                  processed: data.processed,
                  live: data.live,
                  errors: data.errors,
                });
                break;
            }
          } catch {
            // malformed SSE data, skip
          }
        }
      }
    } catch (err: unknown) {
      if (err instanceof Error && err.name === 'AbortError') {
        // user cancelled
      } else {
        setError(err instanceof Error ? err.message : 'Unknown error');
      }
    } finally {
      setIsScanning(false);
    }
  }, [isScanning]);

  const stopScan = useCallback(() => {
    abortRef.current?.abort();
    setIsScanning(false);
  }, []);

  const clearResults = useCallback(() => {
    setResults([]);
    setJobId(null);
    setProgress({ total: 0, processed: 0, live: 0, errors: 0 });
    setError(null);
  }, []);

  return { results, progress, isScanning, jobId, error, startScan, stopScan, clearResults };
}

function resultKey(result: ScanResult): string {
  const domain = (result.domain || '').trim().toLowerCase();
  const url = (result.url || '').trim().toLowerCase();
  return domain || url || result.id;
}
