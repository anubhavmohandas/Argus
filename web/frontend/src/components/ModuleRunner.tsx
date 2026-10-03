import { useEffect, useRef, useState } from "react";
import type { Finding, RunState } from "../types";
import { runModule, health } from "../api";
import { sevRank } from "../lib";
import FindingCard from "./FindingCard";

// target hint per module kind
const HINTS: Record<string, string> = {
  ip: "an IP address, e.g. 8.8.8.8",
  phone: "a phone number, e.g. +14155552671",
  username: "a username, e.g. torvalds",
  secrets: "a file or directory path on the server",
  dns: "a domain, e.g. example.com",
  rdap: "a domain, e.g. example.com",
  subdomains: "a domain, e.g. example.com",
  wayback: "a domain, e.g. example.com",
};

const LABELS: Record<string, string> = {
  ip: "IP intel", phone: "Phone", username: "Username", secrets: "File secrets",
  dns: "DNS", rdap: "RDAP", subdomains: "Subdomains", wayback: "Wayback",
};

export default function ModuleRunner() {
  const [modules, setModules] = useState<string[]>([]);
  const [mod, setMod] = useState("ip");
  const [target, setTarget] = useState("");
  const [state, setState] = useState<RunState>("idle");
  const [log, setLog] = useState<string[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState<string | null>(null);
  const abortRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    health()
      .then((h) => {
        const u = h.utility_modules ?? [];
        setModules(u);
        if (u.length && !u.includes(mod)) setMod(u[0]);
      })
      .catch(() => setModules([]));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const run = () => {
    if (!target.trim() || state === "running") return;
    setState("running");
    setLog([]);
    setFindings([]);
    setError(null);
    abortRef.current = runModule(mod, target.trim(), {
      onStatus: (line) => setLog((l) => [...l, line]),
      onResult: (fs) =>
        setFindings([...fs].sort((a, b) => sevRank(b.severity) - sevRank(a.severity))),
      onError: (m) => {
        setError(m);
        setState("error");
      },
      onDone: () => setState((s) => (s === "error" ? s : "done")),
    });
  };

  const real = findings.filter((f) => sevRank(f.severity) > 0);
  const infoOnly = findings.filter((f) => sevRank(f.severity) === 0);

  return (
    <div className="border border-edge rounded-xl bg-panel">
      <div className="flex items-center gap-2 px-4 py-3 border-b border-edge bg-panel2">
        <span className="text-xs font-mono text-accent">modules</span>
        <span className="text-[11px] text-mute">run any recon module directly</span>
      </div>

      <div className="px-4 py-3">
        <div className="flex flex-wrap items-center gap-2">
          <select
            value={mod}
            onChange={(e) => setMod(e.target.value)}
            disabled={state === "running"}
            className="bg-base border border-edge rounded-lg px-2 py-2 text-xs font-mono text-ink
                       focus:outline-none focus:border-accent/50"
          >
            {(modules.length ? modules : [mod]).map((m) => (
              <option key={m} value={m}>
                {LABELS[m] ?? m}
              </option>
            ))}
          </select>
          <input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && run()}
            disabled={state === "running"}
            placeholder={HINTS[mod] ?? "target"}
            className="flex-1 min-w-[200px] bg-base border border-edge rounded-lg px-3 py-2 text-xs font-mono
                       text-ink placeholder:text-mute/60 focus:outline-none focus:border-accent/50"
          />
          <button
            onClick={run}
            disabled={!target.trim() || state === "running"}
            className="px-4 py-2 rounded-lg bg-accent text-base font-semibold text-xs
                       disabled:opacity-35 disabled:cursor-not-allowed hover:bg-accent/90"
          >
            {state === "running" ? "running…" : "Run"}
          </button>
        </div>

        {(log.length > 0 || error) && (
          <div className="mt-3 border border-edge rounded-lg bg-base max-h-28 overflow-y-auto px-3 py-2
                          font-mono text-[11px] leading-relaxed">
            {log.map((line, i) => (
              <div key={i} className="text-mute whitespace-pre-wrap break-all">{line}</div>
            ))}
            {error && <div className="text-critical">✗ {error}</div>}
          </div>
        )}

        {real.length > 0 && (
          <div className="mt-3 flex flex-col gap-2">
            {real.map((f, i) => <FindingCard key={i} f={f} />)}
          </div>
        )}
        {state === "done" && real.length === 0 && infoOnly.length > 0 && (
          <div className="mt-3 flex flex-col gap-2">
            {infoOnly.map((f, i) => <FindingCard key={i} f={f} />)}
          </div>
        )}
        {state === "done" && findings.length === 0 && !error && (
          <div className="mt-2 text-[11px] font-mono text-mute">no results.</div>
        )}
      </div>
    </div>
  );
}
