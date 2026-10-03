import { useEffect, useRef, useState } from "react";
import type { Finding, RunState } from "../types";
import { runModule, health } from "../api";
import { sevRank } from "../lib";
import FindingCard from "./FindingCard";

const MODULES: { id: string; label: string; hint: string; needsToken?: boolean }[] = [
  { id: "postman_dork", label: "Postman", hint: "public Postman workspaces → leaked env tokens" },
  { id: "github_dork", label: "GitHub code", hint: "secrets in current public GitHub code", needsToken: true },
  { id: "github_org", label: "GitHub history", hint: "secrets in org repos' commit history", needsToken: true },
  { id: "jsmap", label: "JS bundles", hint: "secrets in archived JS / source-maps (Wayback)" },
];

export default function SecretRecon({ seed }: { seed: string }) {
  const [state, setState] = useState<RunState>("idle");
  const [active, setActive] = useState<string | null>(null);
  const [log, setLog] = useState<string[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [hasToken, setHasToken] = useState<boolean | null>(null);
  const abortRef = useRef<(() => void) | null>(null);
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    health().then((h) => setHasToken(!!h.github_token)).catch(() => setHasToken(null));
  }, []);
  useEffect(() => {
    endRef.current?.scrollIntoView({ block: "end" });
  }, [log.length]);

  const run = (mod: string) => {
    if (!seed || state === "running") return;
    setState("running");
    setActive(mod);
    setLog([]);
    setFindings([]);
    setError(null);
    abortRef.current = runModule(mod, seed, {
      onStatus: (line) => setLog((l) => [...l, line]),
      onResult: (fs) =>
        setFindings(
          [...fs].sort(
            (a, b) => sevRank(b.severity) - sevRank(a.severity) || (b.confidence ?? 0) - (a.confidence ?? 0)
          )
        ),
      onError: (m) => {
        setError(m);
        setState("error");
      },
      onDone: () => setState((s) => (s === "error" ? s : "done")),
    });
  };

  const real = findings.filter((f) => sevRank(f.severity) > 0); // hide pure info/no-op lines

  return (
    <div className="border border-edge rounded-xl bg-panel">
      <div className="flex items-center justify-between px-4 py-3 border-b border-edge bg-panel2">
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-accent">secret recon</span>
          <span className="text-[11px] text-mute">
            find exposed credentials · redacted · never validated
          </span>
        </div>
        {hasToken === false && (
          <span className="text-[10px] font-mono text-high" title="set GITHUB_TOKEN where the server runs">
            GITHUB_TOKEN not set — GitHub modules disabled
          </span>
        )}
      </div>

      <div className="px-4 py-3">
        {!seed && (
          <div className="text-xs text-mute font-mono py-2">
            enter a seed above, then run a module here.
          </div>
        )}
        <div className="flex flex-wrap gap-2">
          {MODULES.map((m) => {
            const disabled =
              !seed || state === "running" || (m.needsToken && hasToken === false);
            return (
              <button
                key={m.id}
                onClick={() => run(m.id)}
                disabled={disabled}
                title={m.hint}
                className={`px-3 py-1.5 rounded-md text-xs font-mono border transition-colors
                  ${
                    active === m.id && state === "running"
                      ? "bg-accent/15 border-accent/50 text-accent"
                      : "bg-base border-edge text-mute hover:text-ink hover:border-mute/50"
                  } disabled:opacity-35 disabled:cursor-not-allowed`}
              >
                {active === m.id && state === "running" && (
                  <span className="inline-block w-1.5 h-1.5 rounded-full bg-accent pulse-dot mr-1.5 align-middle" />
                )}
                {m.label}
              </button>
            );
          })}
        </div>

        {(state !== "idle" || log.length > 0) && (
          <div className="mt-3 border border-edge rounded-lg bg-base overflow-hidden">
            <div className="max-h-28 overflow-y-auto px-3 py-2 font-mono text-[11px] leading-relaxed">
              {log.map((line, i) => (
                <div key={i} className="text-mute whitespace-pre-wrap break-all">
                  {line}
                </div>
              ))}
              {error && <div className="text-critical">✗ {error}</div>}
              {state === "done" && real.length === 0 && !error && (
                <div className="text-low">✓ ran clean — no exposed secrets at this confidence</div>
              )}
              <div ref={endRef} />
            </div>
          </div>
        )}

        {real.length > 0 && (
          <div className="mt-3 flex flex-col gap-2">
            <div className="text-[11px] font-mono text-mute">
              {real.length} exposed secret{real.length === 1 ? "" : "s"} — rotate immediately
            </div>
            {real.map((f, i) => (
              <FindingCard key={`${f.rule}-${i}`} f={f} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
