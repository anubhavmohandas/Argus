import { useState } from "react";
import type { Policy } from "../types";
import { compilePolicy } from "../api";

/**
 * Paste a bug-bounty program page (Intigriti / HackerOne / etc.) and compile it
 * into the engagement contract: in-scope / out-of-scope assets, the vulnerability
 * classes the program won't pay for, its objectives, rate cap and required headers.
 * Pure parse on the server — it never touches a target. The compiled scope file
 * can be copied straight into a run's --scope.
 */
export default function ProgramScope() {
  const [text, setText] = useState("");
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);

  const compile = async () => {
    if (!text.trim() || busy) return;
    setBusy(true);
    setError(null);
    setPolicy(null);
    try {
      setPolicy(await compilePolicy(text));
    } catch (e) {
      setError(e instanceof Error ? e.message : "compile failed");
    } finally {
      setBusy(false);
    }
  };

  const copyScope = () => {
    if (!policy?.scope_file) return;
    navigator.clipboard.writeText(policy.scope_file).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };

  return (
    <div className="border border-edge rounded-xl bg-panel">
      <div className="flex items-center justify-between px-4 py-3 border-b border-edge bg-panel2">
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-accent">program scope</span>
          <span className="text-[11px] text-mute">
            paste a program page → in/out-of-scope, exclusions, objectives · parse only, never probes
          </span>
        </div>
      </div>

      <div className="p-4 flex flex-col gap-3">
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="Paste the full program page here (scope / assets, out-of-scope, rules of engagement)…"
          className="w-full h-32 resize-y rounded-lg bg-panel2 border border-edge px-3 py-2 text-xs font-mono text-ink placeholder:text-mute focus:outline-none focus:border-accent"
        />
        <div className="flex items-center gap-3">
          <button
            onClick={compile}
            disabled={!text.trim() || busy}
            className="text-xs font-mono px-3 py-1.5 rounded-lg bg-accent/15 border border-accent/40 text-accent hover:bg-accent/25 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {busy ? "compiling…" : "compile scope"}
          </button>
          {error && <span className="text-[11px] font-mono text-high">{error}</span>}
        </div>

        {policy && <PolicyView policy={policy} onCopy={copyScope} copied={copied} />}
      </div>
    </div>
  );
}

function PolicyView({ policy, onCopy, copied }: { policy: Policy; onCopy: () => void; copied: boolean }) {
  const hasScope = policy.in_scope.length > 0 || policy.out_of_scope.length > 0;
  return (
    <div className="flex flex-col gap-4 text-xs">
      {policy.warnings.map((w, i) => (
        <div key={i} className="font-mono text-[11px] text-medium">⚠ {w}</div>
      ))}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Section title={`in scope · ${policy.in_scope.length}`} empty={!policy.in_scope.length}>
          {policy.in_scope.map((a) => (
            <div key={a.pattern} className="flex items-center gap-2 font-mono">
              <span className="text-low">{a.pattern}</span>
              {a.env && <Badge>{a.env}</Badge>}
              {a.tier != null && <Badge>tier {a.tier}</Badge>}
              {a.action === "passive" && <Badge>passive</Badge>}
            </div>
          ))}
        </Section>

        <Section title={`out of scope · ${policy.out_of_scope.length}`} empty={!policy.out_of_scope.length}>
          {policy.out_of_scope.map((p) => (
            <div key={p} className="font-mono text-high">{p}</div>
          ))}
        </Section>
      </div>

      {policy.non_network_assets.length > 0 && (
        <Section title={`named assets (not host-scoped) · ${policy.non_network_assets.length}`} empty={false}>
          {policy.non_network_assets.map((p) => (
            <div key={p} className="font-mono text-mute">{p}</div>
          ))}
        </Section>
      )}

      <Section title={`won't pay for · ${policy.non_reportable_labels.length}`} empty={!policy.non_reportable_labels.length}>
        {policy.non_reportable_labels.map((l, i) => (
          <div key={i} className="text-mute">· {l}</div>
        ))}
        {policy.suppresses.length > 0 && (
          <div className="mt-1 font-mono text-[11px] text-accent">
            argus auto-suppresses: {policy.suppresses.join(", ")}
          </div>
        )}
      </Section>

      <Section title={`objectives · ${policy.objectives.length}`} empty={!policy.objectives.length}>
        {policy.objectives.map((o, i) => (
          <div key={i} className="text-low">★ {o}</div>
        ))}
      </Section>

      <div className="flex flex-wrap gap-x-6 gap-y-1 font-mono text-[11px] text-mute">
        {policy.rate_per_sec != null && <span>rate <span className="text-ink">{policy.rate_per_sec}/s</span></span>}
        {policy.max_requests != null && <span>max <span className="text-ink">{policy.max_requests}</span></span>}
        {policy.user_agent && <span>UA <span className="text-ink">{policy.user_agent}</span></span>}
        {Object.entries(policy.request_headers).map(([k, v]) => (
          <span key={k}>send <span className="text-ink">{k}: {v}</span></span>
        ))}
      </div>
      {policy.unfilled_headers.length > 0 && (
        <div className="font-mono text-[11px] text-high">
          fill before probing: {policy.unfilled_headers.join(", ")}
        </div>
      )}
      {policy.forbidden.length > 0 && (
        <Section title={`forbidden · ${policy.forbidden.length}`} empty={false}>
          {policy.forbidden.map((f, i) => (
            <div key={i} className="text-high">✕ {f}</div>
          ))}
        </Section>
      )}

      {hasScope && (
        <div className="pt-1">
          <button
            onClick={onCopy}
            className="text-xs font-mono text-accent hover:underline"
            title="scope-file format — paste into a run's --scope"
          >
            {copied ? "copied ✓" : "copy scope file"}
          </button>
        </div>
      )}
    </div>
  );
}

function Section({ title, empty, children }: { title: string; empty: boolean; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <div className="font-mono text-[11px] text-mute uppercase tracking-wide">{title}</div>
      {empty ? <div className="text-mute">—</div> : children}
    </div>
  );
}

function Badge({ children }: { children: React.ReactNode }) {
  return (
    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-panel2 border border-edge text-mute">
      {children}
    </span>
  );
}
