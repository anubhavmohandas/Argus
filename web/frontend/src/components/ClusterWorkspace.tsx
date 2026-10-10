import { useCallback, useEffect, useRef, useState } from "react";
import type { CampaignFinding, CampaignSummary, RootCauseCluster } from "../types";
import { getCampaign, getClusters, listCampaigns, subscribeCampaign } from "../api";

// The duplicate-cluster workspace: root-cause clusters as their own surface. ARGUS SUGGESTS
// relationships (same host + object family + failed boundary); it NEVER silently merges
// findings. This slice is read-only and exposes the evidence behind each suggested
// relationship — the dedupe model does not yet persist a researcher's keep/merge/unrelated
// decision, so no half-working manual-merge mutation is offered (the honest first slice).

export default function ClusterWorkspace() {
  const [campaigns, setCampaigns] = useState<CampaignSummary[]>([]);
  const [cid, setCid] = useState<string | null>(null);
  const [clusters, setClusters] = useState<RootCauseCluster[]>([]);
  const [findings, setFindings] = useState<CampaignFinding[]>([]);
  const [error, setError] = useState<string | null>(null);
  const refetchTimer = useRef<number | null>(null);

  useEffect(() => {
    listCampaigns().then((r) => setCampaigns(r.campaigns)).catch((e) => setError(String(e)));
  }, []);

  const load = useCallback((id: string) => {
    getClusters(id).then((r) => setClusters(r.clusters)).catch((e) => setError(String(e)));
    getCampaign(id)
      .then((d) => setFindings((d.findings as unknown as CampaignFinding[]) ?? []))
      .catch(() => { /* best-effort */ });
  }, []);

  useEffect(() => {
    if (!cid) { setClusters([]); setFindings([]); return; }
    load(cid);
    const unsub = subscribeCampaign(cid, () => {
      if (refetchTimer.current) window.clearTimeout(refetchTimer.current);
      refetchTimer.current = window.setTimeout(() => load(cid), 250);
    });
    return () => {
      unsub();
      if (refetchTimer.current) window.clearTimeout(refetchTimer.current);
    };
  }, [cid, load]);

  const title = (id: string) => findings.find((f) => f.id === id)?.title ?? id;

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center gap-3">
        <span className="text-xs font-mono uppercase tracking-wide text-mute">Duplicate clusters</span>
        <select
          value={cid ?? ""}
          onChange={(e) => setCid(e.target.value || null)}
          className="bg-panel2 border border-edge rounded px-2 py-1 text-xs font-mono text-ink outline-none focus:border-accent/60"
        >
          <option value="">select a campaign…</option>
          {campaigns.map((c) => <option key={c.id} value={c.id}>{c.id}</option>)}
        </select>
      </div>

      {error && (
        <div className="text-xs font-mono text-critical bg-critical/10 border border-critical/30 rounded px-3 py-2">
          {error}
        </div>
      )}

      {!cid ? (
        <div className="text-xs font-mono text-mute px-1">
          select a campaign to see its root-cause clusters — ARGUS suggests, it never merges.
        </div>
      ) : clusters.length === 0 ? (
        <div className="bg-panel border border-edge rounded-lg px-3 py-4 text-xs font-mono text-mute">
          no clusters yet — a second finding sharing a control point forms one.
        </div>
      ) : (
        <div className="flex flex-col gap-2">
          {clusters.map((c) => {
            const related = c.finding_ids.length > 1;
            return (
              <div key={c.cluster_id} className="bg-panel border border-edge rounded-lg p-3 text-xs font-mono">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-accent break-all">{c.cluster_id} · {c.host} · {c.endpoint_family || "—"}</span>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded border ${
                    related ? "text-low border-low/40" : "text-mute border-edge"}`}>
                    {related ? "LIKELY SAME ROOT CAUSE" : "SINGLE FINDING"}
                  </span>
                </div>
                <div className="text-mute mt-1">
                  {c.boundary_type} · {c.affected_actions} affected action(s) · {c.finding_ids.length} finding(s)
                </div>
                {related && (
                  <div className="text-mute/70 mt-1">
                    reason: same security boundary · same resource family · same failed authorization control
                  </div>
                )}
                {c.actions.length > 0 && (
                  <div className="text-mute/70 mt-1">{c.actions.join("   ·   ")}</div>
                )}
                <ul className="list-disc ml-4 mt-1 text-mute">
                  {c.finding_ids.map((id) => (
                    <li key={id} className={id === c.representative_finding ? "text-ink" : ""}>
                      {title(id)}{id === c.representative_finding ? "  (representative)" : ""}
                    </li>
                  ))}
                </ul>
              </div>
            );
          })}
          <div className="text-[10px] font-mono text-mute/60 px-1">
            relationships are suggestions over shared evidence; keep/merge/unrelated decisions
            are not yet persisted, so nothing here is merged automatically.
          </div>
        </div>
      )}
    </div>
  );
}
