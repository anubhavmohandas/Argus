import { useCallback, useEffect, useMemo, useState } from "react";
import type { CampaignSummary, ResourceRow } from "../types";
import { assertOwnership, getResources, listCampaigns } from "../api";

// SURFACE → Resources. The objects captured traffic referenced, mined as candidates and
// overlaid with EXPLICIT ownership. A resource ARGUS cannot attribute is UNKNOWN — a
// normal, first-class state rendered as plain text, never a warning. researcher_controlled
// is trusted metadata set only by an explicit assertion here; it is never inferred from a
// test user merely appearing in a request. Same graphite/aqua DNA as the other surfaces.

const CONTROLLED_LABEL = (r: ResourceRow): string =>
  r.researcher_controlled ? "yes" : r.ownership_status === "INFERRED" ? "inferred" : "no";

export default function ResourcesSurface() {
  const [campaigns, setCampaigns] = useState<CampaignSummary[]>([]);
  const [cid, setCid] = useState<string | null>(null);
  const [rows, setRows] = useState<ResourceRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const [sel, setSel] = useState<ResourceRow | null>(null);

  useEffect(() => {
    listCampaigns().then((r) => setCampaigns(r.campaigns)).catch((e) => setError(String(e)));
  }, []);

  const load = useCallback((id: string) => {
    getResources(id).then((r) => setRows(r.resources)).catch((e) => setError(String(e)));
  }, []);

  useEffect(() => {
    setRows([]);
    setSel(null);
    setError(null);
    if (cid) load(cid);
  }, [cid, load]);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return rows;
    return rows.filter((r) => `${r.resource_type} ${r.value} ${r.owner_identity}`.toLowerCase().includes(needle));
  }, [rows, q]);

  return (
    <div className="flex gap-4">
      <div className="flex-1 flex flex-col gap-4 min-w-0">
        <div className="flex items-center gap-3 flex-wrap">
          <div className="text-xs font-mono tracking-wide text-mute uppercase">Surface · Resources</div>
          <select
            value={cid ?? ""}
            onChange={(e) => setCid(e.target.value || null)}
            className="bg-panel2 border border-edge rounded px-2 py-1 text-xs font-mono text-ink outline-none focus:border-accent/60"
          >
            <option value="">select a campaign…</option>
            {campaigns.map((c) => (
              <option key={c.id} value={c.id}>{c.id}</option>
            ))}
          </select>
          {cid && (
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="filter type / value / owner…"
              className="ml-auto bg-panel2 border border-edge rounded px-2 py-1 text-xs font-mono text-ink placeholder:text-mute/50 outline-none focus:border-accent/60 w-56"
            />
          )}
        </div>

        {error && (
          <div className="text-xs font-mono text-critical bg-critical/10 border border-critical/30 rounded px-3 py-2">
            {error}
          </div>
        )}

        {!cid ? (
          <Empty text="pick a campaign to see the objects its captured traffic referenced." />
        ) : rows.length === 0 ? (
          <Empty text="no resource candidates yet — resources are mined from captured request paths on the Endpoints surface." />
        ) : (
          <div className="bg-panel border border-edge rounded-lg overflow-hidden">
            <div className="grid grid-cols-[110px_1fr_120px_110px_90px_120px] gap-2 px-3 py-2 text-[10px] font-mono uppercase tracking-wide text-mute border-b border-edge">
              <span>Type</span><span>Resource</span><span>Owner</span><span>Tenant</span><span>Controlled</span><span className="text-right">Last seen</span>
            </div>
            <div className="max-h-[64vh] overflow-auto">
              {filtered.map((r) => (
                <button
                  key={`${r.resource_type}\u0000${r.value}`}
                  onClick={() => setSel(r)}
                  className={`w-full grid grid-cols-[110px_1fr_120px_110px_90px_120px] gap-2 px-3 py-1.5 text-xs font-mono border-b border-edge/40 last:border-0 hover:bg-panel2 text-left items-center ${
                    sel?.value === r.value && sel?.resource_type === r.resource_type ? "bg-panel2" : ""
                  }`}
                >
                  <span className={r.resource_type === "unknown" ? "text-mute" : "text-ink"}>{r.resource_type}</span>
                  <span className="text-ink truncate">{r.value}</span>
                  <span className={r.owner_known ? "text-ink" : "text-mute"}>{r.owner_identity || "unknown"}</span>
                  <span className={r.tenant ? "text-ink" : "text-mute"}>{r.tenant || "—"}</span>
                  <span className={r.researcher_controlled ? "text-accent" : "text-mute"}>{CONTROLLED_LABEL(r)}</span>
                  <span className="text-right text-mute truncate">{short(r.last_seen)}</span>
                </button>
              ))}
              {filtered.length === 0 && (
                <div className="px-3 py-6 text-xs font-mono text-mute text-center">no resources match “{q}”.</div>
              )}
            </div>
          </div>
        )}
      </div>

      {sel && cid && (
        <ResourceInspector
          cid={cid}
          r={sel}
          onClose={() => setSel(null)}
          onSaved={() => { load(cid); }}
          onError={setError}
        />
      )}
    </div>
  );
}

function ResourceInspector({
  cid, r, onClose, onSaved, onError,
}: {
  cid: string;
  r: ResourceRow;
  onClose: () => void;
  onSaved: () => void;
  onError: (e: string) => void;
}) {
  const rows: [string, string][] = [
    ["type", r.resource_type],
    ["value", r.value],
    ["fields", r.fields.join(", ") || "—"],
    ["sources", r.sources.join(", ") || "—"],
    ["candidate confidence", r.confidence || "—"],
    ["observed", r.observed ? "yes" : "no (assertion only)"],
    ["observations", String(r.observations)],
    ["owner", r.owner_identity || "unknown"],
    ["tenant", r.tenant || "—"],
    ["controlled", CONTROLLED_LABEL(r)],
    ["ownership", r.ownership_status || "unknown"],
    ["ownership source", r.ownership_source || "—"],
    ["endpoints", String(r.endpoint_refs.length)],
    ["first seen", r.first_seen || "—"],
    ["last seen", r.last_seen || "—"],
  ];
  return (
    <aside className="shrink-0 w-96 border border-edge rounded-lg bg-panel overflow-auto max-h-[78vh]">
      <div className="flex items-center justify-between px-4 h-10 border-b border-edge sticky top-0 bg-panel">
        <span className="text-xs font-mono uppercase tracking-wide text-mute">Inspector · resource</span>
        <button onClick={onClose} className="text-xs font-mono text-mute hover:text-ink">close</button>
      </div>
      <dl className="p-4 flex flex-col gap-2">
        {rows.map(([k, v]) => (
          <div key={k} className="grid grid-cols-[132px_1fr] gap-2 text-xs font-mono">
            <dt className="text-mute">{k}</dt>
            <dd className="text-ink break-words">{v}</dd>
          </div>
        ))}
      </dl>
      <OwnershipForm cid={cid} r={r} onSaved={onSaved} onError={onError} />
    </aside>
  );
}

// Declaring ownership is explicit trusted metadata — the only path to researcher_controlled.
// The server forces an INFERRED assertion non-controlled; the form mirrors that so the
// operator is never misled into thinking a guess grants cross-account authorization.
function OwnershipForm({
  cid, r, onSaved, onError,
}: { cid: string; r: ResourceRow; onSaved: () => void; onError: (e: string) => void }) {
  const [owner, setOwner] = useState(r.owner_identity);
  const [tenant, setTenant] = useState(r.tenant);
  const [status, setStatus] = useState<"CONFIRMED" | "INFERRED">(
    r.ownership_status === "INFERRED" ? "INFERRED" : "CONFIRMED"
  );
  const [controlled, setControlled] = useState(r.researcher_controlled);
  const [busy, setBusy] = useState(false);

  const canControl = status === "CONFIRMED"; // inferred can never be researcher-controlled

  const save = async () => {
    setBusy(true);
    try {
      await assertOwnership(cid, {
        resource_type: r.resource_type,
        resource_value: r.value,
        owner_identity: owner.trim(),
        tenant: tenant.trim(),
        researcher_controlled: canControl && controlled,
        ownership_status: status,
      });
      onSaved();
    } catch (e) {
      onError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="px-4 pb-4 border-t border-edge pt-3 flex flex-col gap-2">
      <div className="text-[10px] font-mono uppercase tracking-wide text-mute">assert ownership</div>
      <input
        value={owner}
        onChange={(e) => setOwner(e.target.value)}
        placeholder="owner identity (e.g. customer_a)"
        className="bg-panel2 border border-edge rounded px-2 py-1 text-xs font-mono text-ink placeholder:text-mute/50 outline-none focus:border-accent/60"
      />
      <input
        value={tenant}
        onChange={(e) => setTenant(e.target.value)}
        placeholder="tenant (optional)"
        className="bg-panel2 border border-edge rounded px-2 py-1 text-xs font-mono text-ink placeholder:text-mute/50 outline-none focus:border-accent/60"
      />
      <div className="flex items-center gap-3 text-xs font-mono">
        <select
          value={status}
          onChange={(e) => setStatus(e.target.value as "CONFIRMED" | "INFERRED")}
          className="bg-panel2 border border-edge rounded px-2 py-1 text-ink outline-none focus:border-accent/60"
        >
          <option value="CONFIRMED">confirmed</option>
          <option value="INFERRED">inferred</option>
        </select>
        <label className={`flex items-center gap-1.5 ${canControl ? "text-ink" : "text-mute/50"}`}>
          <input
            type="checkbox"
            checked={canControl && controlled}
            disabled={!canControl}
            onChange={(e) => setControlled(e.target.checked)}
          />
          researcher-controlled
        </label>
      </div>
      {!canControl && (
        <div className="text-[10px] font-mono text-mute">
          an inferred assertion can never be researcher-controlled — only a confirmed one may authorize cross-account tests.
        </div>
      )}
      <button
        onClick={save}
        disabled={busy}
        className="self-start text-xs font-mono bg-accent/15 text-accent border border-accent/40 rounded px-3 py-1.5 disabled:opacity-40 hover:bg-accent/25"
      >
        {busy ? "saving…" : "save assertion"}
      </button>
    </div>
  );
}

function short(ts: string): string {
  if (!ts) return "—";
  return ts.length > 19 ? ts.slice(0, 19).replace("T", " ") : ts;
}

function Empty({ text }: { text: string }) {
  return (
    <div className="bg-panel border border-edge rounded-lg px-3 py-6 text-xs font-mono text-mute text-center">
      {text}
    </div>
  );
}
