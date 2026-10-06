import { useCallback, useEffect, useState } from "react";
import type { CampaignSummary, CaptureRecord, Endpoint } from "../types";
import { getEndpoint, getEndpoints, ingestTraffic, listCampaigns } from "../api";

// SURFACE → Endpoints. The observed application surface, built only from real captured
// traffic: a dense workstation table (method · endpoint · auth · identities · obs) with a
// right inspector showing the evidence behind a row. Secrets never reach here — the read
// model carries parameter names and references, and the capture evidence is pre-redacted.

const AUTH_COLOR: Record<Endpoint["auth"], string> = {
  required: "text-accent",
  none: "text-mute",
  unknown: "text-mute/60",
};

export default function EndpointsSurface() {
  const [campaigns, setCampaigns] = useState<CampaignSummary[]>([]);
  const [cid, setCid] = useState<string | null>(null);
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [selected, setSelected] = useState<Endpoint | null>(null);
  const [captures, setCaptures] = useState<CaptureRecord[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [showImport, setShowImport] = useState(false);

  useEffect(() => {
    listCampaigns().then((r) => setCampaigns(r.campaigns)).catch((e) => setError(String(e)));
  }, []);

  const load = useCallback((id: string) => {
    getEndpoints(id)
      .then((r) => setEndpoints(r.endpoints))
      .catch((e) => setError(String(e)));
  }, []);

  useEffect(() => {
    if (cid) load(cid);
    setSelected(null);
    setCaptures([]);
  }, [cid, load]);

  const inspect = useCallback(
    (ep: Endpoint) => {
      if (!cid) return;
      setSelected(ep);
      getEndpoint(cid, ep.id)
        .then((r) => setCaptures(r.captures))
        .catch((e) => setError(String(e)));
    },
    [cid]
  );

  return (
    <div className="flex gap-4">
      <div className="flex-1 flex flex-col gap-4 min-w-0">
        <div className="flex items-center gap-3">
          <div className="text-xs font-mono tracking-wide text-mute uppercase">Surface · Endpoints</div>
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
            <button
              onClick={() => setShowImport((v) => !v)}
              className="ml-auto text-xs font-mono text-accent hover:underline"
            >
              {showImport ? "cancel" : "+ import traffic"}
            </button>
          )}
        </div>

        {error && (
          <div className="text-xs font-mono text-critical bg-critical/10 border border-critical/30 rounded px-3 py-2">
            {error}
          </div>
        )}

        {cid && showImport && (
          <ImportPanel
            cid={cid}
            onDone={() => { setShowImport(false); load(cid); }}
            onError={setError}
          />
        )}

        {!cid ? (
          <div className="bg-panel border border-edge rounded-lg px-3 py-6 text-xs font-mono text-mute text-center">
            pick a campaign to see the endpoints observed from its captured traffic.
          </div>
        ) : endpoints.length === 0 ? (
          <div className="bg-panel border border-edge rounded-lg px-3 py-6 text-xs font-mono text-mute text-center">
            no observed traffic yet — import a HAR export or paste a request to map the surface.
          </div>
        ) : (
          <div className="bg-panel border border-edge rounded-lg overflow-hidden">
            <div className="grid grid-cols-[64px_1fr_90px_1fr_52px] gap-2 px-3 py-2 text-[10px] font-mono uppercase tracking-wide text-mute border-b border-edge">
              <span>Method</span><span>Endpoint</span><span>Auth</span><span>Identities</span><span className="text-right">Obs</span>
            </div>
            <div className="max-h-[62vh] overflow-auto">
              {endpoints.map((e) => (
                <button
                  key={e.id}
                  onClick={() => inspect(e)}
                  className={`w-full grid grid-cols-[64px_1fr_90px_1fr_52px] gap-2 px-3 py-1.5 text-xs font-mono border-b border-edge/40 last:border-0 hover:bg-panel2 text-left items-center ${
                    selected?.id === e.id ? "bg-panel2" : ""
                  }`}
                >
                  <span className="text-ink">{e.method}</span>
                  <span className="text-ink truncate">{e.path_template}</span>
                  <span className={AUTH_COLOR[e.auth]}>{e.auth}</span>
                  <span className="text-mute truncate">{e.identities.join(", ") || "—"}</span>
                  <span className="text-right text-mute">{e.obs_count}</span>
                </button>
              ))}
            </div>
          </div>
        )}
      </div>

      {selected && (
        <EndpointInspector ep={selected} captures={captures} onClose={() => setSelected(null)} />
      )}
    </div>
  );
}

function ImportPanel({
  cid, onDone, onError,
}: { cid: string; onDone: () => void; onError: (e: string) => void }) {
  const [text, setText] = useState("");
  const [identity, setIdentity] = useState("");
  const [busy, setBusy] = useState(false);

  const ingest = async () => {
    const raw = text.trim();
    if (!raw) return;
    let payload: Parameters<typeof ingestTraffic>[1];
    try {
      const parsed = JSON.parse(raw);
      // a HAR has log.entries; otherwise treat the JSON as a single structured request
      if (parsed && typeof parsed === "object" && "log" in parsed) {
        payload = { har: parsed, identity: identity.trim() || undefined };
      } else {
        payload = { request: parsed, identity: identity.trim() || undefined };
      }
    } catch {
      onError("import must be JSON — a HAR export, or a single {method,url,headers,body} request");
      return;
    }
    setBusy(true);
    try {
      await ingestTraffic(cid, payload);
      setText("");
      onDone();
    } catch (e) {
      onError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="bg-panel border border-edge rounded-lg p-3 flex flex-col gap-2">
      <div className="text-xs font-mono text-mute">
        Paste a browser HAR export, or one request as JSON (<span className="text-ink">{"{method,url,headers,body,response}"}</span>).
        Secrets are redacted before anything is stored.
      </div>
      <textarea
        value={text}
        onChange={(e) => setText(e.target.value)}
        rows={6}
        placeholder={'{"method":"GET","url":"https://api.example.com/api/orders/123","headers":{"Authorization":"Bearer ..."}}'}
        className="bg-panel2 border border-edge rounded p-2 text-xs font-mono text-ink outline-none focus:border-accent/60 resize-y"
      />
      <div className="flex items-center gap-2">
        <input
          value={identity}
          onChange={(e) => setIdentity(e.target.value)}
          placeholder="identity (optional)"
          className="bg-panel2 border border-edge rounded px-2 py-1 text-xs font-mono text-ink placeholder:text-mute/50 outline-none focus:border-accent/60"
        />
        <button
          onClick={ingest}
          disabled={busy || !text.trim()}
          className="ml-auto text-xs font-mono bg-accent/15 text-accent border border-accent/40 rounded px-3 py-1.5 disabled:opacity-40 hover:bg-accent/25"
        >
          {busy ? "ingesting…" : "ingest"}
        </button>
      </div>
    </div>
  );
}

function EndpointInspector({
  ep, captures, onClose,
}: { ep: Endpoint; captures: CaptureRecord[]; onClose: () => void }) {
  const rows: [string, string][] = [
    ["host", ep.host],
    ["method", ep.method],
    ["template", ep.path_template],
    ["auth", ep.auth],
    ["identities", ep.identities.join(", ") || "—"],
    ["sessions", ep.session_ids.join(", ") || "—"],
    ["query params", ep.query_params.join(", ") || "—"],
    ["body params", ep.body_params.join(", ") || "—"],
    ["content types", ep.content_types.join(", ") || "—"],
    ["responses", ep.response_classes.join(", ") || "—"],
    ["observations", String(ep.obs_count)],
    ["last seen", ep.last_seen],
  ];
  return (
    <aside className="shrink-0 w-96 border border-edge rounded-lg bg-panel overflow-auto max-h-[78vh]">
      <div className="flex items-center justify-between px-4 h-10 border-b border-edge sticky top-0 bg-panel">
        <span className="text-xs font-mono uppercase tracking-wide text-mute">Inspector · endpoint</span>
        <button onClick={onClose} className="text-xs font-mono text-mute hover:text-ink">close</button>
      </div>
      <dl className="p-4 flex flex-col gap-2">
        {rows.map(([k, v]) => (
          <div key={k} className="grid grid-cols-[96px_1fr] gap-2 text-xs font-mono">
            <dt className="text-mute">{k}</dt>
            <dd className="text-ink break-words">{v}</dd>
          </div>
        ))}
      </dl>
      <div className="px-4 pb-4">
        <div className="text-[10px] font-mono uppercase tracking-wide text-mute mb-2">
          sample requests · evidence ({captures.length})
        </div>
        <div className="flex flex-col gap-2">
          {captures.map((c) => (
            <div key={c.id} className="bg-panel2 border border-edge rounded px-2.5 py-2 text-[11px] font-mono">
              <div className="flex items-center gap-2">
                <span className="text-ink">{c.method}</span>
                <span className={c.response_status && c.response_status < 400 ? "text-accent" : "text-medium"}>
                  {c.response_status ?? "—"}
                </span>
                <span className="text-mute truncate">{c.identity || "anon"}</span>
                <span className="ml-auto text-mute/60">{c.source}</span>
              </div>
              <div className="text-mute truncate mt-1">{c.url}</div>
            </div>
          ))}
          {captures.length === 0 && <div className="text-xs font-mono text-mute">no captures loaded.</div>}
        </div>
      </div>
    </aside>
  );
}
