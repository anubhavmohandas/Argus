# Argus Web

A web frontend for Argus — the bug-hunter's correlation engine. Built on
Argus's own **entity-graph + scored-findings** model (not ReconVision's
per-host screenshot model). Two parts:

- **`server.py`** — a thin HTTP + Server-Sent-Events API, **stdlib only, zero
  runtime dependencies**, honoring Argus's prime principle ("no new runtime
  dependency for anything stdlib can do"). It does not reimplement any recon
  logic — it spawns the existing `argus` CLI engine and streams its live
  `[argus]` status lines plus the final JSON dossier.
- **`frontend/`** — a React 18 + Vite + TypeScript + Tailwind app: seed bar with
  engagement-level selector, live run log, the entity graph, and the findings
  dossier (severity · confidence · evidence · hypothesis).

## Run it

### Dev (hot reload)

Two terminals, from the **repo root**:

```bash
# 1) the engine API (stdlib, no deps)
python3 web/server.py                 # http://127.0.0.1:8787

# 2) the frontend dev server (proxies /api -> :8787)
cd web/frontend
npm install
npm run dev                           # http://localhost:5173
```

### Prod (single server)

```bash
cd web/frontend && npm install && npm run build   # emits web/frontend/dist
cd ../.. && python3 web/server.py                 # serves UI + API on :8787
```

Open http://127.0.0.1:8787.

## Engagement levels

Mirror the `argus` interactive menu exactly:

| Level        | Engine flags                      | Loudness |
|--------------|-----------------------------------|----------|
| Passive      | *(none)*                          | public sources only — never touches target |
| Active       | `--probe --cve`                   | connect to hosts + live CVEs |
| Active+      | `--probe-paths --cve`             | + request admin / sensitive paths |
| Full scan    | `--probe-paths --scan --cve`      | + TCP port scan (loudest) |

Anything past Passive sends active traffic; the UI makes you confirm
authorization before it will run, and the API passes the seed as a subprocess
argv element (no shell) with the level checked against a fixed allowlist. Argus's
own SSRF guard still runs before every outbound request.

## API

| Method | Path          | Purpose |
|--------|---------------|---------|
| GET    | `/api/health` | liveness + available levels |
| GET    | `/api/stream` | SSE run: `?seed=&level=&depth=&max=&deep=&ports=` → `start` / `status` / `result` / `done` / `error` events |

## Notes / limits

- Binds to `127.0.0.1` by default. `--host 0.0.0.0` exposes it on the LAN — only
  on a network you control, against authorized targets.
- This is an MVP: one run at a time per stream, no run history/persistence in the
  web layer yet (Argus's own investigation memory still records runs on disk).
  The `oculus/` sibling folder (the visual/screenshot recon tool) is kept as a
  separate component and reference, not wired into this API.
