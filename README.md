# Argus

**Autonomous correlation recon engine.** One seed in → a connected
entity-graph dossier out. Argus doesn't just *look things up* — it pivots
across every source on its own, links what it finds into a single graph,
scores it, and hands you an intelligence brief.

That pivot loop is the point. Individual lookups are a commodity; the
engine that chains them and correlates the results is the thing that's
hard to deny.

```
argus pivot example.com
```

```
[argus] seed 'example.com' classified as: domain
════════════════════════════════════════════════════════════
 ARGUS DOSSIER
════════════════════════════════════════════════════════════
 ENTITY GRAPH  (N nodes · M edges)
   domain      3  example.com, mail.example.com, ns1.example.com
   subdomain  27  api.example.com, dev.example.com, ...
   ip          4  93.184.216.34, ...
 FINDINGS  (K total)
   low        28
   info       12
 TOP SIGNALS
   [low     ] subdomains  27 unique subdomain(s)
   ...
════════════════════════════════════════════════════════════
```

## Why it's different from a scanner

A scanner runs checks against a target you hand it. Argus **discovers the
targets itself**: seed a domain and it walks RDAP → DNS → certificate
transparency → resolves the results to IPs → pivots those back into more
domains, deduping into one graph the whole way. Seed an email and it fans
out into a domain and a username and correlates across both. The graph is
the deliverable, not a flat list.

## Install

```bash
pip install .            # installs the `argus` command (core is stdlib-only)
argus                    # bare command on a terminal → interactive menu
pip install '.[phone]'   # optional extra: the `phone` module (libphonenumber)
```

No install needed to try it — `python3 -m argus <cmd>` runs from the source
tree. Rule-based reasoning uses stdlib `tomllib`, so the **engine needs Python
3.11+**; discovery runs on any Python 3. Core is **stdlib-only** and
dependency-light on purpose — it stays a tool you can drop anywhere.

## Commands

| Command | What it does |
|---|---|
| `argus` | **Interactive menu.** Run with no arguments on a terminal: banner, then pick a seed and an engagement level (passive → full scan). |
| `argus pivot <seed>` | **Headline.** Autonomous correlation from one seed (domain/ip/username/phone/email). |
| `argus run <module> <target>` | Run a single module. |
| `argus all <target>` | Run every module that fits the target. |
| `argus modules` | List modules. |
| `argus coverage` | Which engine predicates have an evidence provider (the roadmap, live from the code). |

Flags on `pivot`: `--depth N` (pivot depth, default 2), `--max N` (entity
cap, default 40), `--deep N` (re-pivot into N discovered subdomains),
`--json` (machine output — the full node/edge/finding graph).

**Engagement levels** (the menu's choice, or the flags directly): passive by
default (public sources only — never touches the target); `--probe` connects to
discovered hosts for evidence; `--probe-paths` also requests admin/sensitive
paths; `--scan` adds a TCP port scan. Everything past passive is **active** — the
menu makes you confirm you're authorized before it sends a single request.

## Modules (the fuel)

Strengths harvested from the source tools, reimplemented natively:

| Module | Source | Does |
|---|---|---|
| `rdap` / `dns` / `subdomains` | Shadowbroker recon + Claude-OSINT arsenal | registrar/dates/NS · DoH A/MX/NS/TXT · crt.sh CT subdomain discovery |
| `ip` / `phone` / `username` | GhostTrack (hardened) | geo/ASN/ISP · carrier/region (offline) · social-platform enumeration |
| `secrets` | Claude-OSINT 48-pattern catalog | credential/key leak scanning of a file or dir |

Add a module: write a `@module(...)`-decorated function in
[`argus/modules.py`](argus/modules.py) that yields `Finding`s. It
auto-registers and the pivot engine can chain it.

## Evidence providers (the probes)

Providers don't grow the graph — they establish facts about hosts it already
found, and write them where the rules read. They're grouped by **engagement
tier**, so you only send what you opt into:

**`--probe`** — reaches each host once (or reads public DNS), low engagement:

| Predicate(s) | Provider | Establishes |
|---|---|---|
| `internet_facing`, `technology`, `authentication_required`, `security_headers_missing`, `insecure_cookie`, `clickjacking`, `subdomain_takeover` | `http_probe` | everything a single `/` response reveals — reachability, tech fingerprint, auth gate, hardening headers, cookie flags, framability, and a dangling-DNS takeover fingerprint |
| `certificate_reused` | `cert_analysis` | the same TLS cert served across unrelated hosts (analysis over the graph) |
| `known_exploited`, `public_exploit` | `kev` | an observed product version matched against a known-exploited catalog |
| `cors_misconfig` | `cors_probe` | a credentialed reflected-origin CORS grant (one extra GET) |
| `email_spoofable` | `email_spoof` | missing / unenforced DMARC — DNS-only, never touches the target |

**`--probe-paths`** — sends multiple requests / payloads per host, louder:

| Predicate(s) | Provider | Establishes |
|---|---|---|
| `has_admin_interface` | `admin_probe` | a reachable admin surface, confirmed by what it serves |
| `exposed_sensitive_file` | `exposure_probe` | a reachable `.git` / `.env` / `.DS_Store` whose body confirms the real file |
| `path_traversal` | `traversal_probe` | a `../` payload that returned real file content (self-gating) |
| `graphql_introspection` | `graphql_probe` | a GraphQL endpoint that answered a live `__schema` query |
| `open_redirect` | `redirect_probe` | a redirect param that bounced to a canary host we injected |
| `reflected_xss`, `ssti` | `injection_probe` | a unique canary reflected unescaped, or `{{7*7}}` rendered to `49` |

**`--scan`** — loudest: `known_vulnerable_service` from a `port_scan` (TCP-connect
+ banner) matched against a service-CVE catalog.

Each predicate is an *observation* only; the conclusion is a TOML rule in
[`argus/rules/`](argus/rules/). `argus coverage` maps every predicate to its
provider, live from the code — the ones with no provider are the roadmap.

## Architecture

```
core.py       finding model · module registry · validated HTTP · input guards
modules.py    built-in recon modules (the hands)
pivot.py      discovery — bounded BFS correlation into an entity graph
providers.py  evidence providers — probe/analysis facts written to Entity.evidence
engine.py     Investigator Rule Engine — read-only reasoning: rules, predicates, conclusions, ledger
rules/        declarative TOML rule files (data, never code)
store.py      investigation memory — per-seed case files + cross-run diff
cli.py        pivot / run / all / modules / coverage + interactive menu
```

Discovery (`pivot`) builds the evidence graph; the **Investigator Rule Engine**
(`engine.investigate`) reasons over it read-only and returns one
`InvestigationResult` that every consumer reads. Together they **are** the
Investigation Engine — the identity of the system. Priority/triage is now one
engine output, not a separate pass. See
[`docs/ENGINEERING_PRINCIPLES.md`](docs/ENGINEERING_PRINCIPLES.md).

**Silence is never a negative.** Argus distinguishes an observation, a
probe-backed fact, and an unknown — and never collapses them. Where another
tool reports "no exploit found," Argus reports "exploit status unknown — no
evidence provider asserted either state." Every conclusion is reproducible from
versioned evidence and inference rules; nothing is inferred from absence.

A broken rule set degrades the same way rather than lying: conclusions go empty,
discovery survives, and the failure travels on `InvestigationResult.error` into
both the dossier and the JSON. A config bug must never read as a clean run.

### Public API

These names are re-exported from the package and are what a downstream caller
(or a NYX module) should import. Everything else is internal and may move.

```python
from argus import pivot, dossier, Budget, Graph, classify   # discovery
from argus import Finding, run_module, run_all, MODULES     # modules
from argus.engine import investigate, InvestigationResult   # reasoning
```

Pre-1.0: the surface is deliberate, but not yet frozen.

## Roadmap

- **More evidence providers** — the seam grows by adding evidence, never by
  changing the engine. Shipped so far: HTTP/TLS probe, KEV catalog, certificate
  reuse, admin surface, sensitive-file exposure, path traversal, clickjacking,
  CORS, GraphQL introspection, subdomain takeover, open redirect, reflected
  XSS / SSTI, DMARC email-spoofing, and a port-scan service-CVE match. Next: a
  live CISA KEV / NVD feed behind the same seam, and wider fingerprint sets.
- **Optional LLM layer (NYX)** — sits *above* the engine to explain,
  summarize, converse, and answer questions over its output. It never decides
  investigation logic — that stays deterministic (Rule 7).
- **Your `MY OWN` tools** — `owasp_scanner`'s observation-class checks are in,
  as the web-exposure providers above. Its active-injection modules and
  `secure_gen`'s payload generation stay *out* of the engine by design
  (Principle 7: Argus observes and reasons; it does not exploit) — they belong
  above it. recon_scanner / whoisuser / CyberTrace patterns (more subdomain
  sources, wider username lists, more seed types) land as further modules.
- **Persistence** — SQLite findings store (pentest-ai schema) for
  cross-run engagements.
- **Person-OSINT modules** — breach correlation, reverse-image, more
  platforms — per the intake methodology.

## Authorization

Argus is for assets you own or are **authorized** to assess. Every source
tool it borrows from ships the same posture: passive/OSINT recon, no active
exploitation. Keep it in scope.

## Attribution

Strengths adapted (all MIT): secret catalog from
[Claude-OSINT](https://github.com/elementalsouls/Claude-OSINT) · lookups from
[GhostTrack](https://github.com/HunxByts/GhostTrack) · recon-toolkit patterns
from [Shadowbroker](https://github.com/bigbodycobain/Shadowbroker) ·
findings-DB schema from
[pentest-ai-agents](https://github.com/0xSteph/pentest-ai-agents) · engine
concept from [CAI](https://github.com/aliasrobotics/cai) · web-exposure evidence
patterns from `owasp_scanner`.
