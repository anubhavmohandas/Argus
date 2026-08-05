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
python3 -m argus modules              # no install step — core is stdlib-only
pip install 'phonenumbers>=8.13'      # optional, only for the `phone` module
```

Core is **stdlib-only** and dependency-light on purpose — it stays a tool
you can drop anywhere.

## Commands

| Command | What it does |
|---|---|
| `argus pivot <seed>` | **Headline.** Autonomous correlation from one seed (domain/ip/username/phone/email). |
| `argus run <module> <target>` | Run a single module. |
| `argus all <target>` | Run every module that fits the target. |
| `argus modules` | List modules. |

Flags on `pivot`: `--depth N` (pivot depth, default 2), `--max N` (entity
cap, default 40), `--deep N` (re-pivot into N discovered subdomains),
`--json` (machine output — the full node/edge/finding graph).

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
found, and write them where the rules read (`--probe` / `--probe-paths`, opt-in
because probing is active). Web-exposure evidence is harvested from the
`owasp_scanner` misconfiguration/disclosure patterns:

| Predicate | Provider | Establishes |
|---|---|---|
| `security_headers_missing` / `insecure_cookie` | `http_probe` | hardening gaps + cookie flags — free, from the one `/` response |
| `exposed_sensitive_file` | `exposure_probe` | a reachable `.git` / `.env` / `.DS_Store` whose body confirms the real file |

Each is an *observation* only; the conclusion is a TOML rule
([`rules/exposed_sensitive_file.toml`](argus/rules/exposed_sensitive_file.toml),
`missing_security_headers`, `insecure_cookie`). `argus coverage` maps every
predicate to its provider.

## Architecture

```
core.py     finding model · module registry · validated HTTP · input guards
modules.py  built-in recon modules (the hands)
pivot.py    discovery — bounded BFS correlation into an entity graph
engine.py   Investigator Rule Engine — read-only reasoning: rules, predicates, conclusions, ledger
rules/      declarative TOML rule files (data, never code)
cli.py      pivot / run / all / modules
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

- **Evidence providers** — modules that assert probe facts (e.g. ExploitDB →
  `public_exploit`, a TLS probe → `certificate_reused`) so existing rules fire
  on real evidence. No engine/rule changes — just better evidence.
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
