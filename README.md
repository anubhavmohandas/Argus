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
pip install -r requirements.txt   # only dep: phonenumbers (for the phone module)
python3 -m argus modules          # list capabilities
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

## Architecture

```
core.py     finding model · module registry · validated HTTP · input guards
modules.py  built-in recon modules (the hands)
pivot.py    the Investigation Engine — bounded BFS correlation over an entity graph
triage.py   deterministic "what matters" reasoning over that graph
cli.py      pivot / run / all / modules
```

The deterministic reasoning stack (pivot + triage, and the Investigator Rule
Engine to come) **is** the Investigation Engine — the identity of the system.
See [`docs/ENGINEERING_PRINCIPLES.md`](docs/ENGINEERING_PRINCIPLES.md).

## Roadmap

- **Investigator Rule Engine** — data-defined rules over the graph that emit
  priorities, hypotheses, and recommendations with *traceable* confidence
  scores. Deterministic; see the principles doc.
- **Optional LLM layer (NYX)** — sits *above* the engine to explain,
  summarize, converse, and answer questions over its output. It never decides
  investigation logic — that stays deterministic (Rule 7).
- **Your `MY OWN` tools** — recon_scanner / owasp_scanner / whoisuser /
  secure_gen / CyberTrace register as modules and feed the same graph.
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
concept from [CAI](https://github.com/aliasrobotics/cai).
