# Argus Research Board

Engineering playbook. One row per repository. The question is never
"which repo do we merge?" — it's **"which engineering idea does Argus
learn from this?"** Ideas get reimplemented natively; code does not get
imported.

**Where things live**

| | |
|---|---|
| Clones / zips | `Tools/` — gitignored, disposable, delete after study |
| Notes | `research/repos/<name>.md` — committed, permanent |
| This board | the index; a repo isn't studied until it has a row *and* a page |
| `research/DECISIONS.md` | the ADR log — where a study that changed architecture ends up |
| Attribution | when an idea ships, log the source in README → Attribution |

**Rules that keep this from becoming a graveyard**

- Max **3** open studies at a time. Finish or drop.
- **10 minutes** per repo: README → structure → core module → page. Over
  budget means the repo is a Category C, close it.
- Read README *before* cloning. Most repos never get cloned.
- Skip `tests/ examples/ vendor/ assets/ docs/` on the first pass.
- A study that produces zero ideas is a **success** — write "nothing" and
  move on. That's the filter working.

---

## Scoring

`★★★★★` architecture · ideas · code quality, judged **for Argus's
purposes only** — a 5-star product can be a 1-star teacher.

**Decision** is the column that matters. Not "what did we learn" — *what
did we do about it*. A verb plus the specific thing:

| | |
|---|---|
| **Build** | reimplement the idea natively — "Build: path queries over the entity graph" |
| **Adapt** | useful in reduced form — "Adapt: confidence, drop the STIX schema" |
| **Reject** | considered and declined — "Reject: event bus, decorator registry is enough" |
| **Keep** | it validated what Argus already does — "Keep: current enum design" |

`Reject` and `Keep` are not failures. A study whose output is "we looked
at this and changed nothing, here's why" is the study paying for itself
the second time someone proposes it.

A decision that changes architecture graduates to an ADR in
[DECISIONS.md](DECISIONS.md). The board says *what we decided*; the ADR
says *why, and what we gave up*.

---

## Category A — Must study (these move architecture)

Each is tied to an **open** item on the Argus maturity checklist. If a
repo doesn't map to a gap, it's not Category A.

| Repository | Category | Rating | What we learn | Closes gap | Decision | Status |
|---|---|---|---|---|---|---|
| BloodHound | Graph | — | Relationship modeling; derived edges; **paths as findings** | hypothesis engine | | queued |
| OpenCTI | Threat intel | — | Entity schema, confidence, evidence chains | hypothesis confidence + graph persistence | | queued |
| MISP | Threat intel | — | IOC modeling, correlation across cases, sharing format | cross-seed intelligence | | queued |
| Amass | Recon | — | Recursive enumeration, **source weighting**, ASN correlation | deeper pivot + per-source confidence | | queued |
| SpiderFoot | OSINT | — | Module loader, event bus, module↔type contract | module registry v2 | Reject: event bus — see [ADR-002](DECISIONS.md) | decided ahead of study; confirm or overturn |
| Nuclei | Scanner | — | Template model, severity taxonomy, finding schema | triage inputs | | queued |
| Neo4j / Graphiti | Graph | — | Persistence, temporal graph, query model | knowledge-graph persistence | Reject: server dep — see [ADR-001](DECISIONS.md) | decided ahead of study; embedded store still open |
| CAI | AI | — | Agent loop, guardrails, tool execution | LLM assistant (NYX layer) | Adapt: loop as *optional* driver | concept in README roadmap; full study pending |

Ratings are `—` until someone has actually read the code. Two rows carry
a decision made *before* the study — that's honest, not a shortcut: the
existing architecture already rejected those approaches, and the study's
job is to confirm or overturn that, not to start from zero.

**Open gaps, for reference:** ⬜ hypothesis engine · ⬜ knowledge-graph
persistence · ⬜ cross-seed intelligence · ⬜ interactive investigation ·
⬜ LLM assistant (NYX). Done: ✓ discovery ✓ correlation ✓ investigation
graph ✓ module registry ✓ triage ✓ investigation memory.

### This week

Three only, all pointed at the **hypothesis engine** (the next specced
build): **BloodHound**, **OpenCTI**, **MISP**. Paths, confidence, and
cross-case correlation are exactly that feature's three unknowns.

---

## Category B — One feature each

Read the one thing, take it, close the tab.

| Repository | The one thing | Status |
|---|---|---|
| httpx | HTTP fingerprinting + probe concurrency | queued |
| Subfinder | Passive source fan-out + dedup | queued |
| Findomain | Throughput / rate-limit handling | queued |
| Katana / Hakrawler | Crawl → endpoint extraction | queued |
| Sherlock / Holehe | Identity pivots, false-positive handling | queued |
| Photon | Endpoint + secret extraction from crawl | queued |
| theHarvester | Email/domain source aggregation | queued |
| CT log parsers (certstream et al.) | Streaming CT ingest vs. crt.sh polling | queued |

## Category C — Curiosity

README only. No clone, no page. Listed here just so it isn't re-opened.

*(empty)*

---

## Already harvested

Studied and reimplemented natively — see README → Attribution.

| Repository | Rating | What was taken | Decision | Page |
|---|---|---|---|---|
| Claude-OSINT | — | 48-pattern secret catalog; recon arsenal | Build: patterns reimplemented natively | pending backfill |
| GhostTrack | — | IP geo/ASN, phone, username enumeration | Build: reimplemented + hardened (input validation) | pending backfill |
| Shadowbroker | — | Recon-toolkit patterns | Build: rdap/dns, native | pending backfill |
| pentest-ai-agents | — | Findings-DB schema | Adapt: schema only; SQLite deferred — see [ADR-004](DECISIONS.md) | pending backfill |

Pages are missing because these were studied before the board existed.
Backfill is cheap and worth it — the *rejected* ideas are the part that
gets forgotten.

## Own tools — module donors

`Tools/MY OWN/`. Not "study" so much as "port": each should register as
an Argus module feeding the same graph.

| Tool | Feeds | Status |
|---|---|---|
| recon_scanner | recon modules | queued |
| owasp_scanner | findings + severity, bug-bounty scope parsing | queued |
| whoisuser | identity pivots | queued |
| CyberTrace | tracing / correlation | queued |
| secure_gen | payloads — likely out of scope (Argus is passive) | queued |

---

## Workflow

```
interesting repo → README (5 min) → worth it?
                                      ├─ no  → Category C row, done
                                      └─ yes → clone into Tools/
                                               → 10-min read
                                               → research/repos/<name>.md
                                               → row on this board
                                               → delete the clone
                                               → implement natively
```

Last step is **implement natively** — not copy, not fork, not vendor.
