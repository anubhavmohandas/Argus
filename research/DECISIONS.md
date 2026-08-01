# Argus Architecture Decisions

Institutional memory. Each entry is a decision **already made and live in
the code** — not a proposal, not a plan. If it isn't in `argus/` yet, it
belongs on [BOARD.md](BOARD.md) or in an issue, not here.

**One exception, added deliberately:** an *invariant locked before the
code exists* may be recorded as `Locked — not yet built`, but only if it
(a) constrains an implementation rather than describing one, (b) names
what it will govern, and (c) states how it gets enforced. That's a
binding constraint, not a plan. A roadmap item wearing this status is
the failure mode to watch for — if it can't be violated by a future
commit, it isn't an invariant.

**Format:** one screen, max. Decision · Why · Consequences · Rejected ·
Revisit when.

Two of those do the real work. **Rejected** answers "why doesn't Argus
just use X" before it gets asked again. **Consequences** lists what the
decision *costs us* — every entry needs `✗` lines, and an ADR with only
`✓` lines is marketing, not a record. The road not taken goes in
Rejected; the price of the road we took goes in Consequences.

**Status:** Accepted · Superseded by ADR-N · Under review

---

## ADR-001 — Native in-memory entity graph, not a graph database

**Status:** Accepted (under review for persistence)

**Decision.** The investigation graph is a plain dataclass in
[`argus/pivot.py`](../argus/pivot.py) — nodes and edges in dicts, bounded
by `Budget` (depth, max entities), serialized to JSON. No Neo4j, no
networkx.

**Why.** Argus has to run on Windows, macOS, and Linux with `pip install`
and nothing else. A graph server is a deployment story, and "drop it
anywhere" is the product. Graph size is bounded by the pivot budget, so
an embedded structure is sufficient — we are not storing an enterprise
knowledge base, we're storing one investigation.

**Consequences.**
- ✓ Zero deployment dependencies — runs from a checkout, on any of the three OSes
- ✓ The graph serializes to JSON for free; the NYX contract is nearly a `asdict()`
- ✗ No Cypher. Every traversal is hand-written Python and ours to keep correct
- ✗ Path-finding for the hypothesis engine is a thing we build, not a thing we query
- ✗ Nothing survives the process except what `store.py` chooses to write

**Rejected.** Neo4j (what BloodHound and OpenCTI both use). It buys real
path queries and a mature query language; it costs a service dependency
that would make Argus un-runnable in exactly the environments it's for.

**Revisit when.** Cross-seed correlation needs queries *across* cases
rather than within one. The bar then is an **embedded** store (SQLite),
not a server — see ADR-004.

---

## ADR-002 — Decorator module registry, not a plugin loader or event bus

**Status:** Accepted

**Decision.** `@module(name, kind, help)` in
[`argus/core.py:49`](../argus/core.py#L49) registers a function into
`MODULES` at import time. Adding a capability = writing one decorated
function that yields `Finding`s. Importing `argus.modules` is the whole
discovery mechanism.

**Why.** No manifest, no directory scan, no lifecycle, no module state
machine. The registry is ~10 lines and there is nothing to debug at 3am.

**Consequences.**
- ✓ A new capability is one decorated function — no manifest, no registration step
- ✓ The call graph stays explicit and greppable, which matters most in correlation code
- ✗ No third-party drop-in modules; adding one means editing the package
- ✗ Every module is imported at startup whether the run uses it or not
- ✗ Modules can't react to entity types — the pivot engine calls them, they don't subscribe

**Rejected.** SpiderFoot's module loader + event bus. It buys dynamic
third-party modules and loose coupling between producers and consumers of
entity types. Nobody is shipping third-party Argus modules, and the event
bus would replace one explicit call graph with an implicit one — harder to
trace for exactly the correlation logic that most needs tracing.

**Revisit when.** Third parties want to ship modules Argus can't import at
build time, or the pivot engine needs modules to react to entity types
rather than being called on them.

---

## ADR-003 — Triage is deterministic and permanent, not an LLM placeholder

**Status:** Accepted (locked — boundary decision)

**Decision.** [`argus/triage.py`](../argus/triage.py) scores entities from
name and finding tokens and exposes `prioritize` / `top_priority` / `why`.
This is Argus's investigation reasoning. It is **not** a stub awaiting a
model.

**Why.** The boundary: **Argus reasons deterministically over its graph
(correlation, scoring, triage, hypotheses); NYX reasons in natural
language on top of Argus's output.** Neither project depends on the other.
Argus stays fully useful with no API key, no network to a model, and no
budget. `why()` exists so every score is explainable — that is the
property an LLM score would not have, and it's why this is an
architectural choice rather than a temporary one.

**Consequences.**
- ✓ Reproducible run to run; the whole triage path is testable offline, no key, no network
- ✓ Every score is explainable — `why()` is a first-class output, not a debug aid
- ✗ Scoring quality is capped by the rules we write. It will never surprise us
- ✗ New signal types cost code, not prompting
- ✗ Someone has to own weight tuning as the module set grows, or the scores drift out of calibration

**Rejected.** LLM-scored triage as the primary path. It would make the
core product depend on an external service, make output non-reproducible
run to run, and hand Argus's identity to whatever model was cheapest that
quarter.

**Revisit when.** Never for the primary path. NYX *reads* these outputs;
it does not replace them.

**Amended by ADR-007.** The determinism decision stands unchanged. What
moves is the *implementation*: triage becomes one consumer of the rule
engine rather than its own scoring pass. `prioritize` / `top_priority` /
`why` stay as the public surface.

---

## ADR-004 — Investigation memory is flat JSON case files, not SQLite

**Status:** Accepted (under review)

**Decision.** One JSON file per seed slug under `$ARGUS_HOME`
(default `~/.argus`) — [`argus/store.py:26`](../argus/store.py#L26).
`history` / `save` / `diff_keys` / `compare_line`. Comparing two runs is a
dict diff.

**Why.** Zero dependencies, human-readable, greppable, and portable across
all three target OSes with no file-locking or migration story. The current
workload is "load the previous run for this one seed and diff it" — that's
a file read, not a query.

**Consequences.**
- ✓ Zero deps; a case file is greppable, diffable, and hand-inspectable mid-engagement
- ✓ "What changed since last run" is a dict compare, not a migration-versioned query
- ✗ No query *across* cases — cross-seed correlation would be a full directory scan
- ✗ No concurrent-write story: two pivots on the same seed race and last-write-wins
- ✗ The whole file is rewritten on every save; fine at current sizes, not forever

**Rejected (for now).** The pentest-ai-agents SQLite findings schema. The
README roadmap still lists it, and it's the right answer for the workload
below.

**Revisit when.** Cross-seed intelligence lands — "which cases share this
IP" is a query across all files, and that's the point where JSON stops
being the lazy answer and starts being the expensive one. SQLite is
stdlib, so this upgrade costs no new dependency.

---

## ADR-005 — Stdlib-only core; pure-Python deps only

**Status:** Accepted (constraint)

**Decision.** `requirements.txt` is one line: `phonenumbers>=8.13`, for
the phone module. Everything else is `urllib`, `concurrent.futures`,
`dataclasses`, `json`, `re`, `pathlib`.

**Why.** Cross-platform with no wheel that needs a compiler. `pip install`
must never become the reason someone can't run Argus during an engagement.

**Consequences.**
- ✓ `pip install` is one pure-Python wheel — no compiler, no per-platform wheels, no lockfile drama
- ✓ Small supply-chain surface: our code plus one dependency to audit
- ✗ Retries, connection reuse, and timeout handling are hand-rolled on `urllib`
- ✗ Terminal output is ours to format — no `rich`, so the dossier layout is manual
- ✗ Some capabilities may be genuinely out of reach without a dep, and the answer is "then we don't ship it"

**Rejected.** `requests`, `httpx`, `rich`, `click` — each individually
reasonable, collectively the difference between a tool you drop anywhere
and a tool with an environment.

**Revisit when.** Per-dependency, never wholesale. A new dep must be pure
Python and has to beat a stdlib equivalent on something that matters, not
on ergonomics.

---

## ADR-006 — Argus reasons; NYX converses; neither depends on the other

**Status:** Accepted (supersedes the earlier "Argus only collects" framing)

**Decision.** Argus's deliverable is the **investigation graph plus
conclusions**. JSON is the transport format NYX consumes, not the product.
Correlation, scoring, triage, and (next) hypotheses live in Argus. Natural
language, interactive analysis, and cross-domain intelligence live in NYX.

**Why.** Two projects that each stand alone, with a clean seam. Argus is
useful with no LLM present; NYX makes it *feel* like working with another
investigator. Calling Argus's layer "AI" would be wrong — it's encoded
investigator expertise, and it's deterministic on purpose.

**Consequences.**
- ✓ Both projects ship, demo, and version independently
- ✓ Argus is fully testable with no model in the loop — the offline self-checks cover the real product
- ✗ Two codebases must agree on a JSON contract, and contract drift is a live failure mode with no compiler to catch it
- ✗ Some reasoning gets duplicated at the seam; deciding which side owns a given inference is a recurring judgement call
- ✗ Argus has to be judged as a standalone product, not excused as "the data layer"

**Rejected.** The original framing, where Argus wrapped tools and emitted
JSON while all reasoning lived in NYX's `brain.py`. It made Argus a
shell script with a schema and made every useful behavior depend on NYX.

**Revisit when.** The seam leaks — if NYX starts needing to re-derive
things Argus already knows, the boundary is in the wrong place.

---

## ADR-007 — The rule engine is the reasoning layer, not a feature

**Status:** Locked — not yet built
**Governs:** the module that will replace `argus/triage.py`'s scoring pass
**Enforced by:** a loader that rejects any rule file carrying executable
content, plus a self-check that evaluation leaves the graph unchanged

### The invariant

> **The Rule Engine consumes an immutable investigation graph and
> produces deterministic conclusions plus an explanation ledger. It never
> mutates evidence, executes user-defined code, or performs discovery.**

Everything below is subordinate to that sentence. If a future change
conflicts with it, the change is wrong, not the sentence.

**Decision.** One reasoning layer, not five. Priority, correlation,
hypotheses, recommendations, interestingness, and explainability are all
*outputs of the same evaluation* over the same fact set:

```
discovery → graph (evidence, immutable during evaluation)
              ↓
       evidence providers → facts
              ↓
        rule engine ── evaluates declarative rules over predicates
              ↓
   conclusions + explanation ledger
```

**Three roles, kept separate.**

| | |
|---|---|
| **Evidence provider** | a discovery module that asserts facts — `certificate_reused = true`. Knows *how* something was found. |
| **Predicate** | the stable vocabulary a rule may reference. Knows nothing about who found it. |
| **Rule** | declarative: conditions over predicates → a weighted conclusion. Data, never code. |

A rule cannot tell which provider asserted a fact, which is the point:
new discovery modules feed *existing* predicates without touching a
single rule file.

**Why.** Explainability stops being a feature to build. If every
conclusion is produced by evaluating rules, the reasoning already exists
at the moment the conclusion does — the ledger is a byproduct of
evaluation, not a parallel code path that can drift from it. And there is
exactly one place to look when a score is wrong.

### Declarative-only is a security boundary, not a style preference

Rule files are **data**. A rule file that can carry `python:`,
`predicate: lambda …`, `eval`, or an import is a remote-code-execution
primitive in a tool that runs against other people's infrastructure and
whose rule packs will inevitably get shared and pasted from the internet.

The loader rejects executable content structurally — an allowlist of
condition forms, not a denylist of dangerous keys. Anything the schema
doesn't recognise is a load error, not a warning. A rule pack must be
reviewable by reading it.

### Two things this forces us to decide now

**Unknown is not false.** `internet_facing` with no provider assertion
means *we did not look*, which must not score the same as *we looked and
it isn't*. For a security tool that difference is the whole product —
"no evidence of a public exploit" scoring as "no public exploit" is how
you hand someone a false negative with a confident number attached.
Predicates are three-valued: `true` / `false` / `unknown`, and a rule
states which it requires. Silence never satisfies a condition.

**Predicate typos must fail at load, not at evaluation.** A rule
referencing a predicate no provider ever asserts would otherwise sit
there quietly never firing, and a rule that never fires is invisible.
The loader validates every referenced predicate against the registered
vocabulary and refuses to start otherwise.

### Derived facts — and the tension they create

Rule chaining (`internet_facing` + `public_exploit` + `admin_interface`
→ `high_value_exposed_service`, consumed by a further rule) is worth
having, and it conflicts with "never mutates evidence" unless it's
resolved explicitly:

- Derived facts go in a **separate fact set**, never into the graph. The
  graph stays exactly as discovery left it. Evidence and inference never
  share a container.
- Rules are **monotonic** — they add facts, never retract them.
- Evaluation runs to a **fixpoint with a hard round cap**. No cycles, no
  order-dependence, guaranteed termination.

Those three together are what keep "deterministic" true once rules can
feed rules. Without them, chaining quietly makes output depend on rule
file ordering, which is the bug you'd never find.

**Consequences.**
- ✓ Explainability is free and cannot drift from the logic that produced the score
- ✓ One place to change how Argus prioritises anything
- ✓ Rules are reviewable, diffable, and shippable as packs without shipping code
- ✓ Discovery modules can be added without touching reasoning, and vice versa
- ✗ Every genuinely new *kind* of evidence needs an engine change, not just a rule
- ✗ The predicate vocabulary becomes a public contract — renaming one breaks every rule pack
- ✗ Fixpoint evaluation is more machinery than a single scoring pass, and the round cap is a real ceiling
- ✗ Expressiveness is deliberately capped: anything a declarative form can't say, Argus can't conclude

**Rejected.**
- **Executable rule files** (`python:`, `lambda`, plugin callbacks). Buys
  unlimited expressiveness, costs the review property and hands an RCE to
  anyone who ships a rule pack. Not a trade, a mistake.
- **Rules mutating the graph** — synthetic nodes, edge deletion,
  confidence rewriting. Once reasoning edits evidence, no run is
  reproducible and no conclusion is traceable to what was actually found.
- **Runtime LLM-generated rules.** NYX may *propose* a rule to a human;
  it never injects one into an evaluation. That's ADR-003 and ADR-006
  applied to this layer.

**Revisit when.** The engine change per new evidence type becomes the
actual bottleneck — measured in "how often did we edit the engine this
quarter", not anticipated. The answer then is a wider predicate
vocabulary, not executable rules; that door stays shut.

---

## Open — no decision yet

These are live questions. They become ADRs when the code does, not before.

- **Hypothesis engine** — *shape* now locked by ADR-007 (it's a rule
  consumer, not a subsystem). Still open: how confidence is computed and
  expressed. BloodHound, OpenCTI, MISP are queued precisely for this.
- **Knowledge-graph persistence** — see ADR-001 / ADR-004; the two are one
  decision when it lands.
- **Tool wrapping** — current modules are native stdlib lookups, not
  nmap/Subfinder/Shodan wrappers. Whether Argus shells out at all, and how
  it degrades when a binary isn't on the box, is undecided.
