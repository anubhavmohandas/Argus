# Argus — Engineering Principles

> **Argus is not an AI pentesting tool. Argus is a deterministic offensive
> intelligence engine that models how experienced investigators collect,
> correlate, prioritize, and explain evidence. AI is optional and sits above
> that foundation — not beneath it.**

That sentence is the constitution. Everything below defends it. Read this
before proposing an architectural change — it exists to prevent drift a year
from now, when Argus has 80+ modules and a change "just needs a quick LLM
call here."

## Identity

Argus is **a deterministic investigation platform for offensive security**.
The load-bearing word is *investigation* — it explains the whole vocabulary
(investigation graph, investigation memory, Investigation Engine, Investigator
Rule Engine, investigation dossier) and the pipeline that separates Argus from
a scanner:

```
Collect → Model → Remember → Reason → Explain
```

Most tools stop at `Collect → Display`; a few reach `Collect → Analyze →
Display`. Making *persistent investigation* the core abstraction — not "run
another scan" — is the whole difference.

---

## The ten principles

### 1. Discovery is deterministic
The same seed produces the same graph. Enumeration, resolution, and
correlation are mechanical walks over public sources — no model in the loop,
no run-to-run variance. Reproducibility is a security property: an
investigator has to be able to trust that what Argus found is what is there.

### 2. Reasoning is deterministic
Priority, interestingness, relationships, hypotheses, recommendations, and
warnings are all produced by rules over the graph — not by a model's
judgement. This is encoded investigator expertise, and it is Argus's job
**permanently**. It is never a placeholder to be swapped out for an LLM.

### 3. Every conclusion must be explainable
No output is allowed to be a bare number or a verdict. If Argus says
something is high priority, or states a hypothesis, it must be able to answer
"why?" with the exact chain of facts and rules that produced it. Nothing
hidden, no magic.

### 4. Every confidence score must be traceable
A confidence score is the sum of a base rule and named evidence adjustments —
each with a sign, a weight, and a source. A score you cannot decompose into
its inputs is a score you cannot defend, and Argus does not emit it.

### 5. Memory stores facts, not conversations
Investigation memory persists **evidence** — graphs, findings, case files —
not chat history or prompt logs. Memory answers "what did I learn about this
target, and what changed since last time," not "what did we talk about." The
graph is what Argus remembers.

### 6. Graphs are the source of truth
The investigation graph is the product. JSON is only its transport format.
Every module, every rule, and every consumer (including NYX) reads from and
writes to the graph — not to each other. There is one canonical
representation of what is known, and it is the graph.

### 7. LLMs never replace investigator logic
An optional LLM layer (NYX) sits **above** the engine. It may:

- explain,
- summarize,
- converse,
- synthesize,
- and answer questions.

It may **not** collect, correlate, score, prioritize, or decide what to
investigate. Those are deterministic and stay in the engine. Argus is fully
useful with no LLM present; the LLM makes it *feel* like working with another
investigator. Neither project depends on the other.

### 8. Reasoning is reproducible
Given the same graph, the same rule set, and the same engine version, Argus
produces identical conclusions. No randomness, no temperature, no hidden state,
no nondeterminism. `engine.fingerprint(graph, rules)` hashes the evidence and
the rules; if it is unchanged, the conclusions are guaranteed unchanged. This
is as load-bearing as "graphs are the source of truth": an investigator must be
able to re-run last week's investigation and trust that a changed conclusion
means changed *evidence* — never a changed mood.

### 9. Rule definitions are declarative; their parser cannot execute code
Rule definitions must be declarative data, and the parser that loads them must
not be capable of executing code — no `eval`, no serialization format that can
carry a callable, no predicate a rule file defines for itself. This is why
rules ship as TOML (stdlib `tomllib`, structurally codeless) and why the loader
is a **structural allowlist**: a rule may only name predicates the engine
already implements, and any unrecognised key is a load error, not a silent
skip. Data that can become executable is not data — it is an attack surface,
and in a security tool that is the one surface you never build. This principle
outranks convenience: if a future rule needs logic the vocabulary can't
express, the answer is a new predicate in engine code under review, never an
escape hatch in the rule file.

### 10. Providers contribute observations, never conclusions
A provider answers exactly one question — *"what evidence can I establish?"* —
and never *"what conclusion should I draw?"* It may assert what it observed on
the wire (`technology = jenkins`, because the response carried an `X-Jenkins`
header). It may not assert what that means: not "high risk", not "exploitable",
not even "this is an administrative interface". A provider that knows Jenkins is
an admin surface has become a second rule engine, and now investigator knowledge
lives in two places that will disagree. So the provider reports the header and
`rules/jenkins_confirmed.toml` draws the conclusion — that is the *only* reason
adding a provider requires no engine change, which is the property the whole
architecture is built to have. The full chain:

```
Discovery → Observation → Evidence → Predicates → Rules → Conclusions
```

Providers own the first two arrows and nothing after them. See
[`EVIDENCE_MODEL.md`](EVIDENCE_MODEL.md) for how observations are represented
today and how they will be represented when providers start disagreeing.

---

## The Investigator Rule Engine

> **The Rule Engine invariant (locked):** *The Rule Engine consumes an
> immutable investigation graph and produces deterministic conclusions plus an
> explanation ledger. It never mutates evidence, executes user-defined code, or
> performs discovery.*

That one sentence is the governing contract for the whole reasoning layer. Its
three "never"s each close a specific failure mode:

- **never mutates evidence** — the graph is read-only *during* evaluation.
  Rules interpret evidence; they do not create synthetic nodes, delete edges,
  or rewrite confidence on the graph. Keeping data and reasoning separate is
  what makes the engine deterministic and testable: re-run it against the same
  graph, get the same conclusions, forever. The moment rules mutate the graph,
  reasoning and data intertwine and neither is trustworthy.
- **never executes user-defined code** — see "Rules are declarative data" below.
- **never performs discovery** — collection lives upstream in modules. The
  engine reads what discovery already found; it does not go fetch.

Principles 2, 3, and 4 are embodied by one component: the **Investigator Rule
Engine**. Not a "hypothesis engine" — hypotheses are only one of its outputs.

**It is not a feature; it is the brain of the Investigation Engine.** All
deterministic reasoning routes through this one layer, and every reasoning
output is a product of it:

```
Discovery → Graph → Rule Engine → { priority · interestingness · correlation ·
                                    hypotheses · recommendations · warnings ·
                                    explainability }
```

That inversion is the point. Hundreds of investigator rules are coming — AWS
exposure, exposed Jenkins, misconfigured S3, public Grafana, open
Elasticsearch, orphaned domains, shared CDN origins, suspicious certificate
reuse. If each lives in its own subsystem, the logic scatters and rots. One
deterministic reasoning layer, fed by the graph, keeps it maintainable — and
makes every new discovery module *compound* in value (new evidence → new rules
fire → better investigation) instead of just producing more JSON.

Triage was the standalone proto of this layer. As of Phase 3.1 it is **folded
in**: priority and interestingness are `engine.investigate()`'s read-only
scoring output, not a separate subsystem. Every consumer — the dossier, JSON,
a future API, NYX — reads one `InvestigationResult` (`conclusions`, `priority`,
`interesting`, `recommendations`, `ledger`, `fingerprint`), never engine
internals. There is one reasoning authority.

### Two levels, so it stays both deterministic and extensible

**Level 1 — a rule fires and creates a conclusion with a base confidence.**

```
admin.example.com  +  Jenkins detected  +  Internet-facing
        └──> rule: "Administrative Jenkins exposed"   base_confidence: 55
```

**Level 2 — evidence adjusts that confidence, up or down.**

```
+ public exploit exists        +10
+ known exploited              +15
- authentication required      -20
- behind VPN                   -35
- recently patched             -15
```

The rule *creates* the hypothesis; the evidence *tunes* the confidence. Both
steps are deterministic, both are logged.

### Rules are declarative data — never code

A new piece of investigator knowledge is a new data entry — never an engine
change. A generic evaluator walks the rule set; adding rule #120 touches no
Python, it adds a file. Rules ship as **TOML** (`argus/rules/*.toml`) — parsed
by stdlib `tomllib`, zero dependencies, and a format that structurally *cannot*
express code, which enforces the boundary below rather than trusting authors to
respect it. The schema is identical in any serialization; the shape is:

```yaml
id: jenkins_suspected
requires:
  name_suggests_technology: jenkins
  publicly_discoverable: true
base_confidence: 40
adjustments:
  - if: internet_facing      # probe-confirmed; raises a lead toward a fact
    add: 15
  - if: public_exploit
    add: 10
outputs:
  priority: high
  recommendation:
    - Inspect authentication
    - Check plugin versions
  hypothesis:
    - Administrative interface may be externally accessible
```

**Hard boundary: rules never execute arbitrary code.** A rule is a fixed
declarative vocabulary — `requires` / `adjustments` / `outputs` — that the
engine *interprets*; it is not a script the engine *runs*. This is a
scalability rule (contributors add data, not engine changes) and, more
importantly, a **security rule**: rule files are data, and data must never
become executable. No `eval`, no `if:` expression that evaluates as Python, no
plugin hook that runs rule-supplied code. The condition vocabulary
(`public_exploit`, `internet_facing`, …) is a closed set the engine resolves
against the graph — extend it in the engine, under review, not from a rule
file. Enforcement is a **structural allowlist**: exactly the keys above, and
anything the schema doesn't recognise is a load error. A denylist of scary
words only catches what we thought of, and silently accepts a typo'd
`[[adjustment]]` that then never fires.

### Predicates vs. evidence providers

A rule references **predicates** (`internet_facing`, `public_exploit`,
`certificate_reused`). It asks only *whether the predicate is true* — never
*who discovered it*. **Evidence providers** (`argus/providers.py`) set those
predicates on the graph: a certificate analyzer writes `certificate_reused =
true`, and every rule referencing that predicate now fires.

Providers are a distinct category from discovery modules, and the difference is
worth keeping straight. A **module** finds new entities and yields `Finding`s
that discovery pivots into — it grows the graph. A **provider** establishes
facts about entities the graph already has and writes them to
`Entity.evidence` — it grows what is *known*, never the shape. Modules answer
"what else is out there?"; providers answer "what is true about this?"

**Predicates are three-valued: true / false / unknown.** Absence of an
assertion is `unknown`, never `false` — *"nobody checked"* and *"checked, it
isn't"* are different claims (invariant I-1). Silence never satisfies a
requirement, so a rule asking for `authentication_required = false` will not
fire on a host no one probed. The ledger renders unknowns as `?` and lists
them, which turns them into the operator's work queue: each one is a number
the confidence does *not* yet account for.

**The vocabulary has two tiers, and the names say which.**

| Tier | Examples | Established by |
|---|---|---|
| **Discovery** — observations | `publicly_discoverable`, `name_suggests_admin`, `name_suggests_preprod`, `name_suggests_cdn`, `name_suggests_technology` | a public source, or the hostname itself. Determinate — the name is fully known. |
| **Probe** — facts about the host | `internet_facing`, `has_admin_interface`, `technology`, `authentication_required`, `public_exploit` | something that actually checked. `unknown` until then; never inferred from a name or an entity type. |

A hostname containing `admin` is a **lead**, not a finding. Calling that
predicate `has_admin_interface` would have Argus reporting a name as a fact —
so the name-derived one is called `name_suggests_admin`, and
`has_admin_interface` is reserved for a probe. Confidence follows the same
split: a rule's base is what the name justifies, and the probe-confirmed
predicate is an adjustment on top. That gap *is* the difference between
suspected and verified, expressed in a number.

Because `requires` is AND-only by design, the two tiers usually mean two
rules rather than an OR in the schema — `jenkins_suspected` (name) and
`jenkins_confirmed` (probe). Two rules, two confidences, two provenance
trails, no evaluator change.

This is what makes the closed-vocabulary trade-off livable. **A new module
feeding an existing predicate needs no engine change** — it just produces
evidence. Only a genuinely *new predicate* — a new word in Argus's
investigation vocabulary — goes through engine code review. That review is
governance, not friction: it is the gate that decides a concept deserves to be
something Argus reasons about.

### Derived facts (future — not v1)

Once the engine is stable, one capability comes almost for free: a rule's
output can itself become a predicate another rule consumes. `internet_facing +
public_exploit + has_admin_interface` → derived fact `high_value_exposed_service`
→ a priority rule consumes that. This is **bounded forward-chaining over
derived facts, not arbitrary recursion** — still declarative, still fully
explainable (the ledger gains one hop). v1 does **not** build this, but v1 must
not *preclude* it: predicates and rule outputs share one namespace, so a
conclusion can be referenced as a condition later without reworking the
evaluator.

This does **not** break the read-only invariant, because derived facts are not
evidence. The immutable **evidence graph** (what discovery found) is never
written to; derived facts accumulate in a separate **conclusions layer** the
engine owns. Rules *read* from evidence + already-derived facts and *write*
only to the conclusions layer. Evidence stays immutable; reasoning stays
deterministic.

### Every output carries its own explanation

Because rules and adjustments are data, the trace is free. When a user asks
"why 73%?", Argus answers with the ledger, not a paragraph:

```
Confidence: 73%

Rule fired
  ✓ Jenkins detected
  ✓ Internet-facing
  ✓ Public exploit exists
  ✓ Version vulnerable

Negative evidence
  ✗ Authentication required   -20

Final confidence: 73%
```

A hypothesis is a **claim worth investigating**, never a truth assertion.
"Based on everything I know, this is worth your time" — that is what a senior
investigator says, and it is all Argus claims.

---

## The Provider Contract

Principle 10 says a provider contributes observations, never conclusions. This
is its operational form: the fixed shape every provider must satisfy so that the
hundredth one is mechanical and still never reopens `engine.py`. Freezing it
before the first Analysis provider is the same investment already paid for probe
providers — define the interface once, and implementation becomes almost
copy-work.

### Three classes, one contract

Providers differ only in *where the observation comes from*. What they may **do**
with it is identical.

| Class | Reads | Example | Contributes |
|---|---|---|---|
| **Discovery** | public sources | DNS, CT logs, RDAP | new entities — grows the graph |
| **Probe** | the target, over the network | HTTP, TLS | facts about a host it contacted |
| **Analysis** | the graph itself — no network | certificate reuse, ASN clustering | facts derived by comparing nodes |

**Analysis** is the newest and strictest class: it reads `observed` and
`evidence` across nodes, compares, and asserts a predicate — touching no network
and mutating no graph shape. The separation that holds everywhere else holds
here too: the TLS *probe* records a certificate fingerprint; the *analyzer*
notices the same fingerprint on two hosts and asserts `certificate_reused`. The
probe never claims reuse — it has only ever seen one host.

### The completion checklist

A provider is not done until every answer is "yes". These are Principle 10 made
checkable:

1. **Observations only** — it asserts facts, never priority, confidence, or risk.
2. **No conclusions** — "what it means" is left entirely to the rules.
3. **Declares its predicates** — registered with `@declares(...)`, so
   `argus coverage` sees it and the coverage map cannot drift.
4. **Independently testable** — its core runs with no network and no engine.
5. **No engine change** — it plugs in without touching `engine.py` or a rule file.
6. **Preserves the ledger** — every predicate it sets appears, signed and
   sourced, in the explanation.
7. **Minimum evidence** — it persists the *smallest* observation set that enables
   downstream reasoning, and nothing more.

Item 7 is the guard on the observation channel. Persist the certificate
fingerprint, issuer, SANs, and validity dates a rule will actually use — not the
whole certificate, the raw HTML, or every header. The moment a provider stores
what nothing consumes, the channel stops being evidence and becomes a database
nobody queries. Smallest set that enables the reasoning; no more.

### Two per-entity channels: `evidence` and `observed`

The split is load-bearing — it is what lets a provider establish a fact from data
that is not itself a predicate:

- **`evidence`** — engine-vocabulary predicates only (`technology`,
  `known_exploited`). The Rule Engine reads it through `_ev()`; it feeds the
  fingerprint, and therefore the conclusions.
- **`observed`** — non-predicate facts one provider records for another
  (`version` → the KEV provider; `cert_fingerprint` → the certificate analyzer).
  The engine never reads it, so — by design, and consistent with
  [`EVIDENCE_MODEL.md`](EVIDENCE_MODEL.md) Trap 1 — it never enters the
  reproducibility hash. Raw observation stays here; only the *derived* predicate
  crosses into `evidence`.

That seam is why the KEV provider could assert `known_exploited` from a version
it never had to make a predicate, and it is the same seam the TLS provider and
certificate analyzer will use. `observed` is the lightweight form of the fuller
observation model in [`EVIDENCE_MODEL.md`](EVIDENCE_MODEL.md); when a third
provider makes provenance matter, that document — not this contract — is where
the representation grows.

**The observation channel is intentionally minimal, not unfinished.** It is
expected to evolve into the Claim model in [`EVIDENCE_MODEL.md`](EVIDENCE_MODEL.md)
*when multiple providers or conflicting observations require it* — the trigger is
a real disagreement (two providers, one exclusive field, incompatible values),
not a provider count. Until then, do not introduce structure that has no
consumer: a single provider writing a single value per field is honestly
representable today, and `Entity.observed` is right-sized for exactly that.

---

## For contributors

Before you add code, check it against the constitution:

- Adding intelligence? It goes in a **rule (data)**, not in the engine, and it
  must be explainable and traceable (Principles 2–4).
- Adding a provider? It satisfies the **Provider Contract** — observations only,
  declares its predicates, independently testable, no engine change (Principle 10).
- Reaching for an LLM? Only if the task is explain / summarize / converse /
  synthesize / answer. Anything that collects, correlates, scores, or decides
  stays deterministic (Principle 7).
- Adding an output? It reads from and writes to the **graph** (Principle 6).
- Adding memory? It stores **evidence**, not conversation (Principle 5).

If a change can't satisfy these, it isn't an Argus change — it's a NYX change,
or it doesn't belong.
