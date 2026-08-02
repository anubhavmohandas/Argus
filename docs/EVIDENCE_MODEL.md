# Argus — The Evidence Model

> **Status: design note, not a specification. Nothing here is built.**
> Written 2026-08-02, one provider in, while the problem is visible but not yet
> painful. It exists so that provider #5 and provider #12 don't paint us into a
> corner. Do not implement it until the trigger at the bottom fires.

Governed by [Principle 10](ENGINEERING_PRINCIPLES.md): *providers contribute
observations, never conclusions.* This document works out what an "observation"
actually is.

---

## What exists today

One provider ([`argus/providers.py`](../argus/providers.py)), and evidence is a
flat dict on the entity:

```python
Entity.evidence = {"technology": "jenkins", "internet_facing": True}
```

The rule engine reads it through `_ev(name)`, a one-line resolver. Absent means
unknown (I-1). It works, it is three lines of machinery, and with one provider
it is exactly the right amount of structure.

Its limit is precise: **a value carries no account of where it came from.** The
ledger can say `technology +10` but not *who said so, how, or when*. With one
provider that's invisible, because there is only one possible answer.

---

## The four questions, answered

### 1. What is an observation?

**A single claim, by one provider, about one field of one entity, at one time,
by one method.** It is the atomic unit of what Argus was told.

An observation is not a fact about the world. It is a fact about *what we saw* —
`X-Jenkins` was in the response headers at 14:02 UTC. That distinction is the
whole model: the world can change, providers can be wrong, two providers can
look at different things. What never changes is that we observed what we
observed.

```
Observation
  entity      subdomain:jenkins.example.com
  field       technology
  value       jenkins
  provider    http_probe
  method      header:x-jenkins
  observed_at 2026-08-02T14:02:11Z
```

### 2. What is evidence?

**Evidence is the resolved view of the observations for a field** — what Argus
is prepared to assert, after reconciling everything it was told.

```
observations  ──[resolution]──>  evidence  ──[_ev()]──>  predicate  ──> rules
```

That is the key structural move: **observations accumulate, evidence is
derived.** Today the two are collapsed (`evidence.update()` overwrites, so
evidence *is* the last observation). Separating them is the actual Phase 3.2
change; everything else follows from it.

Note where this sits: observations are *evidence-layer* data, not conclusions.
The graph remains the source of truth (Principle 6) and remains immutable during
evaluation (the Rule Engine invariant). Resolution happens after collection and
before evaluation — the engine reads a settled view.

### 3. How do providers report observations?

Unchanged from today, structurally: a provider returns claims and the collection
layer records them. The only difference is that the layer stamps each claim with
who/how/when rather than flattening it.

```python
def probe(host) -> dict:            # today  — provider returns field: value
def probe(host) -> list[Claim]:     # later  — provider returns field, value, method
```

The provider still never sets confidence, priority, or meaning. `method` is not
a judgment — it is a description of what was done (`header:x-jenkins`,
`title-match`, `api:shodan`), and the *weight* of a method is the engine's to
decide (see the trap below).

### 4. How does the Rule Engine consume them?

**Exactly as it does now.** `_ev()` reads the resolved evidence view; predicates
stay three-valued; rules stay unchanged. This is the constraint the design has to
satisfy, not a nice-to-have — if introducing observations forces a rule rewrite,
the design is wrong and should be thrown out.

What improves is the **ledger**. Instead of:

```
✓ technology                  +10
```

it can render:

```
✓ technology = jenkins        +10
    http_probe · header:x-jenkins · 2026-08-02T14:02Z
    (shodan disagreed: nginx · api:shodan · 2026-07-30T09:11Z — superseded, see below)
```

Principle 3 (explainable) and Principle 4 (traceable) get materially stronger
without the evaluator changing at all.

---

## Conflict — and why most of it isn't conflict

### Most disagreements are both-true

The motivating example is "HTTP says `jenkins`, Shodan says `nginx`". That is
**not a conflict**. A host running nginx in front of Jenkins makes both
observations correct. The real defect is that `technology` is single-valued,
which forces two true statements to fight over one slot.

So the first fix is not a resolution policy. It is:

> **A field is multi-valued unless it is logically exclusive.**

`technology` becomes a set. `_PREDICATES["technology"]` matching `jenkins`
becomes a membership test, and `rules/jenkins_confirmed.toml` fires on a host
that also runs nginx — correctly. Most of the anticipated conflict problem
disappears here, before any policy is needed.

### Genuine conflict is narrow

What is left is one entity, one exclusive field, two incompatible values:

| Kind | Example | Resolution |
|---|---|---|
| **Stale** | auth required (Jul 30) vs. not required (Aug 2) | Newest wins. The world changed; that *is* the finding. |
| **Method strength** | `header:x-jenkins` vs. `title-match` | Stronger method wins. Direct beats inferred. |
| **True contradiction** | same field, same strength, same hour | **Do not resolve. Mark the field `disputed`.** |

The third row is the one that matters, and the answer is deliberately not
"pick one". A disputed field resolves to **unknown**, which by I-1 means no rule
requiring it fires and no adjustment applies — and the ledger says *why* it is
unknown. Argus reporting "two sources disagree, I am not asserting this" is a
correct and useful investigative output. Silently averaging them is not.

This preserves the property the whole system is built on: **silence is never a
negative, and a fabricated resolution is worse than silence.**

---

## Three traps

Recorded because each one is cheap to avoid now and expensive to discover later.

### Trap 1 — `observed_at` breaks the fingerprint

`engine._graph_digest()` hashes `sorted(evidence.items())`. Put a timestamp in
there and **every run produces a new fingerprint even when nothing changed**,
which destroys Principle 8's guarantee: "a changed fingerprint means changed
evidence."

The fix is to be deliberate about it: the fingerprint hashes the **resolved
evidence view only** — `(field, value)` — never the observation log, never
timestamps, never provider identity. Provenance is for explanation; the
fingerprint is for reproducibility. They are different jobs and must not share a
digest.

### Trap 2 — provider-supplied confidence is a conclusion wearing a disguise

A provider emitting `confidence: 80` looks like metadata. It isn't — it is a
judgment about how much a claim should count, which is investigator knowledge,
which is the rule engine's. Ship that, and confidence tuning scatters across
every provider file and Principle 10 is dead within three providers.

Instead: **providers report `method`; the engine owns method weight**, as a data
table alongside the rules, reviewable and diffable in one place.

```
header:x-jenkins   strong     # the service identified itself
api:shodan         medium     # a third party observed it, at some past time
title-match        weak       # inferred from a page we rendered
```

This keeps every confidence number traceable to a reviewable table rather than
to a number some provider hard-coded, which is what Principle 4 requires.

### Trap 3 — observations grow without bound

Every re-run appends observations for every field of every entity, and
[`store.py`](../argus/store.py) persists graphs across runs. Ten runs against a
40-node target is a large multiple of what memory holds today, most of it
identical repeats.

Decide the retention rule when the model is built, not after the store is full:
keep the newest observation per `(field, value, provider, method)` and bump a
`seen_count` + `last_seen`, rather than appending a new record. Repetition is
worth counting, not worth storing N times.

---

## When to build this

**Not now.** With one provider, `evidence.update()` is correct and the model
above is speculative structure — the exact thing Argus's own principles reject.

The trigger is concrete: **the third provider, or the first real disagreement,
whichever comes first.** Two providers that never contradict each other still
don't justify it. Three do, because that is the point where "who said this?"
stops having an obvious answer.

What can be done cheaply *before* then, because it is not speculative:

1. **Make `technology` multi-valued.** It is already wrong as a single slot, and
   it is wrong independent of whether observations ever get built.
2. **Keep providers returning plain dicts.** The `list[Claim]` shape is the
   migration, not a thing to prepare for.

The order matters. Fix (1) when it bites; build the rest when the trigger fires.
