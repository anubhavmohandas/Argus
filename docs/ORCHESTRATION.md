# ARGUS orchestration — target state & backlog

The orchestrated, policy-enforced platform, built iteratively onto the existing
recon engine. This file is the spec lock and the gap ledger: what's built, what's
next, and what is deliberately NOT built.

## The boundary (non-negotiable)

**ARGUS = deterministic collection/execution infrastructure.** Owns: policies,
authorization gates, scope, identities, sessions, experiments, HTTP/browser
execution, differential execution, observations, evidence/provenance, state,
queues, retries, budgets, audit logs.

**NYX = reasoning/decision intelligence.** Owns: hypothesis generation, deciding
which boundary is interesting, prioritization *recommendations*, experiment-plan
*proposals*, interpreting observations, impact reasoning, finding critique.

**No LLM is in charge of hard enforcement.** NYX proposes a task; ARGUS's
`EngagementPolicy.can_test` independently decides ALLOW / ALLOW_WITH_LIMITS /
HUMAN_APPROVAL / DENY. The orchestrator may never run a task that didn't pass the
gate. Control flow:

```
NYX/Orchestrator proposes task
  → ARGUS policy.can_test evaluates (deterministic)
  → DENY / APPROVAL_REQUIRED / ALLOW_WITH_LIMITS / ALLOW
  → ARGUS executes bounded task (ALLOW* only)
  → raw observation/evidence recorded (immutable, provenance)
  → result returned to orchestrator
  → campaign state + audit updated
  → next task selected
  ↺
```

## Built

- **Slice 1 — authorization gate.** `policy.can_test(host, technique, intensity,
  account)` → `Decision(verdict, reason, limits)`. Enforces: fail-closed on
  undefined scope, scope exclusions, per-asset `action_for`, the (previously dead)
  `policy.forbidden` list, passive-only assets, deterministic high-risk →
  HUMAN_APPROVAL, rate/budget clamp. Provider backstop `providers._permitted`
  shares the host rows via `host_permitted`; `apply()` arms it; `reset_engagement`
  disarms atomically. `tests/test_can_test.py`.
- **Slice 2 — campaign persistence.** `campaign.py`: Campaign (dir + recompilable
  policy), Experiment (full provenance: why/verdict/identity/what-changed/
  classification), Observation (immutable request/response), append-only JSONL
  audit. JSON under `$ARGUS_HOME`, owner-only. `tests/test_campaign.py`.
- **Slice 3 — orchestrator loop.** `orchestrator.py`: Task state machine, the
  `propose → _authorize(can_test) → QUEUED|DENIED|APPROVAL_REQUIRED → step → record`
  loop, deterministic priority, dependency ordering, request budget, bounded retry,
  human-approval manager (re-checks the gate — approval can't override a DENY),
  worker registry. Invariant under test: a worker runs only for a gate-cleared task.
  `tests/test_orchestrator.py`.
- **Slice 4 — identity model.** `identity.py`: Identity (researcher_owned flag,
  role, tenant), credentials as an env-var *reference* validated at the boundary so
  a secret is never written to disk, per-campaign registration + audit. Feeds
  can_test's cross-account row. `tests/test_identity.py`.

## Backlog (priority order: scope→enforcement→state→provenance→usefulness)

1. **Differential runner** — baseline → one controlled mutation → compare, across
   authorized identities only. Each request a cross_account/state_change technique →
   can_test → the owned-victim/approval path. The highest-risk slice (active
   execution): gets its own careful pass. ARGUS-owned execution; NYX classifies.
2. **Endpoint/application mapping primitives** — routes/params/methods catalog.
3. **Finding-candidate lifecycle** — OBSERVED→REPRODUCIBLE→IN_SCOPE→
   BOUNDARY_CONFIRMED→IMPACT_CONFIRMED→DUPLICATE_CHECKED→REPORT_READY.
4. **Evidence collection + secret redaction** — reuse `providers.secrets_in`.
5. **Reproducibility check** — fresh session, re-run, score.
6. **Duplicate / root-cause grouping.**
7. **Report generation primitives + deterministic report-critic checklist** (the
   LLM critique is NYX; the rule checks are ARGUS).
8. **NYX interface** — the task-proposal / observation-interpretation seam.

## Deliberately NOT built (YAGNI for a single-operator CLI)

Temporal/Celery, Redis, PostgreSQL/Neo4j, Kafka event bus, S3, Docker worker
sandboxing, OpenTelemetry. The behavior each provides (durable state, queue,
graph, event reactions, retries, budgets) is built as plain Python on the existing
JSON store + in-process loop. Trigger to adopt any of them: a concrete need the
lazy version measurably can't meet (cross-process workers, a query that needs an
index), not the essay's wishlist. Record the trigger here when it arrives.
