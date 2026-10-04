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
  can_test's cross-account row. Now also `auth_headers()` — the resolved secret as a
  request header (bearer by default; `auth_header`/`auth_template` are the
  cookie/API-key calibration knob). `tests/test_identity.py`.
- **Slice 5 — differential runner.** `differential.py`: the baseline → one controlled
  mutation → compare → observe primitive. `Variant` (actor identity + method/path/
  body/resource + explicit `owner` of the targeted object); `run()` validates exactly
  ONE changed axis (no uncontrolled fuzzing), then gates **each** outbound request
  INDEPENDENTLY through `can_test` (not just the parent), executes via the throttled,
  SSRF-guarded, method-aware `providers._fetch`, `normalize`s both responses (volatile
  headers + uuid/timestamp/token body noise scrubbed), `compare`s them, and records a
  single Experiment (with `mutation` provenance + `baseline_obs`) plus both raw
  Observations. Deterministic first-pass classification only — suspicious (cross-
  account bypass: B reached A's object) / secure / inconclusive; never `vulnerable`
  (that needs the reproducibility slice). Auth secrets are `<redacted>` before any
  Observation hits disk. Wired as the default orchestrator worker for both
  `differential_*` techniques; the orchestrator adopts the runner's Experiment id
  rather than recording a duplicate. `tests/test_differential.py` (safety invariants
  first: a non-researcher-owned victim's object is never executed).

- **Slice 6 — finding-candidate lifecycle.** `finding.py`: a Finding promoted from a
  `suspicious`/`vulnerable` Experiment (idempotent — one candidate per experiment),
  walking a closed, forward-only pipeline OBSERVED → REPRODUCIBLE → IN_SCOPE →
  BOUNDARY_CONFIRMED → IMPACT_CONFIRMED → DUPLICATE_CHECKED → REPORT_READY (or
  DISMISSED, terminal). `reportable` is a deterministic policy check at promotion
  (scope + non_reportable class) — found ≠ reportable, so an out-of-scope/excluded
  candidate is still tracked but never reaches `report_ready()`. Every transition hits
  the finding history AND the campaign audit. JSON per finding under the campaign dir,
  same discipline as experiments/observations. Promotion is an explicit primitive, not
  auto-wired into `step()` — deciding a candidate is interesting stays NYX's call.
  `tests/test_finding.py`.

- **Slice 7 — reproducibility engine.** `reproduce.py`: `verify()` re-runs the exact
  controlled differential N trials (each a fresh policy-gated Experiment with its own
  Observations — reproduction adds evidence, never overwrites it), and judges
  stability strictly: reproduced ⇔ every trial agrees AND the class is `suspicious`. On
  reproduction, advances the linked finding OBSERVED → REPRODUCIBLE. A flaky target
  (split results) does NOT reproduce. Pure ARGUS — no NYX. `tests/test_reproduce.py`.
- **Slice 8 — report generation + critic.** `report.py`: `generate()` assembles a
  Report from a finding + its source experiment's Observations (baseline first), runs a
  fixed deterministic critic checklist (reportable? REPORT_READY? reproduced? baseline
  +mutation evidence present? titled?), and `render()`s submittable markdown.
  `submittable` ⇔ critic clean AND policy-reportable. A response body that leaked a
  secret is reported as IMPACT via `providers.secrets_in` (masked) and the raw body is
  WITHHELD — Argus proves the leak, never re-leaks it. The LLM prose critique is NYX's
  optional layer; this produces a submittable report with no NYX. `tests/test_report.py`.

ARGUS now runs end-to-end standalone: **campaign → differential → finding → reproduce
→ report**, deterministic throughout, no NYX required at any step.

- **Slice 9 — CLI surface.** `argus campaign {new|identity|diff|report|list}` drives the
  whole pipeline from the terminal (`cli._cmd_campaign`). Safe by default: a diff whose
  targeted object isn't researcher-owned, or whose host is out of scope, prints
  `not executed` and sends nothing. A suspicious diff promotes a finding; `--trials N`
  reproduces and advances it; `report` renders submittable markdown. A pasted secret as
  `--cred` is rejected at the boundary. `tests/test_cli_campaign.py`.

ARGUS is a usable standalone product: `argus campaign new → identity → diff → report`.

## Backlog (priority order)

1. **Endpoint/application mapping primitives** — routes/params/methods catalog
   (feeds differential `path`/`method` instead of hand-written specs).
2. **Duplicate / root-cause grouping** — cluster findings before DUPLICATE_CHECKED.
3. **Operator UI** — the SOC-workstation surface over the above APIs (next track).

### NYX (optional add-on — ARGUS must never depend on it)

**NYX interface** is a seam, not a dependency: a `suspicious` experiment is already a
tracked candidate and a reproduced one already advances, all deterministically. NYX, if
present, only *proposes* which boundary to test next and *interprets* observations into
richer prose — it never gates, promotes, or reports on its own, and ARGUS is fully
functional with NYX absent. Build this last.

## Deliberately NOT built (YAGNI for a single-operator CLI)

Temporal/Celery, Redis, PostgreSQL/Neo4j, Kafka event bus, S3, Docker worker
sandboxing, OpenTelemetry. The behavior each provides (durable state, queue,
graph, event reactions, retries, budgets) is built as plain Python on the existing
JSON store + in-process loop. Trigger to adopt any of them: a concrete need the
lazy version measurably can't meet (cross-process workers, a query that needs an
index), not the essay's wishlist. Record the trigger here when it arrives.
