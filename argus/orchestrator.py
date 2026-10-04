"""Orchestrator — the deterministic control loop. NYX proposes, ARGUS disposes.

The one rule this file exists to enforce: a task reaches a worker ONLY after
`policy.can_test` returned ALLOW or ALLOW_WITH_LIMITS. DENY parks it as DENIED;
HUMAN_APPROVAL parks it as APPROVAL_REQUIRED; a worker never sees either. That is
the whole safety contract — enforcement is deterministic code, not a model call.

The loop is in-process and synchronous. Durability is the campaign's append-only
audit + its Experiment/Observation records, not a workflow engine (see
docs/ORCHESTRATION.md for why not Temporal/Celery). A Task lives in memory; its
*outcome* (verdict, experiment, observation) is what persists.

NYX may register a worker for a technique and supply a task's priority inputs, but
there is no API that runs a task around can_test. AI proposes; ARGUS decides.

occam: list as queue, dict as task table, immediate bounded retry (the throttle
owns 429 backoff). A cross-process queue is the trigger to change this, not a guess.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from . import providers
from .campaign import Experiment, Observation, _now
from .policy import Verdict

# Task lifecycle. Closed vocab: a typo can't invent a state that skips the gate.
TASK_STATES = (
    "CREATED", "POLICY_CHECKED", "DENIED", "APPROVAL_REQUIRED",
    "QUEUED", "RUNNING", "COMPLETED", "FAILED", "EVALUATED",
)


@dataclass
class Task:
    """A proposed bounded action. Priority inputs default to deterministic values so
    a task NYX never scored still has a stable order. `account` is the executing
    identity (for can_test's cross-account row); it is in-memory only, never saved."""
    campaign_id: str
    technique: str
    host: str
    hypothesis: str = ""
    identity: str = ""
    intensity: float = 1.0
    account: object = None
    # technique-specific parameters a generic Task can't model — e.g. a differential's
    # {baseline, mutation} variant specs. In-memory only; the Experiment is what persists.
    spec: dict | None = None
    deps: list[str] = field(default_factory=list)
    # priority = impact · confidence · novelty / cost (spec formula; scope_certainty
    # is folded into can_test — an out-of-scope task never reaches the queue).
    impact: float = 1.0
    confidence: float = 0.5
    novelty: float = 1.0
    cost: float = 1.0
    state: str = "CREATED"
    verdict: str = ""
    verdict_reason: str = ""
    limits: dict | None = None
    attempts: int = 0
    experiment_id: str = ""
    id: str = field(default_factory=lambda: f"task-{uuid.uuid4().hex[:12]}")

    @property
    def priority(self) -> float:
        return (self.impact * self.confidence * self.novelty) / max(self.cost, 0.01)


class Orchestrator:
    def __init__(self, campaign, budget_requests: int | None = None, max_attempts: int = 2):
        self.c = campaign
        self.tasks: dict[str, Task] = {}
        self.budget = budget_requests          # None = unbounded
        self.max_attempts = max_attempts
        self.workers: dict[str, callable] = dict(_DEFAULT_WORKERS)
        self._started_at = ""                  # set on first proposal
        self._last_completed = ""              # id of the last EVALUATED task

    # --- progress: a snapshot derived from the task table (no new store) ---
    def progress(self) -> dict:
        """Current work-unit snapshot, computed from the in-memory task table. This is the
        model the operator UI's live progress bar consumes: `percentage` is verified work
        (completed/planned) and never time-based, `state` drives the heartbeat animation.
        occam: derived on read from `self.tasks`, the one table the loop already maintains —
        no parallel counters to drift out of sync."""
        tasks = list(self.tasks.values())
        n = lambda s: sum(1 for t in tasks if t.state == s)
        planned = len(tasks)
        completed, running, queued = n("EVALUATED"), n("RUNNING"), n("QUEUED")
        blocked, denied, failed = n("APPROVAL_REQUIRED"), n("DENIED"), n("FAILED")
        cur = next((t for t in tasks if t.state == "RUNNING"), None)
        if running:
            state = "RUNNING"
        elif queued:
            state = "WAITING"
        elif blocked:
            state = "BLOCKED"
        elif planned and (completed + denied + failed) == planned:
            state = "COMPLETE"
        else:
            state = "IDLE"
        return {
            "campaign_id": self.c.id, "source": "orchestrator", "state": state,
            "planned": planned, "completed": completed, "running": running,
            "queued": queued, "blocked": blocked, "denied": denied, "failed": failed,
            "queue_depth": queued,
            "percentage": round(100 * completed / planned) if planned else 0,
            "current_task": cur.id if cur else "",
            "current_technique": cur.technique if cur else "",
            "last_completed": self._last_completed,
            "started_at": self._started_at, "updated_at": _now(),
        }

    def _snapshot(self) -> None:
        self.c.save_progress(self.progress())

    def register_worker(self, technique: str, fn) -> None:
        """Bind a technique to an ARGUS capability. NYX can add a worker; it cannot
        add a path that skips _authorize."""
        self.workers[technique] = fn

    # --- proposal + the gate ---------------------------------------------
    def propose(self, task: Task) -> Task:
        """Accept a proposed task and immediately run it through the gate. The task
        is queued, denied, or parked for approval — it never auto-executes here."""
        self.tasks[task.id] = task
        self._started_at = self._started_at or _now()
        self.c.audit("task_proposed", task=task.id, technique=task.technique,
                     host=task.host, hypothesis=task.hypothesis)
        self._authorize(task)
        self._snapshot()
        return task

    def _authorize(self, task: Task) -> None:
        d = self.c.policy.can_test(task.host, task.technique, task.intensity, task.account)
        task.verdict, task.verdict_reason, task.limits = d.verdict.value, d.reason, d.limits
        task.state = {Verdict.DENY: "DENIED",
                      Verdict.HUMAN_APPROVAL: "APPROVAL_REQUIRED"}.get(d.verdict, "QUEUED")
        self.c.audit("policy_decision", task=task.id, host=task.host, technique=task.technique,
                     verdict=d.verdict.value, reason=d.reason, limits=d.limits)

    def approve(self, task_id: str, by: str) -> Task:
        """A human authorizes a parked high-risk task. The gate is re-checked: an
        approval sanctions the human-gated class, it can NEVER override a scope or
        forbidden-technique DENY."""
        t = self.tasks[task_id]
        if t.state != "APPROVAL_REQUIRED":
            raise ValueError(f"task {task_id} is {t.state}, not awaiting approval")
        d = self.c.policy.can_test(t.host, t.technique, t.intensity, t.account)
        if d.verdict is Verdict.DENY:
            t.state, t.verdict, t.verdict_reason = "DENIED", "DENY", d.reason
            self.c.audit("approval_overruled_by_policy", task=task_id, reason=d.reason, by=by)
            raise ValueError(f"policy denies {task_id} regardless of approval: {d.reason}")
        t.state = "QUEUED"
        self.c.audit("human_approved", task=task_id, by=by)
        self._snapshot()
        return t

    def pending_approvals(self) -> list[Task]:
        return [t for t in self.tasks.values() if t.state == "APPROVAL_REQUIRED"]

    # --- the loop ---------------------------------------------------------
    def _ready(self) -> list[Task]:
        done = {tid for tid, t in self.tasks.items() if t.state == "EVALUATED"}
        q = [t for t in self.tasks.values() if t.state == "QUEUED" and set(t.deps) <= done]
        return sorted(q, key=lambda t: t.priority, reverse=True)

    def step(self) -> Task | None:
        """Run the one highest-priority ready task. Returns it, or None when nothing
        is runnable (queue empty, deps unmet, or budget exhausted)."""
        ready = self._ready()
        if not ready:
            return None
        t = ready[0]
        if self.budget is not None and self.budget <= 0:
            self.c.audit("budget_exhausted", task=t.id)
            return None
        # INVARIANT: only QUEUED tasks reach here, and a task is QUEUED only via an
        # ALLOW/ALLOW_WITH_LIMITS verdict (or a human approval that re-passed the gate).
        worker = self.workers.get(t.technique)
        if worker is None:
            t.state = "FAILED"
            self.c.audit("no_worker", task=t.id, technique=t.technique)
            self._snapshot()
            return t
        t.state, t.attempts = "RUNNING", t.attempts + 1
        self._snapshot()                        # UI sees "currently executing" this task
        try:
            # Bind THIS campaign's engagement context for the span of the worker, so its
            # outbound requests (and its fan-out threads, via providers._CtxPool) use this
            # campaign's scope/rate/budget/headers — never another campaign's process state.
            with providers.bound_context(self.c.policy.execution_context(self.c.id)):
                result = worker(t, self.c)
        except Exception as e:                  # noqa: BLE001 — a worker fault must not kill the loop
            t.state = "QUEUED" if t.attempts < self.max_attempts else "FAILED"
            self.c.audit("task_retry" if t.state == "QUEUED" else "task_failed",
                         task=t.id, error=str(e), attempt=t.attempts)
            self._snapshot()
            return t
        if self.budget is not None:
            self.budget -= 1
        # A worker may return (obs_dict, classification) for the generic path, or
        # (obs_dict, classification, experiment_id) when it already recorded a richer
        # Experiment itself (the differential runner) — adopt that id, don't duplicate.
        obs_dict, classification = result[0], result[1]
        adopted_id = result[2] if len(result) > 2 else None
        if adopted_id:
            t.experiment_id = adopted_id
        else:
            exp = self.c.save_experiment(Experiment(
                campaign_id=self.c.id, hypothesis=t.hypothesis, technique=t.technique, host=t.host,
                verdict=t.verdict, verdict_reason=t.verdict_reason, identity=t.identity,
                limits=t.limits, status="COMPLETED", classification=classification or ""))
            t.experiment_id = exp.id
            if obs_dict is not None:
                self.c.save_observation(Observation(experiment_id=exp.id, **obs_dict))
        t.state = "EVALUATED"
        self._last_completed = t.id
        self.c.audit("experiment_recorded", task=t.id, experiment=t.experiment_id,
                     classification=classification or "")
        self._snapshot()
        return t

    def run(self, max_steps: int = 1000) -> int:
        """Drain the ready queue; returns how many tasks were executed. Stops when
        nothing is runnable — parked (DENIED/APPROVAL_REQUIRED) tasks are left as-is."""
        n = 0
        while n < max_steps and self.step() is not None:
            n += 1
        return n


# --- default ARGUS workers ------------------------------------------------
# A worker is `(task, campaign) -> (observation_dict | None, classification)`. It
# executes a bounded capability and returns the RAW observation; it does NOT
# classify (that's NYX) — the default returns "" for classification.
def _http_probe_worker(task: Task, campaign):
    from . import providers
    ev, observed = providers.probe(task.host)   # scope-gated at the provider backstop too
    response = dict(observed or {})
    if ev:
        response["_evidence"] = ev              # facts observed, not conclusions
    obs = {"request": {"method": "GET", "url": f"https://{task.host}/", "headers": {}, "body": ""},
           "response": response}
    return obs, ""


def _variant_from_spec(campaign, spec: dict):
    """Build a differential Variant from a task spec's identity NAMES, resolving each to
    a registered Identity. An unknown identity name is a hard error — the runner must
    never fabricate an account, since ownership drives the cross-account safety gate."""
    from . import differential, identity as id_mod
    ANON = id_mod.ANONYMOUS

    def ident(name: str):
        if not name or name == "anonymous":
            return ANON
        got = id_mod.get(campaign, name)
        if got is None:
            raise ValueError(f"unknown identity {name!r} — register it before a differential")
        return got

    owner = spec.get("owner")
    return differential.Variant(
        identity=ident(spec["identity"]),
        method=spec.get("method", "GET"), path=spec.get("path", "/"),
        body=spec.get("body", ""), resource=spec.get("resource", ""),
        owner=ident(owner) if owner else None)


def _differential_worker(task: Task, campaign):
    """ARGUS differential primitive, driven by a gated Task. The orchestrator already
    cleared the parent task; the runner independently re-gates EACH outbound request via
    can_test. Returns (None, classification, experiment_id) — the runner owns the richer
    Experiment + its two Observations, so the orchestrator adopts the id rather than
    recording a duplicate."""
    from . import differential
    spec = task.spec or {}
    base = _variant_from_spec(campaign, spec["baseline"])
    mut = _variant_from_spec(campaign, spec["mutation"])
    r = differential.run(campaign, task.technique, task.host, base, mut,
                         hypothesis=task.hypothesis, intensity=task.intensity)
    return None, r.classification, r.experiment_id


_DEFAULT_WORKERS: dict[str, callable] = {
    "http_probe": _http_probe_worker,
    "differential_same_account": _differential_worker,
    "differential_cross_account": _differential_worker,
}


def demo() -> None:
    """Self-check: the loop executes an ALLOWed task, parks a high-risk one for
    approval, denies an out-of-scope one, and a worker NEVER runs on a non-QUEUED
    task. Offline — uses a stub worker and a temp ARGUS_HOME."""
    import os
    import tempfile
    from . import campaign as campaign_mod
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["ARGUS_HOME"] = tmp
        c = campaign_mod.create("Assets:\n*.acme.example\nRate: 2 requests/sec\n", name="Acme")
        orch = Orchestrator(c)

        ran = []
        orch.register_worker("http_probe", lambda t, cc: (ran.append(t.host) or (
            {"request": {"method": "GET", "url": f"https://{t.host}/", "headers": {}, "body": ""},
             "response": {"status": 200}}, "")))

        allowed = orch.propose(Task(campaign_id=c.id, technique="http_probe",
                                    host="api.acme.example", hypothesis="internet-facing?"))
        denied = orch.propose(Task(campaign_id=c.id, technique="http_probe",
                                   host="evil.other.example", hypothesis="oob"))
        risky = orch.propose(Task(campaign_id=c.id, technique="state_change",
                                  host="api.acme.example", hypothesis="can we write?"))
        assert allowed.state == "QUEUED"
        assert denied.state == "DENIED" and "out of scope" in denied.verdict_reason
        assert risky.state == "APPROVAL_REQUIRED"

        orch.run()
        assert ran == ["api.acme.example"], ran        # ONLY the allowed task executed
        assert allowed.state == "EVALUATED"
        assert risky.state == "APPROVAL_REQUIRED"      # untouched: no approval given
        assert denied.state == "DENIED"

        # a human approves the risky one; the gate re-passes (in scope, not forbidden)
        orch.approve(risky.id, by="researcher")
        assert risky.state == "QUEUED"
        orch.register_worker("state_change", lambda t, cc: (None, "inconclusive"))
        orch.run()
        assert risky.state == "EVALUATED"

        # provenance + audit landed
        exps = c.experiments()
        assert any(e["technique"] == "http_probe" and e["verdict"] == "ALLOW" for e in exps)
        events = [a["event"] for a in c.audit_trail()]
        assert "policy_decision" in events and "human_approved" in events
        assert "experiment_recorded" in events
    del os.environ["ARGUS_HOME"]
    print("orchestrator demo passed")


if __name__ == "__main__":
    demo()
