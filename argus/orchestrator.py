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

from .campaign import Experiment, Observation
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

    def register_worker(self, technique: str, fn) -> None:
        """Bind a technique to an ARGUS capability. NYX can add a worker; it cannot
        add a path that skips _authorize."""
        self.workers[technique] = fn

    # --- proposal + the gate ---------------------------------------------
    def propose(self, task: Task) -> Task:
        """Accept a proposed task and immediately run it through the gate. The task
        is queued, denied, or parked for approval — it never auto-executes here."""
        self.tasks[task.id] = task
        self.c.audit("task_proposed", task=task.id, technique=task.technique,
                     host=task.host, hypothesis=task.hypothesis)
        self._authorize(task)
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
            return t
        t.state, t.attempts = "RUNNING", t.attempts + 1
        try:
            obs_dict, classification = worker(t, self.c)
        except Exception as e:                  # noqa: BLE001 — a worker fault must not kill the loop
            t.state = "QUEUED" if t.attempts < self.max_attempts else "FAILED"
            self.c.audit("task_retry" if t.state == "QUEUED" else "task_failed",
                         task=t.id, error=str(e), attempt=t.attempts)
            return t
        if self.budget is not None:
            self.budget -= 1
        exp = self.c.save_experiment(Experiment(
            campaign_id=self.c.id, hypothesis=t.hypothesis, technique=t.technique, host=t.host,
            verdict=t.verdict, verdict_reason=t.verdict_reason, identity=t.identity,
            limits=t.limits, status="COMPLETED", classification=classification or ""))
        t.experiment_id = exp.id
        if obs_dict is not None:
            self.c.save_observation(Observation(experiment_id=exp.id, **obs_dict))
        t.state = "EVALUATED"
        self.c.audit("experiment_recorded", task=t.id, experiment=exp.id,
                     classification=classification or "")
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


_DEFAULT_WORKERS: dict[str, callable] = {
    "http_probe": _http_probe_worker,
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
