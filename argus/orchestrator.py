"""Orchestrator — the deterministic control loop. NYX proposes, ARGUS disposes.

The one rule this file exists to enforce: a task reaches a worker ONLY after
`policy.can_test` returned ALLOW or ALLOW_WITH_LIMITS. DENY parks it as DENIED;
HUMAN_APPROVAL parks it as APPROVAL_REQUIRED; a worker never sees either. That is
the whole safety contract — enforcement is deterministic code, not a model call.

The loop is in-process and synchronous, but the task table is DURABLE: every Task
is a JSON record under campaigns/<id>/tasks/, rewritten on each state transition, so
a restart (CLI exit, server restart, crash) recovers the exact queue rather than
losing it. A second Orchestrator on the same campaign adopts the same tasks. The
Task record is stateful by design; the audit log stays append-only and the
Experiment/Observation records stay immutable.

Restart recovery is deterministic: a task left RUNNING when the process died is
marked INTERRUPTED and RE-authorized — a high-risk action goes back to human review,
never a silent re-run. State transitions are validated against a closed table
(_TRANSITIONS); a DENIED task has no edge back to QUEUED, so no field rewrite can
walk a task around the gate.

NYX may register a worker for a technique and supply a task's priority inputs, but
there is no API that runs a task around can_test. AI proposes; ARGUS decides.

occam: flat JSON per task (same discipline as campaign.py), immediate bounded retry
(the throttle owns 429 backoff), no workflow engine. A cross-process scheduler or a
real indexing/concurrency need is the trigger to change this, not a guess.
"""
from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field

from . import providers
from .campaign import Experiment, Observation, _now
from .policy import Verdict

# Task lifecycle. Closed vocab: a typo can't invent a state that skips the gate.
TASK_STATES = (
    "CREATED", "POLICY_CHECKED", "DENIED", "APPROVAL_REQUIRED",
    "QUEUED", "RUNNING", "RETRY_SCHEDULED", "INTERRUPTED",
    "COMPLETED", "FAILED", "EVALUATED", "PAUSED", "CANCELLED",
)
_TERMINAL = frozenset({"DENIED", "FAILED", "EVALUATED", "CANCELLED"})

# Legal state transitions. The gate's safety contract lives here as DATA: a caller
# changing a field can NEVER walk a DENIED task back to QUEUED, because that edge
# does not exist. APPROVAL_REQUIRED reaches QUEUED only through approve(), which
# re-runs can_test first. Terminal states have no outgoing edges.
_TRANSITIONS: dict[str, set[str]] = {
    "CREATED": {"POLICY_CHECKED", "QUEUED", "DENIED", "APPROVAL_REQUIRED"},
    "POLICY_CHECKED": {"QUEUED", "DENIED", "APPROVAL_REQUIRED"},
    "QUEUED": {"RUNNING", "PAUSED", "CANCELLED", "FAILED"},
    "APPROVAL_REQUIRED": {"QUEUED", "DENIED", "CANCELLED"},
    "RUNNING": {"EVALUATED", "FAILED", "QUEUED", "RETRY_SCHEDULED", "INTERRUPTED"},
    "RETRY_SCHEDULED": {"QUEUED", "FAILED", "CANCELLED"},
    "INTERRUPTED": {"QUEUED", "APPROVAL_REQUIRED", "DENIED", "FAILED", "CANCELLED"},
    "PAUSED": {"QUEUED", "CANCELLED"},
    "COMPLETED": {"EVALUATED"},
    "DENIED": set(), "FAILED": set(), "EVALUATED": set(), "CANCELLED": set(),
}


def _assert_transition(frm: str, to: str) -> None:
    if to not in _TRANSITIONS.get(frm, set()):
        raise ValueError(f"illegal task transition {frm} -> {to}")


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
    max_attempts: int = 2
    experiment_id: str = ""
    # executing identity's NAME (durable). `account` is the live object re-resolved
    # from this on load; only the name survives a restart.
    account_name: str = ""
    created_at: str = field(default_factory=_now)
    queued_at: str = ""
    started_at: str = ""
    completed_at: str = ""
    updated_at: str = ""
    id: str = field(default_factory=lambda: f"task-{uuid.uuid4().hex[:12]}")

    @property
    def priority(self) -> float:
        return (self.impact * self.confidence * self.novelty) / max(self.cost, 0.01)

    def to_record(self) -> dict:
        """JSON-serializable form. The live `account` object is NOT persisted (it may
        carry a credential_ref); its name is, so the gate can be re-run on reload."""
        r = asdict(self)
        r.pop("account", None)
        r["account_name"] = self.account_name or getattr(self.account, "name", "")
        return r

    @classmethod
    def from_record(cls, rec: dict, campaign) -> "Task":
        """Rebuild a Task from disk, re-resolving `account` from its persisted name
        against the campaign's registered identities (None if it no longer exists —
        the gate then treats it as a non-researcher-owned account, fail-safe)."""
        rec = dict(rec)
        name = rec.get("account_name", "")
        rec.pop("account", None)
        t = cls(**{k: v for k, v in rec.items() if k in cls.__dataclass_fields__})
        if name and name != "anonymous":
            from . import identity as id_mod
            t.account = id_mod.get(campaign, name)
        return t


@dataclass
class Approval:
    """A first-class, auditable human decision on ONE parked high-risk task. One
    approval authorizes one bounded task — there is deliberately no 'approve
    everything' record. Persisted so a pending request survives a restart."""
    task_id: str
    campaign_id: str
    reason: str = ""                # why the task needs a human (the technique's risk)
    policy_reason: str = ""         # the verdict_reason that parked it
    requested_at: str = field(default_factory=_now)
    resolved_at: str = ""
    resolved_by: str = ""
    decision: str = ""              # APPROVE_ONCE | DENY | CANCEL ("" = still pending)
    note: str = ""
    id: str = field(default_factory=lambda: f"appr-{uuid.uuid4().hex[:12]}")


APPROVAL_DECISIONS = ("APPROVE_ONCE", "DENY", "CANCEL")


class Orchestrator:
    def __init__(self, campaign, budget_requests: int | None = None, max_attempts: int = 2):
        self.c = campaign
        self.tasks: dict[str, Task] = {}
        self.budget = budget_requests          # None = unbounded
        self.max_attempts = max_attempts
        self.workers: dict[str, callable] = dict(_DEFAULT_WORKERS)
        self._started_at = ""                  # set on first proposal
        self._last_completed = ""              # id of the last EVALUATED task
        self._ctx = None                       # campaign ExecutionContext, built once (see _exec_context)
        self._load()                           # durable: adopt this campaign's persisted queue

    def _exec_context(self):
        """This campaign's bound ExecutionContext, built ONCE and reused across every
        step. Caching it is what makes rate + request budget SHARED across all tasks this
        orchestrator runs (the program command's one-cap-for-the-whole-run); rebuilding
        it per step would hand each task a fresh budget. A new process (restart) starts a
        fresh context — budget is a per-run politeness cap, not a durable ledger."""
        if self._ctx is None:
            self._ctx = self.c.policy.execution_context(self.c.id)
        return self._ctx

    # --- durability: the task table lives on disk, not just in this process ---
    def _load(self) -> None:
        """Adopt the campaign's persisted tasks so a second Orchestrator (or a
        restart) sees the same queue, then recover anything caught mid-flight."""
        for rec in self.c.tasks():
            t = Task.from_record(rec, self.c)
            self.tasks[t.id] = t
            self._started_at = self._started_at or t.created_at
            if t.state == "EVALUATED":
                self._last_completed = t.id
        self._recover()

    def _recover(self) -> None:
        """Restart recovery. A task left RUNNING when the process died must NOT be
        assumed complete — mark it INTERRUPTED, audit, then RE-authorize through the
        same gate: a high-risk task lands back in APPROVAL_REQUIRED (human review,
        never a silent re-run of a possibly state-changing action), an in-scope read
        re-queues only if its retry budget remains, out-of-scope becomes DENIED."""
        for t in self.tasks.values():
            if t.state != "RUNNING":
                continue
            self.c.audit("recovered_interrupted", task=t.id, technique=t.technique,
                         host=t.host, attempts=t.attempts)
            self._set(t, "INTERRUPTED")
            d = self.c.policy.can_test(t.host, t.technique, t.intensity, t.account)
            t.verdict, t.verdict_reason, t.limits = d.verdict.value, d.reason, d.limits
            if d.verdict is Verdict.DENY:
                self._set(t, "DENIED")
            elif d.verdict is Verdict.HUMAN_APPROVAL:
                self._set(t, "APPROVAL_REQUIRED")
                self._request_approval(t)
            elif t.attempts >= t.max_attempts:
                self._set(t, "FAILED")       # exhausted its retries before the crash
            else:
                self._set(t, "QUEUED")

    def _set(self, task: Task, state: str) -> None:
        """The ONLY way a task changes state: validate the edge, stamp time, persist.
        An illegal edge raises before anything is written."""
        _assert_transition(task.state, state)
        task.state = state
        task.updated_at = _now()
        if state == "QUEUED" and not task.queued_at:
            task.queued_at = task.updated_at
        elif state == "RUNNING":
            task.started_at = task.updated_at
        elif state in _TERMINAL:
            task.completed_at = task.updated_at
        self.c.save_task(task.to_record())

    def _request_approval(self, task: Task) -> None:
        """Record a pending Approval for a parked task (idempotent — one open request
        per task)."""
        if any(a["task_id"] == task.id and not a["decision"] for a in self.c.approvals()):
            return
        self.c.save_approval(asdict(Approval(
            task_id=task.id, campaign_id=self.c.id,
            reason=f"{task.technique} requires explicit human authorization",
            policy_reason=task.verdict_reason)))

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
        completed, running = n("EVALUATED"), n("RUNNING")
        approval_required, denied = n("APPROVAL_REQUIRED"), n("DENIED")
        failed, cancelled = n("FAILED"), n("CANCELLED")
        retry_scheduled = n("RETRY_SCHEDULED") + n("INTERRUPTED")
        # QUEUED splits by dependency status: ready/waiting = queued; a dep that failed
        # or vanished = blocked (never silently counted as done).
        queued = sum(1 for t in tasks if t.state == "QUEUED" and self._dep_status(t) != "blocked")
        blocked = sum(1 for t in tasks if t.state == "QUEUED" and self._dep_status(t) == "blocked")
        cur = next((t for t in tasks if t.state == "RUNNING"), None)
        if running:
            state = "RUNNING"
        elif queued or retry_scheduled:
            state = "WAITING"
        elif approval_required or blocked:
            state = "BLOCKED"
        elif planned and (completed + denied + failed + cancelled) == planned:
            state = "COMPLETE"
        else:
            state = "IDLE"
        return {
            "campaign_id": self.c.id, "source": "orchestrator", "state": state,
            "planned": planned, "completed": completed, "running": running,
            "queued": queued, "blocked": blocked, "approval_required": approval_required,
            "denied": denied, "failed": failed, "cancelled": cancelled,
            "retry_scheduled": retry_scheduled, "queue_depth": queued,
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
        task.account_name = task.account_name or getattr(task.account, "name", "")
        task.max_attempts = self.max_attempts   # the orchestrator's cap governs this task
        self.tasks[task.id] = task
        self._started_at = self._started_at or task.created_at
        self.c.save_task(task.to_record())         # durable from the moment it exists
        self.c.audit("task_proposed", task=task.id, technique=task.technique,
                     host=task.host, hypothesis=task.hypothesis)
        self._authorize(task)
        self._snapshot()
        return task

    def _authorize(self, task: Task) -> None:
        d = self.c.policy.can_test(task.host, task.technique, task.intensity, task.account)
        task.verdict, task.verdict_reason, task.limits = d.verdict.value, d.reason, d.limits
        state = {Verdict.DENY: "DENIED",
                 Verdict.HUMAN_APPROVAL: "APPROVAL_REQUIRED"}.get(d.verdict, "QUEUED")
        self.c.audit("policy_decision", task=task.id, host=task.host, technique=task.technique,
                     verdict=d.verdict.value, reason=d.reason, limits=d.limits)
        self._set(task, state)
        if state == "APPROVAL_REQUIRED":
            self._request_approval(task)

    def approve(self, task_id: str, by: str, note: str = "") -> Task:
        """A human authorizes a parked high-risk task. The gate is re-checked: an
        approval sanctions the human-gated class, it can NEVER override a scope or
        forbidden-technique DENY. The decision is recorded as a durable Approval."""
        t = self.tasks[task_id]
        if t.state != "APPROVAL_REQUIRED":
            raise ValueError(f"task {task_id} is {t.state}, not awaiting approval")
        d = self.c.policy.can_test(t.host, t.technique, t.intensity, t.account)
        if d.verdict is Verdict.DENY:
            t.verdict, t.verdict_reason = "DENY", d.reason
            self._set(t, "DENIED")
            self._resolve_approval(task_id, "DENY", by, note=f"policy re-check denied: {d.reason}")
            self.c.audit("approval_overruled_by_policy", task=task_id, reason=d.reason, by=by)
            raise ValueError(f"policy denies {task_id} regardless of approval: {d.reason}")
        self._set(t, "QUEUED")
        self._resolve_approval(task_id, "APPROVE_ONCE", by, note=note)
        self.c.audit("human_approved", task=task_id, by=by)
        self._snapshot()
        return t

    def deny(self, task_id: str, by: str, note: str = "") -> Task:
        """A human declines a parked task — terminal DENIED, recorded as an Approval."""
        t = self.tasks[task_id]
        if t.state != "APPROVAL_REQUIRED":
            raise ValueError(f"task {task_id} is {t.state}, not awaiting approval")
        t.verdict, t.verdict_reason = "DENY", f"human denied by {by}"
        self._set(t, "DENIED")
        self._resolve_approval(task_id, "DENY", by, note=note)
        self.c.audit("human_denied", task=task_id, by=by)
        self._snapshot()
        return t

    def cancel(self, task_id: str, by: str, note: str = "") -> Task:
        """Operator abandons a not-yet-terminal task. Resolves any open approval as
        CANCEL. A task already terminal (DENIED/FAILED/EVALUATED) cannot be cancelled."""
        t = self.tasks[task_id]
        if t.state == "APPROVAL_REQUIRED":
            self._resolve_approval(task_id, "CANCEL", by, note=note)
        self._set(t, "CANCELLED")               # raises if t is already terminal
        self.c.audit("task_cancelled", task=task_id, by=by)
        self._snapshot()
        return t

    def _resolve_approval(self, task_id: str, decision: str, by: str, note: str = "") -> None:
        if decision not in APPROVAL_DECISIONS:
            raise ValueError(f"bad approval decision {decision!r}")
        for rec in self.c.approvals():
            if rec["task_id"] == task_id and not rec["decision"]:
                rec.update(decision=decision, resolved_by=by, resolved_at=_now(), note=note)
                self.c.save_approval(rec)
                return

    def pending_approvals(self) -> list[Task]:
        return [t for t in self.tasks.values() if t.state == "APPROVAL_REQUIRED"]

    # --- the loop ---------------------------------------------------------
    def _dep_status(self, task: Task) -> str:
        """Classify a task's dependencies: 'ready' (all EVALUATED), 'blocked' (a dep
        failed / was denied / cancelled / is missing — downstream must NOT run), or
        'waiting' (a dep is still in flight). A failed prerequisite never silently
        counts as satisfied; it blocks until the plan is revised."""
        status = "ready"
        for dep in task.deps:
            d = self.tasks.get(dep)
            if d is None or d.state in ("FAILED", "DENIED", "CANCELLED"):
                return "blocked"
            if d.state != "EVALUATED":
                status = "waiting"
        return status

    def _ready(self) -> list[Task]:
        q = [t for t in self.tasks.values()
             if t.state == "QUEUED" and self._dep_status(t) == "ready"]
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
            self._set(t, "FAILED")
            self.c.audit("no_worker", task=t.id, technique=t.technique)
            self._snapshot()
            return t
        t.attempts += 1
        self._set(t, "RUNNING")                 # persisted: a crash here is recoverable
        self._snapshot()                        # UI sees "currently executing" this task
        try:
            # Bind THIS campaign's engagement context for the span of the worker, so its
            # outbound requests (and its fan-out threads, via providers._CtxPool) use this
            # campaign's scope/rate/budget/headers — never another campaign's process state.
            with providers.bound_context(self._exec_context()):
                result = worker(t, self.c)
        except Exception as e:                  # noqa: BLE001 — a worker fault must not kill the loop
            retry = t.attempts < t.max_attempts
            self._set(t, "QUEUED" if retry else "FAILED")
            self.c.audit("task_retry" if retry else "task_failed",
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
        self._set(t, "EVALUATED")
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
    "differential_anonymous": _differential_worker,
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
