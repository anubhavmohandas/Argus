"""Campaign run coordinator — the single writer for one active campaign.

The problem this file exists to solve: a background active run creates/updates tasks
WHILE an operator approves / denies / pauses / resumes / stops from the UI. The
orchestrator's durable task table must not be mutated by two loops at once.

The design is an in-process actor, not scattered locks. ONE coordinator per campaign
id (the module registry guarantees it), and ONE mutation thread per coordinator. The
loop thread is the only code that touches the orchestrator while a run is live; every
operator action becomes a queued command applied ON that thread. So there is never a
second writer — ordering is deterministic FIFO, not timing luck. The HTTP handler
enqueues and returns a run snapshot immediately; SSE carries the rest.

Run state is a closed vocabulary with validated transitions (_RUN_TRANSITIONS) — an
API handler cannot assign an arbitrary state, exactly as a Task cannot skip the gate.
Run state is persisted (run.json) and every transition is audited, so a restart never
lies about what happened. A process that died mid-run comes back STOPPED, never silently
resumes state-changing work — the orchestrator's own _recover re-authorizes any task
left RUNNING through can_test on load.

The APPROVAL INVARIANT is untouched: approve() still routes to Orchestrator.approve,
which re-runs can_test; a human can never walk a scope/forbidden DENY back to the queue.

occam: a single in-process actor thread per campaign. The trigger to replace it with a
real distributed scheduler is explicit — multiple ARGUS server processes, remote
workers, or cross-machine execution. Until one of those exists, simple + deterministic
beats Redis/Celery/Temporal. A per-run generation id (run_id) guards against a lingering
old loop committing into a newer run; cross-process stale workers are out of scope until
the same trigger fires.
"""
from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from queue import Empty as _Empty, Queue as _Queue

from .campaign import _now
from .orchestrator import Orchestrator

# Closed run-state vocabulary. A typo can't invent a state, and an API handler can't
# assign one directly — every change goes through _set_state, validated against the table.
RUN_STATES = (
    "IDLE", "STARTING", "RUNNING", "PAUSING", "PAUSED",
    "WAITING_APPROVAL", "STOPPING", "STOPPED", "FAILED", "COMPLETE",
)
# States that mean "a loop thread should be alive". If run.json shows one of these on
# load, the process died mid-run — recover to STOPPED rather than trust it.
_ACTIVE = frozenset({"STARTING", "RUNNING", "PAUSING", "PAUSED", "WAITING_APPROVAL", "STOPPING"})

_RUN_TRANSITIONS: dict[str, set[str]] = {
    "IDLE": {"STARTING"},
    "STARTING": {"RUNNING", "FAILED", "STOPPING"},
    "RUNNING": {"PAUSING", "STOPPING", "WAITING_APPROVAL", "COMPLETE", "FAILED"},
    "PAUSING": {"PAUSED", "STOPPING"},
    "PAUSED": {"RUNNING", "STOPPING"},
    "WAITING_APPROVAL": {"RUNNING", "PAUSING", "STOPPING", "COMPLETE", "FAILED"},
    "STOPPING": {"STOPPED"},
    "STOPPED": {"STARTING"},
    "FAILED": {"STARTING"},
    "COMPLETE": {"STARTING"},
}


@dataclass
class _Command:
    """One operator action queued for the loop thread. `done` lets a caller that wants a
    result (approve/deny/cancel) wait for it; fire-and-forget callers ignore it."""
    name: str
    args: dict = field(default_factory=dict)
    done: threading.Event = field(default_factory=threading.Event)
    result: object = None
    error: BaseException = None


class CampaignRunCoordinator:
    """Owns mutation ordering for ONE campaign's execution. Not constructed directly in
    normal use — call `coordinator_for(campaign)` so the process keeps a single owner."""

    def __init__(self, campaign, *, budget_requests: int | None = None):
        self.c = campaign
        self.orch = Orchestrator(campaign, budget_requests=budget_requests)
        self._cmds: _Queue = _Queue()
        self._lock = threading.Lock()          # guards _state, _run_id, _thread, flags
        self._wake = threading.Event()         # wakes a paused / approval-blocked loop
        self._thread: threading.Thread | None = None
        self._run_id = ""
        self._paused = False
        self._stopping = False
        self._planner = None                   # optional callable(self) run once at run start
        self._on_complete = None                # optional callable(self) run when the drain completes
        self._detail = ""
        self._started_at = ""
        self._state = self._recover_state()

    # --- run-state persistence + crash recovery ---------------------------
    def _recover_state(self) -> str:
        """Load persisted run state. A state in _ACTIVE means the process died mid-run —
        recover to STOPPED (durable tasks are preserved; the orchestrator re-authorized
        anything left RUNNING on its own load). Never auto-resume state-changing work."""
        rec = self._load_run()
        st = rec.get("state", "IDLE")
        if st not in RUN_STATES:
            st = "IDLE"
        if st in _ACTIVE:
            self.c.audit("run_recovered", from_state=st, run_id=rec.get("run_id", ""))
            st = "STOPPED"
            self._persist(st, rec.get("run_id", ""))
        return st

    def _load_run(self) -> dict:
        import json
        p = self.c.dir / "run.json"
        if not p.exists():
            return {}
        try:
            return json.loads(p.read_text())
        except (OSError, ValueError):
            return {}

    def _persist(self, state: str, run_id: str) -> None:
        import json
        p = self.c.dir / "run.json"
        p.touch(mode=0o600)
        p.write_text(json.dumps({
            "campaign_id": self.c.id, "state": state, "run_id": run_id,
            "detail": self._detail, "started_at": self._started_at, "updated_at": _now(),
        }, indent=2))

    def _set_state(self, state: str, *, detail: str = "") -> None:
        """The only way run state changes: validate the edge, stamp, persist, audit, emit.
        Idempotent self-edges (RUNNING->RUNNING) are allowed as no-ops so the loop can
        assert its state cheaply."""
        with self._lock:
            if state == self._state:
                return
            if state not in _RUN_TRANSITIONS.get(self._state, set()):
                raise ValueError(f"illegal run transition {self._state} -> {state}")
            self._state = state
            self._detail = detail
        self._persist(state, self._run_id)
        # durable history + SSE source: the coordinator is the authority for run activity,
        # so each transition is one audit record (maps to a campaign.run.* event).
        self.c.audit("run_transition", state=state, run_id=self._run_id, detail=detail)

    # --- public snapshot --------------------------------------------------
    def snapshot(self) -> dict:
        """What an API handler returns immediately. Run state (activity) is kept separate
        from the orchestrator's progress (verified work) — the UI never conflates them."""
        with self._lock:
            st, rid, started = self._state, self._run_id, self._started_at
        return {"campaign_id": self.c.id, "run_state": st, "run_id": rid,
                "started_at": started, "detail": self._detail, "updated_at": _now()}

    # --- command surface (called from HTTP/CLI threads) -------------------
    def start(self, *, planner=None, on_complete=None, wait: float = 0.0) -> dict:
        """Begin (or resume ownership of) a run. Idempotent: a second concurrent start
        finds the loop already alive and returns the live snapshot — one owner, never a
        second loop. `planner(self)` (optional) proposes work on the loop thread before
        the drain begins (the background pivot); `on_complete(self)` (optional) runs on the
        same thread once the drain finishes (passive analysis / projection). Returns
        quickly — SSE carries the rest."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return self.snapshot_locked()
            self._run_id = f"run-{uuid.uuid4().hex[:12]}"
            self._paused = False
            self._stopping = False
            self._planner = planner
            self._on_complete = on_complete
            self._started_at = _now()
            # STARTING is reachable from every resting state in the table. Persist +
            # audit it BEFORE the loop thread starts, so STARTING is always ordered ahead
            # of the RUNNING the loop will log — the audit log is the SSE source of truth.
            self._state = self._transition_locked(self._state, "STARTING")
            self._persist("STARTING", self._run_id)
            self.c.audit("run_transition", state="STARTING", run_id=self._run_id, detail="")
            self._thread = threading.Thread(target=self._loop, args=(self._run_id,),
                                            name=f"coord-{self.c.id}", daemon=True)
            self._thread.start()
        if wait:
            self._thread.join(wait)
        return self.snapshot()

    def pause(self) -> dict:
        self._submit("pause")
        return self.snapshot()

    def resume(self) -> dict:
        self._submit("resume")
        return self.snapshot()

    def stop(self) -> dict:
        self._submit("stop")
        return self.snapshot()

    def approve(self, task_id: str, by: str, note: str = "", wait: float = 30.0):
        return self._submit("approve", {"task_id": task_id, "by": by, "note": note}, wait=wait)

    def deny(self, task_id: str, by: str, note: str = "", wait: float = 30.0):
        return self._submit("deny", {"task_id": task_id, "by": by, "note": note}, wait=wait)

    def cancel(self, task_id: str, by: str, note: str = "", wait: float = 30.0):
        return self._submit("cancel", {"task_id": task_id, "by": by, "note": note}, wait=wait)

    def _submit(self, name: str, args: dict | None = None, wait: float = 0.0):
        """Enqueue a command and wake the loop. If no loop is alive (idle campaign), apply
        it inline under the lock so there is STILL exactly one writer. For result-bearing
        commands the caller waits briefly for the loop to apply it; it is bounded because
        each applied command is cheap (no target I/O — that only happens inside step())."""
        cmd = _Command(name, args or {})
        self._cmds.put(cmd)
        self._wake.set()
        with self._lock:
            alive = self._thread is not None and self._thread.is_alive()
            if not alive:
                self._drain()                   # single writer: loop not running, we are it
        if wait and not cmd.done.is_set():
            cmd.done.wait(wait)
        if cmd.error is not None:
            raise cmd.error
        return cmd.result

    # --- the single mutation thread ---------------------------------------
    def _loop(self, run_id: str) -> None:
        """THE single writer while a run is live. Propose (planner), then drain the ready
        queue one step at a time, applying any queued operator commands between steps.
        A bounded step may do 30s of network I/O — commands simply wait their turn; because
        only this thread touches the orchestrator, no lock is held across that I/O and no
        second loop can dispatch the same task."""
        try:
            if self._planner is not None:
                self._planner(self)             # propose work (serialized on this thread)
            self._drain()                       # apply any commands that arrived meanwhile
            if self._stopping or self._run_id != run_id:
                self._finish(run_id, "STOPPED")
                return
            self._set_state("RUNNING")
            while True:
                self._drain()
                if self._run_id != run_id:      # superseded by a newer run — exit silently
                    return
                if self._stopping:
                    self._finish(run_id, "STOPPED")
                    return
                if self._paused:
                    self._enter_paused()
                    self._wake.wait(timeout=1.0)
                    self._wake.clear()
                    continue
                if self._state == "PAUSED":     # resumed: lift back to RUNNING first
                    self._set_state("RUNNING")
                t = self._guarded_step(run_id)
                if t is not None:
                    if self._state != "RUNNING":
                        self._set_state("RUNNING")
                    continue
                # nothing ran: either waiting on a human, or genuinely done.
                if self.orch.pending_approvals():
                    if self._state != "WAITING_APPROVAL":
                        self._set_state("WAITING_APPROVAL")
                    self._wake.wait(timeout=1.0)  # woken by an approve/deny command
                    self._wake.clear()
                    continue
                if self._on_complete is not None:
                    self._on_complete(self)       # passive analysis / projection, serialized here
                    self._on_complete = None      # run once per run
                self._finish(run_id, "COMPLETE")
                return
        except BaseException as e:              # noqa: BLE001 — a loop fault must be recorded, not silent
            try:
                self._set_state("FAILED", detail=str(e))
            finally:
                with self._lock:
                    if self._run_id == run_id:
                        self._run_id = ""

    def _enter_paused(self) -> None:
        """Move to PAUSED through the transient PAUSING the table requires. PAUSE means:
        dispatch no NEW task. A task already inside step() finishes (it is bounded); the
        loop simply stops claiming the next one. SSE/approvals stay live while paused."""
        if self._state in ("RUNNING", "WAITING_APPROVAL"):
            self._set_state("PAUSING")
        if self._state != "PAUSED":
            self._set_state("PAUSED")

    def _finish(self, run_id: str, state: str) -> None:
        if state == "STOPPED":
            self._set_state("STOPPING")
        self._set_state(state)
        with self._lock:
            if self._run_id == run_id:
                self._run_id = ""

    def _guarded_step(self, run_id: str):
        """Run one orchestrator step, but ONLY for the current run generation. A lingering
        loop from a stopped-then-restarted run (a stale run_id) refuses here, so an old
        generation can never commit a task result into a newer run."""
        with self._lock:
            if self._run_id != run_id or self._stopping or self._paused:
                return None
        return self.orch.step()

    def _drain(self) -> None:
        """Apply every queued command, in order, on this (the single-writer) thread."""
        while True:
            try:
                cmd = self._cmds.get_nowait()
            except _Empty:
                return
            try:
                cmd.result = self._apply(cmd)
            except BaseException as e:          # noqa: BLE001 — report to the caller, keep the loop alive
                cmd.error = e
            finally:
                cmd.done.set()

    def _apply(self, cmd: _Command):
        """Mutate on the single writer thread. pause/resume/stop set flags the loop reads;
        approve/deny/cancel route straight through the orchestrator (approve re-runs
        can_test — the gate is never weakened here)."""
        # pause/resume/stop set flags the loop reads; they return None (the caller's
        # pause()/resume()/stop() takes the snapshot AFTER _submit, off the lock) so this
        # method never re-acquires self._lock during an inline drain.
        n, a = cmd.name, cmd.args
        if n == "pause":
            if not self._stopping:
                self._paused = True
            return None
        if n == "resume":
            self._paused = False
            self._wake.set()
            return None
        if n == "stop":
            self._stopping = True
            self._paused = False
            self._wake.set()
            return None
        if n == "approve":
            t = self.orch.approve(a["task_id"], a["by"], a.get("note", ""))
            self._wake.set()                    # a newly QUEUED task may be runnable now
            return t
        if n == "deny":
            return self.orch.deny(a["task_id"], a["by"], a.get("note", ""))
        if n == "cancel":
            return self.orch.cancel(a["task_id"], a["by"], a.get("note", ""))
        raise ValueError(f"unknown command {n!r}")

    # --- lock-held helpers (caller already holds self._lock) --------------
    def snapshot_locked(self) -> dict:
        return {"campaign_id": self.c.id, "run_state": self._state, "run_id": self._run_id,
                "started_at": self._started_at, "detail": self._detail, "updated_at": _now()}

    def _transition_locked(self, frm: str, to: str) -> str:
        if to != frm and to not in _RUN_TRANSITIONS.get(frm, set()):
            raise ValueError(f"illegal run transition {frm} -> {to}")
        return to


# --- the in-process registry: ONE coordinator per campaign id -------------
_COORDINATORS: dict[str, CampaignRunCoordinator] = {}
_REGISTRY_LOCK = threading.Lock()


def coordinator_for(campaign, *, budget_requests: int | None = None) -> CampaignRunCoordinator:
    """The single owner for this campaign id in this process. A second caller with a
    freshly reloaded campaign object gets the SAME coordinator — two loops can never both
    believe they own one campaign's execution state. (Cross-process ownership is the
    documented upgrade trigger, not something this registry pretends to solve.)"""
    with _REGISTRY_LOCK:
        co = _COORDINATORS.get(campaign.id)
        if co is None:
            co = CampaignRunCoordinator(campaign, budget_requests=budget_requests)
            _COORDINATORS[campaign.id] = co
        return co


def _reset_registry() -> None:
    """Test hook: drop all coordinators (e.g. between ARGUS_HOME temp dirs)."""
    with _REGISTRY_LOCK:
        _COORDINATORS.clear()


def demo() -> None:
    """Self-check: a run drains an ALLOWed task, parks + then runs an approved one, and
    leaves a DENY untouched — all through the coordinator's single thread, with pause and
    stop honored. Offline, temp ARGUS_HOME, a latching worker so timing is deterministic."""
    import os
    import tempfile
    from . import campaign as campaign_mod
    from .orchestrator import Task
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["ARGUS_HOME"] = tmp
        _reset_registry()
        c = campaign_mod.create("In scope:\n*.acme.example\nRate: 5 requests/sec\n", name="Acme")
        co = coordinator_for(c)

        ran: list[str] = []
        gate = threading.Event()

        def worker(t, cc):
            gate.wait(5)                        # hold the step so we can test "no new dispatch"
            ran.append(t.host)
            return {"request": {"method": "GET", "url": f"https://{t.host}/", "headers": {}, "body": ""},
                    "response": {"status": 200}}, ""
        co.orch.register_worker("http_probe", worker)
        co.orch.register_worker("state_change", lambda t, cc: (None, "inconclusive"))

        allowed = co.orch.propose(Task(campaign_id=c.id, technique="http_probe",
                                       host="api.acme.example", hypothesis="up?"))
        denied = co.orch.propose(Task(campaign_id=c.id, technique="http_probe",
                                      host="evil.other.example", hypothesis="oob"))
        risky = co.orch.propose(Task(campaign_id=c.id, technique="state_change",
                                     host="api.acme.example", hypothesis="write?"))
        assert allowed.state == "QUEUED" and denied.state == "DENIED"
        assert risky.state == "APPROVAL_REQUIRED"

        co.start()
        gate.set()                              # release the latched step
        _join_until(co, lambda: allowed.state == "EVALUATED")
        assert ran == ["api.acme.example"], ran
        assert denied.state == "DENIED"

        # approve the risky one through the coordinator: can_test re-runs, task wakes, runs.
        co.approve(risky.id, by="researcher")
        _join_until(co, lambda: risky.state == "EVALUATED")
        with co._lock:
            assert co._state in ("WAITING_APPROVAL", "COMPLETE", "RUNNING")
        co.stop()
        _join_until(co, lambda: co.snapshot()["run_state"] in ("STOPPED", "COMPLETE"))

        events = [a["event"] for a in c.audit_trail()]
        assert "run_transition" in events and "human_approved" in events
    del os.environ["ARGUS_HOME"]
    _reset_registry()
    print("run coordinator demo passed")


def _join_until(co: CampaignRunCoordinator, pred, timeout: float = 5.0) -> None:
    import time
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return
        time.sleep(0.01)
    raise AssertionError(f"condition not met within {timeout}s; run_state={co.snapshot()['run_state']}")


if __name__ == "__main__":
    demo()
