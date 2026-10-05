"""Per-campaign run coordinator — concurrency contract.

The dangerous bugs in a live campaign are ordering bugs, not syntax bugs: a background
loop and an operator command mutating one durable task table at the same time. These
tests pin the coordinator's guarantees down with real threads and latching workers, so
the ordering is asserted, not left to timing luck.

Locked here: one execution owner per campaign, independent campaigns, pause = no new
dispatch, resume continues exactly once, approve re-checks policy and wakes the loop,
deny never executes, stop preserves durable work, restart recovers deterministically,
a stale run generation can't mutate a newer run, a task is never dispatched twice, and
run-state transitions land in the audit log in order.
"""
import os
import threading
import time

import pytest

from argus import campaign as campaign_mod
from argus.orchestrator import Task
from argus.run import _reset_registry, coordinator_for

PROGRAM = "In scope:\n*.acme.example\nRate: 50 requests/sec\n"


@pytest.fixture
def home(tmp_path):
    os.environ["ARGUS_HOME"] = str(tmp_path)
    _reset_registry()
    try:
        yield tmp_path
    finally:
        _reset_registry()
        del os.environ["ARGUS_HOME"]


def _camp(name="acme"):
    return campaign_mod.create(PROGRAM, name=name)


def _wait(pred, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.005)
    return False


def _instant_probe(calls):
    def worker(t, c):
        calls.append(t.host)
        return ({"request": {"method": "GET", "url": f"https://{t.host}/", "headers": {}, "body": ""},
                 "response": {"status": 200}}, "")
    return worker


# --- one execution owner --------------------------------------------------
def test_concurrent_starts_yield_one_owner_and_run_each_task_once(home):
    c = _camp()
    co = coordinator_for(c)
    calls: list[str] = []
    co.orch.register_worker("http_probe", _instant_probe(calls))
    hosts = [f"h{i}.acme.example" for i in range(6)]
    for h in hosts:
        co.orch.propose(Task(campaign_id=c.id, technique="http_probe", host=h))

    seen_run_ids: set[str] = set()

    def racer():
        snap = co.start()
        seen_run_ids.add(snap["run_id"])

    threads = [threading.Thread(target=racer) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert _wait(lambda: co.snapshot()["run_state"] == "COMPLETE")
    # exactly one run generation won — 10 concurrent starts, one owner
    assert len(seen_run_ids) == 1, seen_run_ids
    # every task executed exactly once (no double dispatch)
    assert sorted(calls) == sorted(hosts)
    assert all(t.state == "EVALUATED" and t.attempts == 1 for t in co.orch.tasks.values())


def test_different_campaigns_run_independently(home):
    c1, c2 = _camp("one"), _camp("two")
    co1, co2 = coordinator_for(c1), coordinator_for(c2)
    assert co1 is not co2 and co1 is coordinator_for(c1)   # registry: one per id
    for co, c in ((co1, c1), (co2, c2)):
        co.orch.register_worker("http_probe", _instant_probe([]))
        co.orch.propose(Task(campaign_id=c.id, technique="http_probe", host="a.acme.example"))
    rid1 = co1.start()["run_id"]
    rid2 = co2.start()["run_id"]
    assert rid1 and rid2 and rid1 != rid2                  # distinct run generations
    assert _wait(lambda: co1.snapshot()["run_state"] == "COMPLETE")
    assert _wait(lambda: co2.snapshot()["run_state"] == "COMPLETE")


# --- pause / resume -------------------------------------------------------
def _latching_worker(entered: dict, release: dict, calls: list):
    """Worker that signals when it enters a task and blocks until that task is released.
    Lets a test hold one step 'running' while it issues pause/stop, then observe that no
    NEXT task is dispatched."""
    def worker(t, c):
        entered.setdefault(t.host, threading.Event()).set()
        release.setdefault(t.host, threading.Event()).wait(5)
        calls.append(t.host)
        return ({"request": {"method": "GET", "url": f"https://{t.host}/", "headers": {}, "body": ""},
                 "response": {"status": 200}}, "")
    return worker


def test_pause_lets_running_task_finish_but_dispatches_no_new(home):
    c = _camp()
    co = coordinator_for(c)
    entered: dict = {h: threading.Event() for h in ("a.acme.example", "b.acme.example")}
    release: dict = {h: threading.Event() for h in entered}
    calls: list[str] = []
    co.orch.register_worker("http_probe", _latching_worker(entered, release, calls))
    # higher priority on 'a' so it is claimed first, deterministically
    co.orch.propose(Task(campaign_id=c.id, technique="http_probe", host="a.acme.example", impact=10))
    co.orch.propose(Task(campaign_id=c.id, technique="http_probe", host="b.acme.example", impact=1))

    co.start()
    assert _wait(lambda: entered["a.acme.example"].is_set())   # 'a' is mid-step
    co.pause()
    release["a.acme.example"].set()                            # let the running task finish
    assert _wait(lambda: co.snapshot()["run_state"] == "PAUSED")
    time.sleep(0.2)
    assert calls == ["a.acme.example"]                         # 'b' was NOT dispatched
    assert not entered["b.acme.example"].is_set()

    co.resume()
    release["b.acme.example"].set()
    assert _wait(lambda: co.snapshot()["run_state"] == "COMPLETE")
    assert sorted(calls) == ["a.acme.example", "b.acme.example"]  # continued exactly once


# --- approval under concurrency ------------------------------------------
def test_approve_rechecks_policy_and_wakes_the_loop(home):
    c = _camp()
    co = coordinator_for(c)
    calls: list[str] = []
    co.orch.register_worker("state_change", lambda t, cc: (calls.append(t.host) or (None, "inconclusive")))
    risky = co.orch.propose(Task(campaign_id=c.id, technique="state_change", host="api.acme.example"))
    assert risky.state == "APPROVAL_REQUIRED"

    co.start()
    assert _wait(lambda: co.snapshot()["run_state"] == "WAITING_APPROVAL")
    assert calls == []                                        # not executed while parked
    co.approve(risky.id, by="researcher")                     # routes through can_test again
    assert _wait(lambda: risky.state == "EVALUATED")
    assert calls == ["api.acme.example"]


def test_deny_is_terminal_and_never_executes(home):
    c = _camp()
    co = coordinator_for(c)
    calls: list[str] = []
    co.orch.register_worker("state_change", lambda t, cc: (calls.append(t.host) or (None, "inconclusive")))
    risky = co.orch.propose(Task(campaign_id=c.id, technique="state_change", host="api.acme.example"))
    co.start()
    assert _wait(lambda: co.snapshot()["run_state"] == "WAITING_APPROVAL")
    co.deny(risky.id, by="researcher")
    assert _wait(lambda: co.snapshot()["run_state"] == "COMPLETE")
    assert risky.state == "DENIED"
    assert calls == []


def test_out_of_scope_deny_cannot_be_approved_through_the_coordinator(home):
    c = _camp()
    co = coordinator_for(c)
    # out-of-scope host parks as DENIED, not APPROVAL_REQUIRED — but force an approval
    # attempt to prove the gate re-check cannot walk a scope DENY to the queue.
    t = co.orch.propose(Task(campaign_id=c.id, technique="http_probe", host="evil.other.example"))
    assert t.state == "DENIED"
    with pytest.raises(ValueError):
        co.approve(t.id, by="attacker")                       # wrong state / policy re-check
    assert t.state == "DENIED"


# --- stop -----------------------------------------------------------------
def test_stop_preserves_durable_work_and_dispatches_no_more(home):
    c = _camp()
    co = coordinator_for(c)
    entered = {"a.acme.example": threading.Event()}
    release = {"a.acme.example": threading.Event()}
    calls: list[str] = []
    co.orch.register_worker("http_probe", _latching_worker(entered, release, calls))
    co.orch.propose(Task(campaign_id=c.id, technique="http_probe", host="a.acme.example", impact=10))
    b = co.orch.propose(Task(campaign_id=c.id, technique="http_probe", host="b.acme.example", impact=1))

    co.start()
    assert _wait(lambda: entered["a.acme.example"].is_set())
    co.stop()
    release["a.acme.example"].set()
    assert _wait(lambda: co.snapshot()["run_state"] == "STOPPED")
    assert calls == ["a.acme.example"]                        # 'b' never dispatched
    assert b.state == "QUEUED"                                # durable queued work preserved
    assert any(rec["id"] == b.id and rec["state"] == "QUEUED" for rec in c.tasks())


# --- restart recovery -----------------------------------------------------
def test_crash_mid_run_recovers_to_stopped_not_running(home):
    c = _camp()
    co = coordinator_for(c)
    # simulate a process that died with run.json saying RUNNING
    co._persist("RUNNING", "run-ghost")
    _reset_registry()                                         # drop the in-memory coordinator
    c2 = campaign_mod.load(c.id)
    co2 = coordinator_for(c2)                                 # "restart": fresh process
    assert co2.snapshot()["run_state"] == "STOPPED"           # never trusts a stale RUNNING
    assert any(a["event"] == "run_recovered" for a in c2.audit_trail())


# --- stale run generation -------------------------------------------------
def test_stale_run_id_cannot_step_the_newer_run(home):
    c = _camp()
    co = coordinator_for(c)
    calls: list[str] = []
    co.orch.register_worker("http_probe", _instant_probe(calls))
    co.orch.propose(Task(campaign_id=c.id, technique="http_probe", host="a.acme.example"))
    co.start()
    assert _wait(lambda: co.snapshot()["run_state"] == "COMPLETE")
    stale = "run-old-generation"
    assert co._run_id != stale
    # an old-generation loop calling in must refuse — it cannot commit into the live run
    assert co._guarded_step(stale) is None


# --- progress is verified work, not activity ------------------------------
def test_progress_percentage_tracks_only_completed_work(home):
    c = _camp()
    co = coordinator_for(c)
    co.orch.register_worker("http_probe", _instant_probe([]))
    for i in range(4):
        co.orch.propose(Task(campaign_id=c.id, technique="http_probe", host=f"h{i}.acme.example"))
    co.start()
    assert _wait(lambda: co.snapshot()["run_state"] == "COMPLETE")
    p = c.progress()
    assert p["percentage"] == 100 and p["completed"] == 4 and p["planned"] == 4


# --- reproduction rides the same coordinator ------------------------------
def test_reproduction_runs_through_the_coordinator_and_advances_finding(home, monkeypatch):
    from argus import differential, finding as finding_mod, identity as id_mod, reproduce
    monkeypatch.setenv("A_TOK", "tok-a")
    monkeypatch.setenv("B_TOK", "tok-b")
    c = campaign_mod.create("In scope:\napi.acme.example\nRate: 20 requests/sec\n", name="repro")
    a = id_mod.register(c, id_mod.Identity(name="user_a", researcher_owned=True, credential_ref="A_TOK"))
    id_mod.register(c, id_mod.Identity(name="user_b", researcher_owned=True, credential_ref="B_TOK"))
    # stable leak: B always gets 200 on A's object -> "suspicious", every time
    monkeypatch.setattr(differential, "_default_fetch",
                        lambda *x: (200, {"content-type": "application/json"}, "{}"))
    co = coordinator_for(c)
    spec = {"baseline": {"identity": "user_a", "method": "POST", "path": "/o/1/cancel",
                         "resource": "o1", "owner": "user_a"},
            "mutation": {"identity": "user_b", "method": "POST", "path": "/o/1/cancel",
                         "resource": "o1", "owner": "user_a"}}
    orig = co.orch.propose(Task(campaign_id=c.id, technique="differential_cross_account",
                                host="api.acme.example", spec=spec, hypothesis="idor?",
                                account=a, account_name="user_a"))
    co.start()
    assert _wait(lambda: orig.state == "EVALUATED")
    assert _wait(lambda: not co.is_active())

    exp = next(e for e in c.experiments() if e["id"] == orig.experiment_id)
    assert exp["classification"] == "suspicious"
    f = finding_mod.promote(c, exp)
    assert f.state == "OBSERVED"

    # reproduce through the SAME coordinator — trials are gated differential Tasks
    planner, on_complete = reproduce.background_verify(c, f.id, trials=3)
    co.start(planner=planner, on_complete=on_complete)
    assert _wait(lambda: finding_mod._get(c, f.id).state == "REPRODUCIBLE")
    checks = [a for a in c.audit_trail() if a["event"] == "reproducibility_check"]
    assert checks and checks[-1]["reproduced"] is True and checks[-1]["trials"] == 3


# --- SSE source: run transitions land in the audit log in order -----------
def test_run_transitions_are_audited_in_order(home):
    c = _camp()
    co = coordinator_for(c)
    co.orch.register_worker("http_probe", _instant_probe([]))
    co.orch.propose(Task(campaign_id=c.id, technique="http_probe", host="a.acme.example"))
    co.start()
    assert _wait(lambda: co.snapshot()["run_state"] == "COMPLETE")
    states = [a["state"] for a in c.audit_trail() if a["event"] == "run_transition"]
    assert states[0] == "STARTING"
    assert states[1] == "RUNNING"
    assert states[-1] == "COMPLETE"
    # a transition is only ever a legal edge in the state machine
    from argus.run import _RUN_TRANSITIONS
    for frm, to in zip(states, states[1:]):
        assert to in _RUN_TRANSITIONS.get(frm, set()) or to == frm
