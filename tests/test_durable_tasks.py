"""Durable task model + durable orchestrator.

Slice 5's contract: the orchestrator is a DURABLE campaign controller, not an
in-memory one. A restart (a fresh Orchestrator on the same campaign) must recover
the exact queue — parked tasks stay parked, a task caught mid-run is never assumed
complete, and no illegal state edge (DENIED -> QUEUED) is reachable by rewriting a
field. These tests pin that down.
"""
import os

import pytest

from argus import campaign, identity as id_mod
from argus.orchestrator import Orchestrator, Task, _assert_transition


@pytest.fixture
def camp(tmp_path):
    os.environ["ARGUS_HOME"] = str(tmp_path)
    try:
        yield campaign.create("Assets:\n*.acme.example\nRate: 2 requests/sec\n", name="Acme")
    finally:
        del os.environ["ARGUS_HOME"]


def _probe(t, c):
    return ({"request": {"method": "GET", "url": f"https://{t.host}/", "headers": {}, "body": ""},
             "response": {"status": 200}}, "")


# --- persistence round-trip + shared queue --------------------------------
def test_second_orchestrator_sees_the_same_queue(camp):
    o1 = Orchestrator(camp)
    a = o1.propose(Task(campaign_id=camp.id, technique="http_probe", host="api.acme.example"))
    d = o1.propose(Task(campaign_id=camp.id, technique="http_probe", host="evil.example"))
    r = o1.propose(Task(campaign_id=camp.id, technique="state_change", host="api.acme.example"))

    o2 = Orchestrator(camp)                       # "restart": a fresh process
    assert set(o2.tasks) == {a.id, d.id, r.id}
    assert o2.tasks[a.id].state == "QUEUED"
    assert o2.tasks[d.id].state == "DENIED"
    assert o2.tasks[r.id].state == "APPROVAL_REQUIRED"


def test_progress_is_computed_from_durable_tasks(camp):
    o1 = Orchestrator(camp)
    o1.register_worker("http_probe", _probe)
    o1.propose(Task(campaign_id=camp.id, technique="http_probe", host="api.acme.example"))
    o1.run()
    # a separate controller, loading only from disk, reports the same verified work
    o2 = Orchestrator(camp)
    p = o2.progress()
    assert p["planned"] == 1 and p["completed"] == 1 and p["percentage"] == 100


# --- the safety invariant: illegal edges don't exist ----------------------
def test_denied_can_never_walk_back_to_queued(camp):
    o = Orchestrator(camp)
    d = o.propose(Task(campaign_id=camp.id, technique="http_probe", host="evil.example"))
    assert d.state == "DENIED"
    with pytest.raises(ValueError):
        o._set(d, "QUEUED")                       # terminal: no outgoing edge
    with pytest.raises(ValueError):
        _assert_transition("DENIED", "QUEUED")
    # and a reload keeps it DENIED, not silently reset
    assert Orchestrator(camp).tasks[d.id].state == "DENIED"


# --- restart recovery of a task caught mid-run ----------------------------
def test_interrupted_read_task_requeues_on_restart(camp):
    o1 = Orchestrator(camp)
    t = o1.propose(Task(campaign_id=camp.id, technique="http_probe", host="api.acme.example"))
    o1._set(t, "RUNNING")                         # crash mid-flight: left RUNNING on disk

    o2 = Orchestrator(camp)                        # restart recovers it
    assert o2.tasks[t.id].state == "QUEUED"        # re-queued (in scope, retries remain)
    events = [a["event"] for a in camp.audit_trail()]
    assert "recovered_interrupted" in events


def test_interrupted_highrisk_task_goes_back_to_approval(camp):
    o1 = Orchestrator(camp)
    r = o1.propose(Task(campaign_id=camp.id, technique="state_change", host="api.acme.example"))
    o1.approve(r.id, by="researcher")              # human cleared it -> QUEUED
    o1._set(r, "RUNNING")                          # then the process died mid-run

    o2 = Orchestrator(camp)
    # a possibly state-changing action is NOT silently re-run: back to human review
    assert o2.tasks[r.id].state == "APPROVAL_REQUIRED"


# --- durable approvals -----------------------------------------------------
def test_approval_record_is_durable_and_resolved(camp):
    o1 = Orchestrator(camp)
    r = o1.propose(Task(campaign_id=camp.id, technique="state_change", host="api.acme.example"))
    pend = camp.approvals()
    assert len(pend) == 1 and pend[0]["task_id"] == r.id and pend[0]["decision"] == ""

    o2 = Orchestrator(camp)                        # restart: the request still stands
    assert [t.id for t in o2.pending_approvals()] == [r.id]
    o2.approve(r.id, by="alice", note="authorized per engagement")
    resolved = camp.approvals()[0]
    assert resolved["decision"] == "APPROVE_ONCE" and resolved["resolved_by"] == "alice"


def test_human_approval_never_overrides_a_scope_deny_across_restart(camp):
    o1 = Orchestrator(camp)
    # in-scope high-risk: parks for approval
    r = o1.propose(Task(campaign_id=camp.id, technique="mass_enumeration", host="api.acme.example"))
    assert r.state == "APPROVAL_REQUIRED"
    # the program is edited to forbid the technique; a fresh controller re-reads policy
    camp.policy.forbidden.append("No enumeration permitted")
    o2 = Orchestrator(camp)
    with pytest.raises(ValueError):
        o2.approve(r.id, by="alice")               # policy re-check denies regardless
    assert o2.tasks[r.id].state == "DENIED"


# --- dependency recovery ---------------------------------------------------
def test_failed_prerequisite_blocks_downstream_not_satisfies_it(camp):
    o = Orchestrator(camp, max_attempts=1)
    o.register_worker("http_probe", lambda t, c: (_ for _ in ()).throw(RuntimeError("boom")))
    a = o.propose(Task(campaign_id=camp.id, technique="http_probe", host="api.acme.example"))
    b = o.propose(Task(campaign_id=camp.id, technique="http_probe", host="app.acme.example",
                       deps=[a.id]))
    o.run()
    assert a.state == "FAILED"
    assert b.state == "QUEUED"                     # never ran: a failed dep is NOT "done"
    p = o.progress()
    assert p["blocked"] == 1 and p["completed"] == 0


def test_dependency_waits_survive_restart(camp):
    o1 = Orchestrator(camp)
    o1.register_worker("http_probe", _probe)
    a = o1.propose(Task(campaign_id=camp.id, technique="http_probe", host="api.acme.example"))
    b = o1.propose(Task(campaign_id=camp.id, technique="http_probe", host="app.acme.example",
                        deps=[a.id]))
    # restart BEFORE anything runs: B must still wait on A, not run free
    o2 = Orchestrator(camp)
    o2.register_worker("http_probe", _probe)
    assert o2._dep_status(o2.tasks[b.id]) == "waiting"
    o2.run()
    assert o2.tasks[a.id].state == "EVALUATED" and o2.tasks[b.id].state == "EVALUATED"


# --- identity round-trips through persistence ------------------------------
def test_account_name_round_trips_for_cross_account_tasks(camp):
    id_mod.register(camp, id_mod.Identity(name="user_a", researcher_owned=True))
    o1 = Orchestrator(camp)
    acct = id_mod.get(camp, "user_a")
    t = o1.propose(Task(campaign_id=camp.id, technique="http_probe",
                        host="api.acme.example", account=acct))
    assert camp.tasks()[0]["account_name"] == "user_a"
    o2 = Orchestrator(camp)                         # reload re-resolves the live identity
    assert o2.tasks[t.id].account is not None
    assert o2.tasks[t.id].account.name == "user_a"
