"""Orchestrator loop + the safety invariants it exists to hold.

The whole point of the orchestrator is that a worker runs ONLY for a task the gate
cleared. These tests pin that down directly, not just via the happy path.
"""
import os

import pytest

from argus import campaign, orchestrator
from argus.orchestrator import Orchestrator, Task


@pytest.fixture
def camp(tmp_path):
    os.environ["ARGUS_HOME"] = str(tmp_path)
    try:
        yield campaign.create("Assets:\n*.acme.example\nRate: 2 requests/sec\n", name="Acme")
    finally:
        del os.environ["ARGUS_HOME"]


def _spy_worker(calls):
    def w(task, c):
        calls.append((task.technique, task.host))
        return ({"request": {"method": "GET", "url": f"https://{task.host}/", "headers": {}, "body": ""},
                 "response": {"status": 200}}, "")
    return w


def test_orchestrator_demo():
    orchestrator.demo()


def test_worker_never_runs_on_denied_or_parked_tasks(camp):
    calls = []
    orch = Orchestrator(camp)
    orch.register_worker("http_probe", _spy_worker(calls))
    orch.register_worker("state_change", _spy_worker(calls))

    orch.propose(Task(campaign_id=camp.id, technique="http_probe", host="evil.example"))      # DENY
    orch.propose(Task(campaign_id=camp.id, technique="state_change", host="api.acme.example"))  # APPROVAL
    ok = orch.propose(Task(campaign_id=camp.id, technique="http_probe", host="api.acme.example"))  # ALLOW

    orch.run()
    assert calls == [("http_probe", "api.acme.example")]   # the one cleared task, nothing else
    assert ok.state == "EVALUATED"


def test_approval_cannot_override_a_scope_deny(camp):
    orch = Orchestrator(camp)
    # out-of-scope high-risk task: denied outright, never even reaches APPROVAL_REQUIRED
    t = orch.propose(Task(campaign_id=camp.id, technique="state_change", host="evil.example"))
    assert t.state == "DENIED"
    with pytest.raises(ValueError):
        orch.approve(t.id, by="researcher")     # cannot approve what was DENIED


def test_priority_orders_the_queue(camp):
    orch = Orchestrator(camp)
    orch.register_worker("http_probe", _spy_worker([]))
    lo = orch.propose(Task(campaign_id=camp.id, technique="http_probe", host="a.acme.example",
                           impact=1, confidence=0.3, cost=2))
    hi = orch.propose(Task(campaign_id=camp.id, technique="http_probe", host="b.acme.example",
                           impact=5, confidence=0.9, cost=1))
    order = [orch.step().host, orch.step().host]
    assert order == ["b.acme.example", "a.acme.example"]   # higher priority first
    assert hi.priority > lo.priority


def test_budget_stops_execution(camp):
    orch = Orchestrator(camp, budget_requests=1)
    orch.register_worker("http_probe", _spy_worker([]))
    for h in ("a.acme.example", "b.acme.example"):
        orch.propose(Task(campaign_id=camp.id, technique="http_probe", host=h))
    assert orch.run() == 1                        # only one task fits the budget
    assert sum(1 for t in orch.tasks.values() if t.state == "EVALUATED") == 1
