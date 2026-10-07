"""ExperimentProposal + the knowledge-update loop — the seam between knowing and doing.

These tests pin the loop's safety and its learning:

  * a proposal is a PLAN — building one sends no request; it carries the concrete owner
    path, the expected secure behaviour, and the ownership assertions it relies on
  * queue() reaches execution ONLY through the existing orchestrator (can_test re-gates it)
  * the full loop: gap -> proposal -> orchestrator -> experiment -> reconcile -> gap TESTED
    and a suspicious result promotes a FindingCandidate through the existing pipeline
  * a secure result RESOLVES the gap (a negative result is remembered, never re-proposed)
  * nothing in matrix/priority/proposal ever executes (offline, no network, is sufficient)
"""
from dataclasses import asdict

import pytest

from argus import (
    campaign as cmod, coverage, finding as finding_mod, identity as imod,
    priority, proposal, resource, traffic,
)
from argus.orchestrator import Orchestrator


@pytest.fixture
def camp(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_HOME", str(tmp_path))
    c = cmod.create("In scope:\napi.acme.example\nRate: 2 requests/sec\n", name="acme")
    for name in ("customer_a", "customer_b"):
        imod.register(c, imod.Identity(name=name, role="customer", tenant="t1", researcher_owned=True))
    traffic.capture(c, method="POST", url="https://api.acme.example/api/orders/777/cancel",
                    headers={"Authorization": "Bearer s"}, identity="customer_a",
                    response={"status": 204})
    resource.assert_ownership(c, resource.Ownership(
        resource_type="order", resource_value="777", owner_identity="customer_a",
        tenant="t1", researcher_controlled=True))
    return c


def _gid(c):
    return priority.rank(c)[0]["gap_id"]


def test_proposal_carries_concrete_owner_path(camp):
    p = proposal.proposals(camp)[0]
    assert p["method"] == "POST" and p["path"] == "/api/orders/777/cancel"
    assert p["baseline_identity"] == "customer_a" and p["mutation_identity"] == "customer_b"
    assert p["target_resource"] == "777"
    assert p["required_ownership_assertions"][0]["researcher_controlled"] is True
    assert "rejected" in p["expected_secure_behavior"]
    # a plan quotes the policy verdict but is not an execution
    assert p["policy_decision_preview"]["verdict"] == "ALLOW_WITH_LIMITS"


def test_to_task_is_a_differential_cross_account_task(camp):
    p = proposal.proposals(camp)[0]
    t = proposal.to_task(camp, p)
    assert t.technique == "differential_cross_account" and t.identity == "customer_b"
    assert t.spec["baseline"]["identity"] == "customer_a"
    assert t.spec["mutation"]["identity"] == "customer_b"
    assert t.spec["mutation"]["path"] == "/api/orders/777/cancel"
    assert getattr(t.account, "researcher_owned", False) is True   # owner drives the gate


def test_queue_gates_through_orchestrator_and_marks_proposed(camp):
    gid = _gid(camp)
    q = proposal.queue(camp, gid)
    assert q["verdict"] == "ALLOW_WITH_LIMITS"
    g = next(x for x in coverage.build(camp)["gaps"] if x["gap_id"] == gid)
    assert g["status"] == "PROPOSED"
    # a durable task exists and is the kind the EXISTING differential worker runs
    task = next(t for t in camp.tasks() if t["id"] == q["task_id"])
    assert task["technique"] == "differential_cross_account"
    assert task["state"] in ("QUEUED", "POLICY_CHECKED", "CREATED")


def test_ingest_suspicious_promotes_finding_and_marks_tested(camp):
    gid = _gid(camp)
    exp = cmod.Experiment(
        campaign_id=camp.id, hypothesis="h", technique="differential_cross_account",
        host="api.acme.example", verdict="ALLOW_WITH_LIMITS", verdict_reason="",
        identity="customer_b", status="EVALUATED", classification="suspicious")
    camp.save_experiment(exp)
    res = proposal.ingest(camp, gid, asdict(exp))
    assert res["status"] == "TESTED" and res["classification"] == "suspicious"
    assert res["finding_id"] and len(finding_mod.findings(camp)) == 1


def test_ingest_secure_resolves_gap_without_a_finding(camp):
    gid = _gid(camp)
    exp = cmod.Experiment(
        campaign_id=camp.id, hypothesis="h", technique="differential_cross_account",
        host="api.acme.example", verdict="ALLOW", verdict_reason="",
        status="EVALUATED", classification="secure")
    camp.save_experiment(exp)
    res = proposal.ingest(camp, gid, asdict(exp))
    assert res["status"] == "RESOLVED" and res["finding_id"] == ""
    assert finding_mod.findings(camp) == []
    # a resolved boundary is remembered — it drops out of the priority queue
    assert all(g["gap_id"] != gid for g in priority.rank(camp))


def test_full_loop_through_the_real_orchestrator(camp):
    """gap -> queue (orchestrator gate) -> run (stubbed differential worker, so offline) ->
    reconcile -> gap TESTED + FindingCandidate. Execution goes through the ACTUAL orchestrator
    task path; only the leaf differential worker is stubbed to avoid a real network request."""
    gid = _gid(camp)
    q = proposal.queue(camp, gid)
    task_id = q["task_id"]

    # a fresh orchestrator adopts the durable QUEUED task; stub ONLY the leaf worker so no
    # HTTP leaves the box, but the orchestrator's gate/run/evaluate path is the real one.
    orch = Orchestrator(camp)

    def fake_differential(task, campaign):
        e = campaign.save_experiment(cmod.Experiment(
            campaign_id=campaign.id, hypothesis=task.hypothesis,
            technique=task.technique, host=task.host, verdict=task.verdict,
            verdict_reason=task.verdict_reason, identity=task.identity,
            status="EVALUATED", classification="suspicious"))
        return None, "suspicious", e.id

    orch.register_worker("differential_cross_account", fake_differential)
    orch.run()

    task = next(t for t in camp.tasks() if t["id"] == task_id)
    assert task["state"] == "EVALUATED" and task["experiment_id"]

    out = proposal.reconcile(camp)
    assert out and out[0]["status"] == "TESTED"
    g = next(x for x in coverage.build(camp)["gaps"] if x["gap_id"] == gid)
    assert g["status"] == "TESTED" and g["lifecycle"]["classification"] == "suspicious"
    assert len(finding_mod.findings(camp)) == 1
    # reconcile is idempotent — a second pass changes nothing
    assert proposal.reconcile(camp) == []


def test_queue_unknown_gap_errors(camp):
    with pytest.raises(ValueError):
        proposal.queue(camp, "gap-does-not-exist")


def test_demo_self_check():
    proposal.demo()
