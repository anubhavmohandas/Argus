"""Deterministic research-priority engine — pins the ranking semantics.

Priority is research signal, NEVER severity. These tests lock: a state-changing, sensitive,
cross-identity boundary outranks a bland read; the score is a transparent sum of named
factors; the order is deterministic for the same campaign state; only OPEN gaps are ranked;
and the Command Center intel reports research coverage (never a security score) + the single
highest-value unexplored boundary — all derived, executing nothing.
"""
import pytest

from argus import campaign as cmod, coverage, identity as imod, priority, resource, traffic


@pytest.fixture
def camp(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_HOME", str(tmp_path))
    c = cmod.create("In scope:\napi.acme.example\nRate: 2 requests/sec\n", name="acme")
    for name in ("customer_a", "customer_b"):
        imod.register(c, imod.Identity(name=name, role="customer", tenant="t1", researcher_owned=True))
    return c


def _owned_action(c, method, path, rtype, rid):
    traffic.capture(c, method=method, url=f"https://api.acme.example{path}",
                    headers={"Authorization": "Bearer s"}, identity="customer_a",
                    response={"status": 200})
    resource.assert_ownership(c, resource.Ownership(
        resource_type=rtype, resource_value=rid, owner_identity="customer_a",
        tenant="t1", researcher_controlled=True))


def test_sensitive_write_outranks_bland_read(camp):
    _owned_action(camp, "POST", "/api/refunds/5/approve", "refund", "5")
    _owned_action(camp, "GET", "/api/profile/9", "profile", "9")
    ranked = priority.rank(camp)
    assert len(ranked) == 2
    assert "refunds" in ranked[0]["path_template"]
    assert ranked[0]["priority_score"] > ranked[1]["priority_score"]
    assert [g["priority_rank"] for g in ranked] == [1, 2]


def test_score_is_a_transparent_sum_of_factors(camp):
    _owned_action(camp, "POST", "/api/orders/7/cancel", "order", "7")
    g = priority.rank(camp)[0]
    assert "priority_factors" in g and g["priority_factors"]["base"] == 25
    # factors sum to the score (no clamp at these weights)
    assert sum(g["priority_factors"].values()) == g["priority_score"]


def test_ranking_is_deterministic(camp):
    _owned_action(camp, "POST", "/api/refunds/5/approve", "refund", "5")
    _owned_action(camp, "POST", "/api/orders/7/cancel", "order", "7")
    a = [g["gap_id"] for g in priority.rank(camp)]
    b = [g["gap_id"] for g in priority.rank(cmod.load(camp.id))]
    assert a == b


def test_resolved_gaps_are_not_ranked(camp):
    _owned_action(camp, "POST", "/api/orders/7/cancel", "order", "7")
    gid = priority.rank(camp)[0]["gap_id"]
    coverage.set_gap_state(camp, gid, "RESOLVED", classification="secure")
    assert all(g["gap_id"] != gid for g in priority.rank(camp))


def test_intel_reports_research_coverage_not_security(camp):
    _owned_action(camp, "POST", "/api/refunds/5/approve", "refund", "5")
    it = priority.intel(camp)
    rc = it["research_coverage"]
    assert rc["note"] == "research coverage, not a security score"
    assert rc["ownership_confirmed"] == 1 and rc["open_boundary_gaps"] == 1
    assert it["highest_value_boundary"]["gap_id"] == priority.rank(camp)[0]["gap_id"]
    # intel is derived state — it carries no verdict about the application
    assert "vulnerable" not in str(it).lower()


def test_intel_is_separate_from_execution_progress(camp):
    # a refreshed matrix/gap must never move the campaign's execution progress percentage.
    _owned_action(camp, "POST", "/api/orders/7/cancel", "order", "7")
    priority.intel(camp)
    assert camp.progress()["percentage"] == 0        # no planned execution work yet


def test_demo_self_check():
    priority.demo()


def test_workflow_counts_daily_attention(camp):
    """The Command Center workflow block is a pure aggregate over existing state: open gaps,
    suspicious observations, and findings by earned stage."""
    _owned_action(camp, "GET", "/api/orders/1", "order", "1")
    wf = priority.workflow(camp)
    assert set(wf) == {
        "open_research_gaps", "experiments_awaiting_approval", "suspicious_observations",
        "candidates_needing_reproduction", "reproduced_findings", "impact_confirmed_findings",
        "likely_duplicate_clusters", "reports_ready"}
    assert wf["open_research_gaps"] >= 1
    assert all(isinstance(v, int) and v >= 0 for v in wf.values())
