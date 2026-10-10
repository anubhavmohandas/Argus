"""Deterministic research planner — pins the next-best-safe-action decision and honest stops.

The planner is the hunter brain: of everything unexplored, the single highest-value SAFE next
action, or an honest reason there is none. These lock: it chooses the top-ranked policy-safe
gap; it parks (never auto-runs) a gap that needs human approval; its stop reasons are honest
and never "secure"; and the completion handoff is composed from the existing aggregates. It
executes nothing.
"""
import pytest

from argus import (
    campaign as cmod,
    identity as imod,
    planner,
    priority,
    resource,
    traffic,
)


@pytest.fixture
def camp(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_HOME", str(tmp_path))
    c = cmod.create("In scope:\napi.acme.example\nRate: 5 requests/sec\n", name="acme")
    for name in ("customer_a", "customer_b"):
        imod.register(c, imod.Identity(name=name, role="customer", tenant="t1",
                                       researcher_owned=True))
    return c


def _owned_action(c, method, path, rtype, rid):
    traffic.capture(c, method=method, url=f"https://api.acme.example{path}",
                    headers={"Authorization": "Bearer s"}, identity="customer_a",
                    response={"status": 200})
    resource.assert_ownership(c, resource.Ownership(
        resource_type=rtype, resource_value=rid, owner_identity="customer_a",
        tenant="t1", researcher_controlled=True))


def test_module_demo():
    planner.demo()


def test_picks_top_safe_gap(camp):
    _owned_action(camp, "POST", "/api/refunds/5/approve", "refund", "5")
    _owned_action(camp, "GET", "/api/orders/9", "order", "9")
    a = planner.assess(camp)
    assert not a["stopped"] and a["stop_reason"] == ""
    top = priority.rank(camp)[0]
    assert a["next_action"]["gap"]["gap_id"] == top["gap_id"]
    # both gaps are researcher-owned cross-account -> ALLOW*, so both are safe-runnable
    assert a["counts"]["safe_runnable"] == a["counts"]["open_gaps"]
    assert a["counts"]["need_approval"] == 0


def test_empty_campaign_stops_honestly(camp):
    a = planner.assess(camp)
    assert a["stopped"] and a["stop_reason"] == "no_open_gaps"
    assert a["next_action"] is None
    done = planner.completion(camp)
    # never "secure" — only that useful research is exhausted under current knowledge
    assert done["status"] == "RESEARCH_EXHAUSTED"
    assert "secure" not in done["status"].lower()


def test_budget_and_threshold_stops(camp):
    _owned_action(camp, "POST", "/api/refunds/5/approve", "refund", "5")
    assert planner.assess(camp, budget_remaining=0)["stop_reason"] == "budget_exhausted"
    assert planner.assess(camp, min_score=101)["stop_reason"] == "below_useful_threshold"


def test_completion_counts_match_aggregates(camp):
    _owned_action(camp, "POST", "/api/refunds/5/approve", "refund", "5")
    done = planner.completion(camp)
    assert done["mapped"]["ownership_confirmed"] == 1
    assert done["remaining"]["untested_boundaries"] == planner.assess(camp)["counts"]["open_gaps"]
    assert done["research_coverage_note"] == "research coverage, not a security score"
