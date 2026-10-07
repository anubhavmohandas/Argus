"""Ownership-aware authorization coverage + ResearchGaps — the third research-memory layer.

A ResearchGap is MISSING EVIDENCE, never a finding. These tests pin the one high-value
boundary ARGUS must spot — an owner was observed acting on a researcher-controlled object,
a non-owner never was — and the invariants around it: gaps are derived deterministically,
only a CONFIRMED researcher-controlled resource yields an owner→non-owner gap, the policy
verdict a test would get is quoted (never executed), and lifecycle state persists so a
resolved/dismissed boundary is never re-recommended.
"""
import pytest

from argus import campaign as cmod, coverage, identity as imod, resource, traffic


@pytest.fixture
def camp(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_HOME", str(tmp_path))
    c = cmod.create("In scope:\napi.acme.example\nRate: 2 requests/sec\n", name="acme")
    imod.register(c, imod.Identity(name="customer_a", role="customer", tenant="t1", researcher_owned=True))
    imod.register(c, imod.Identity(name="customer_b", role="customer", tenant="t1", researcher_owned=True))
    return c


def _owner_cancels_777(c):
    traffic.capture(c, method="POST", url="https://api.acme.example/api/orders/777/cancel",
                    headers={"Authorization": "Bearer s"}, identity="customer_a",
                    response={"status": 204})
    resource.assert_ownership(c, resource.Ownership(
        resource_type="order", resource_value="777", owner_identity="customer_a",
        tenant="t1", researcher_controlled=True))


def _live(c):
    return [g for g in coverage.build(c)["gaps"] if not g.get("orphan")]


def test_owner_observed_nonowner_untested_makes_a_gap(camp):
    _owner_cancels_777(camp)
    gaps = _live(camp)
    assert len(gaps) == 1
    g = gaps[0]
    assert g["gap_type"] == "OWNER_NONOWNER_UNTESTED"
    assert g["baseline_identity"] == "customer_a" and g["mutation_identity"] == "customer_b"
    assert g["resource_type"] == "order" and g["resource_id"] == "777"
    assert g["estimated_requests"] == 2 and g["status"] == "OPEN"


def test_gap_quotes_policy_but_never_executes(camp):
    _owner_cancels_777(camp)
    g = _live(camp)[0]
    # both identities researcher-owned + a controlled object -> ALLOW_WITH_LIMITS, not a run
    assert g["policy_preview"]["verdict"] == "ALLOW_WITH_LIMITS"
    assert g["policy_preview"]["limits"] and g["policy_preview"]["limits"].get("single_object")
    assert g["technique"] == "differential_cross_account"
    # a gap is an opportunity, never a verdict about the app
    assert "vulnerable" not in str(g).lower() and "finding" not in str(g).lower()


def test_boundary_labels_only_when_metadata_supports_them(camp):
    _owner_cancels_777(camp)
    g = _live(camp)[0]
    # same role + same tenant are known, so both labels appear
    assert "SAME_ROLE_DIFFERENT_IDENTITY" in g["boundary"] and "SAME_TENANT" in g["boundary"]
    assert "OTHER_RESEARCHER_OWNED_RESOURCE" in g["boundary"]


def test_no_gap_without_researcher_controlled_ownership(camp):
    # owner acts, but the resource is NOT asserted researcher-controlled -> no safe gap
    traffic.capture(camp, method="POST", url="https://api.acme.example/api/invoices/900/void",
                    headers={"Authorization": "Bearer s"}, identity="customer_a",
                    response={"status": 204})
    assert not any(g["resource_id"] == "900" for g in _live(camp))


def test_inferred_ownership_does_not_authorize_a_gap(camp):
    traffic.capture(camp, method="POST", url="https://api.acme.example/api/orders/55/cancel",
                    headers={"Authorization": "Bearer s"}, identity="customer_a",
                    response={"status": 204})
    # an INFERRED ownership can never be researcher-controlled, so no owner-nonowner gap
    resource.assert_ownership(camp, resource.Ownership(
        resource_type="order", resource_value="55", owner_identity="customer_a",
        researcher_controlled=True, ownership_status="INFERRED", confidence=0.7, source="inferred"))
    assert not any(g["resource_id"] == "55" for g in _live(camp))


def test_nonowner_already_observed_closes_the_gap(camp):
    _owner_cancels_777(camp)
    assert len(_live(camp)) == 1
    # customer_b now observed on the same object+endpoint -> boundary already exercised
    traffic.capture(camp, method="POST", url="https://api.acme.example/api/orders/777/cancel",
                    headers={"Authorization": "Bearer s"}, identity="customer_b",
                    response={"status": 403})
    assert len(_live(camp)) == 0


def test_gap_id_deterministic_and_reload_stable(camp):
    _owner_cancels_777(camp)
    first = coverage.build(camp)
    assert coverage.build(cmod.load(camp.id)) == first


def test_lifecycle_persists_and_is_remembered(camp):
    _owner_cancels_777(camp)
    gid = _live(camp)[0]["gap_id"]
    coverage.set_gap_state(camp, gid, "RESOLVED", classification="secure", experiment_id="exp-1")
    g = next(x for x in coverage.build(camp)["gaps"] if x["gap_id"] == gid)
    assert g["status"] == "RESOLVED" and g["lifecycle"]["classification"] == "secure"
    # a dead boundary that stops being derivable is kept as an orphan memory, never lost
    # (here it is still derivable; just assert the state survives re-derivation)
    assert coverage.build(cmod.load(camp.id))["summary"]["by_status"].get("RESOLVED") == 1


def test_bad_gap_state_rejected(camp):
    _owner_cancels_777(camp)
    gid = _live(camp)[0]["gap_id"]
    with pytest.raises(ValueError):
        coverage.set_gap_state(camp, gid, "BOGUS")


def test_build_is_read_only(camp):
    _owner_cancels_777(camp)
    before = sorted(p.name for p in camp.dir.rglob("*"))
    coverage.build(camp)
    coverage.build(camp)
    assert sorted(p.name for p in camp.dir.rglob("*")) == before


def test_demo_self_check():
    coverage.demo()
