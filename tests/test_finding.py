"""Finding-candidate lifecycle — promotion, the EARNED forward-only state machine, and the
policy-reportability gate. The core invariant: a finding's state describes what ARGUS has
earned (evidence), not what a caller asked it to call the issue. A caller cannot jump the
lifecycle; each transition verifies evidence that traces back to immutable records.
"""
import os

import pytest

from argus import campaign, differential, finding, identity, reproduce, resource
from argus.differential import Variant, run
from argus.finding import (DISMISSED, complete_dedupe, confirm_boundary, confirm_impact,
                           confirm_scope, dismiss, findings, mark_report_ready,
                           mark_reproducible, promote, report_ready)
from argus.identity import Identity


@pytest.fixture
def camp(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_HOME", str(tmp_path))
    monkeypatch.setenv("A_TOK", "tok-a")
    monkeypatch.setenv("B_TOK", "tok-b")
    c = campaign.create("Assets:\napi.acme.example\nRate: 9 requests/sec\n", name="Acme")
    identity.register(c, Identity(name="user_a", role="customer", tenant="t1",
                                  researcher_owned=True, credential_ref="A_TOK"))
    identity.register(c, Identity(name="user_b", role="customer", tenant="t1",
                                  researcher_owned=True, credential_ref="B_TOK"))
    resource.assert_ownership(c, resource.Ownership(
        resource_type="order", resource_value="order-1", owner_identity="user_a",
        researcher_controlled=True))
    return c


def _leaky_finding(c, host="api.acme.example", path="/api/orders/1", body='{"total":9}'):
    """Run a real leaky cross-account GET differential, promote it, return (finding, base, mut, fetch)."""
    a = Identity(name="user_a", role="customer", tenant="t1", researcher_owned=True, credential_ref="A_TOK")
    b = Identity(name="user_b", role="customer", tenant="t1", researcher_owned=True, credential_ref="B_TOK")
    base = Variant(a, method="GET", path=path, resource="order-1", owner=a)
    mut = Variant(b, method="GET", path=path, resource="order-1", owner=a)
    leak = lambda *x: (200, {"content-type": "application/json"}, body)
    r = run(c, "differential_cross_account", host, base, mut, fetch=leak)
    f = promote(c, next(e for e in c.experiments() if e["id"] == r.experiment_id))
    return f, base, mut, leak


def test_demo():
    finding.demo()


def test_suspicious_differential_becomes_one_candidate(camp):
    f, *_ = _leaky_finding(camp)
    assert f is not None and f.state == "OBSERVED" and f.reportable
    # idempotent: two reconcile/promote calls never create two findings
    exp = next(e for e in camp.experiments() if e["id"] == f.experiment_id)
    assert promote(camp, exp).id == f.id
    assert len(findings(camp)) == 1


def test_secure_experiment_never_promotes(camp):
    exp = {"id": "exp-x", "technique": "differential_cross_account",
           "host": "api.acme.example", "classification": "secure"}
    assert promote(camp, exp) is None
    assert findings(camp) == []


def test_cannot_jump_observed_to_report_ready(camp):
    f, *_ = _leaky_finding(camp)
    with pytest.raises(ValueError, match="needs the finding at DUPLICATE_CHECKED"):
        mark_report_ready(camp, f.id)
    # and no intermediate earned step is skippable either
    with pytest.raises(ValueError, match="needs the finding at REPRODUCIBLE"):
        confirm_scope(camp, f.id)
    with pytest.raises(ValueError, match="needs the finding at IN_SCOPE"):
        confirm_boundary(camp, f.id)


def test_reproducible_requires_real_linked_reproduction_evidence(camp):
    f, *_ = _leaky_finding(camp)
    # a bare claim with no trials is refused
    with pytest.raises(ValueError, match="link real trial experiments"):
        mark_reproducible(camp, f.id, {"reproduced": True, "original": "suspicious",
                                       "trial_experiment_ids": []})
    # a dangling trial ref is refused
    with pytest.raises(ValueError, match="link real trial experiments"):
        mark_reproducible(camp, f.id, {"reproduced": True, "original": "suspicious",
                                       "trial_experiment_ids": ["exp-nope"]})
    assert finding._get(camp, f.id).state == "OBSERVED"


def test_failed_reproduction_does_not_become_validated(camp):
    f, *_ = _leaky_finding(camp)
    with pytest.raises(ValueError, match="did not confirm"):
        mark_reproducible(camp, f.id, {"reproduced": False, "original": "suspicious",
                                       "trial_experiment_ids": []})
    assert finding._get(camp, f.id).state == "OBSERVED"


def test_in_scope_references_frozen_policy(camp):
    f, base, mut, leak = _leaky_finding(camp)
    reproduce.verify(camp, "differential_cross_account", "api.acme.example", base, mut,
                     trials=2, fetch=leak, finding_id=f.id)
    g = confirm_scope(camp, f.id)
    ev = g.evidence["IN_SCOPE"]
    assert ev["policy_version"] == finding._policy_version(camp)
    assert ev["asset"] == "api.acme.example" and ev["experiment_verdict"].startswith("ALLOW")


def test_boundary_confirmed_requires_boundary_evidence(camp):
    f, base, mut, leak = _leaky_finding(camp)
    reproduce.verify(camp, "differential_cross_account", "api.acme.example", base, mut,
                     trials=2, fetch=leak, finding_id=f.id)
    confirm_scope(camp, f.id)
    g = confirm_boundary(camp, f.id)
    ev = g.evidence["BOUNDARY_CONFIRMED"]
    assert ev["confirmed"] and ev["boundary_type"] == "OWNER_NONOWNER"
    assert len(ev["evidence_refs"]) == 3


def test_boundary_refused_when_enforced(camp):
    # a server that enforces: non-owner denied -> no boundary -> confirm_boundary refuses
    a = Identity(name="user_a", researcher_owned=True, credential_ref="A_TOK")
    b = Identity(name="user_b", researcher_owned=True, credential_ref="B_TOK")
    base = Variant(a, method="GET", path="/api/orders/5", resource="order-1", owner=a)
    mut = Variant(b, method="GET", path="/api/orders/5", resource="order-1", owner=a)
    enforced = lambda m, u, h, bdy: ((200 if h.get("Authorization", "").endswith("tok-a") else 403), {}, "{}")
    # this classifies secure, so it won't even promote — assert that directly
    r = run(camp, "differential_cross_account", "api.acme.example", base, mut, fetch=enforced)
    assert r.classification == "secure"
    assert promote(camp, next(e for e in camp.experiments() if e["id"] == r.experiment_id)) is None


def test_impact_confirmed_requires_demonstrated_impact(camp):
    # a granted GET that returns an EMPTY body: boundary confirmed, but no demonstrated impact
    f, base, mut, leak = _leaky_finding(camp, body="")
    reproduce.verify(camp, "differential_cross_account", "api.acme.example", base, mut,
                     trials=2, fetch=leak, finding_id=f.id)
    confirm_scope(camp, f.id)
    confirm_boundary(camp, f.id)
    with pytest.raises(ValueError, match="no demonstrated impact"):
        confirm_impact(camp, f.id)
    assert finding._get(camp, f.id).state == "BOUNDARY_CONFIRMED"


def test_dedupe_checked_requires_a_result(camp):
    f, base, mut, leak = _leaky_finding(camp)
    reproduce.verify(camp, "differential_cross_account", "api.acme.example", base, mut,
                     trials=2, fetch=leak, finding_id=f.id)
    confirm_scope(camp, f.id)
    confirm_boundary(camp, f.id)
    confirm_impact(camp, f.id)
    g = complete_dedupe(camp, f.id)
    ev = g.evidence["DUPLICATE_CHECKED"]
    assert "relation" in ev and "cluster_id" in ev


def test_report_ready_requires_every_prerequisite(camp):
    f, base, mut, leak = _leaky_finding(camp)
    reproduce.verify(camp, "differential_cross_account", "api.acme.example", base, mut,
                     trials=2, fetch=leak, finding_id=f.id)
    confirm_scope(camp, f.id)
    confirm_boundary(camp, f.id)
    confirm_impact(camp, f.id)
    complete_dedupe(camp, f.id)
    g = mark_report_ready(camp, f.id)
    assert g.state == "REPORT_READY"
    assert all(s in g.evidence for s in
               ("REPRODUCIBLE", "IN_SCOPE", "BOUNDARY_CONFIRMED", "IMPACT_CONFIRMED", "DUPLICATE_CHECKED"))
    assert [d["id"] for d in report_ready(camp)] == [f.id]


def test_suspicious_reproduction_is_idempotent(camp):
    f, base, mut, leak = _leaky_finding(camp)
    reproduce.verify(camp, "differential_cross_account", "api.acme.example", base, mut,
                     trials=2, fetch=leak, finding_id=f.id)
    assert finding._get(camp, f.id).state == "REPRODUCIBLE"
    # verifying again is a no-op on the already-advanced finding (not OBSERVED → skip)
    reproduce.verify(camp, "differential_cross_account", "api.acme.example", base, mut,
                     trials=2, fetch=leak, finding_id=f.id)
    assert finding._get(camp, f.id).state == "REPRODUCIBLE"


def test_dismissed_is_terminal(camp):
    f, *_ = _leaky_finding(camp)
    dismiss(camp, f.id, note="dup")
    with pytest.raises(ValueError):
        mark_reproducible(camp, f.id, {"reproduced": True, "original": "suspicious",
                                       "trial_experiment_ids": []})


def test_out_of_scope_candidate_flagged_not_report_ready(camp):
    # a real OOS differential is policy-blocked (inconclusive), so a suspicious OOS candidate
    # can only arise synthetically — it is tracked but never reportable.
    f = promote(camp, {"id": "exp-oos", "technique": "differential_cross_account",
                       "host": "evil.example", "classification": "suspicious"})
    assert not f.reportable and "not in scope" in f.suppressed_reason
    assert report_ready(camp) == []


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
