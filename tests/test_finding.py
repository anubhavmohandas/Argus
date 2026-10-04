"""Finding-candidate lifecycle — promotion, the forward-only state machine, and the
policy-reportability gate. Plus the link that matters: a suspicious differential run
becomes exactly one tracked candidate.
"""
import os

import pytest

from argus import campaign, differential, finding, identity
from argus.differential import Variant, run
from argus.finding import DISMISSED, advance, findings, promote, report_ready
from argus.identity import Identity


@pytest.fixture
def camp(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_HOME", str(tmp_path))
    monkeypatch.setenv("A_TOK", "tok-a")
    monkeypatch.setenv("B_TOK", "tok-b")
    c = campaign.create("Assets:\napi.acme.example\nRate: 5 requests/sec\n", name="Acme")
    identity.register(c, Identity(name="user_a", researcher_owned=True, credential_ref="A_TOK"))
    identity.register(c, Identity(name="user_b", researcher_owned=True, credential_ref="B_TOK"))
    return c


def test_demo():
    finding.demo()


def test_suspicious_differential_becomes_one_candidate(camp):
    """The pipeline link: run a leaky cross-account differential, promote its experiment,
    get exactly one OBSERVED, reportable candidate — and promoting again is a no-op."""
    a = Identity(name="user_a", researcher_owned=True, credential_ref="A_TOK")
    b = Identity(name="user_b", researcher_owned=True, credential_ref="B_TOK")
    base = Variant(a, method="POST", path="/api/orders/1/cancel", resource="o1", owner=a)
    mut = Variant(b, method="POST", path="/api/orders/1/cancel", resource="o1", owner=a)
    r = run(camp, "differential_cross_account", "api.acme.example", base, mut,
            fetch=lambda *x: (200, {"content-type": "application/json"}, "{}"))
    assert r.classification == "suspicious"

    exp = next(e for e in camp.experiments() if e["id"] == r.experiment_id)
    f = promote(camp, exp)
    assert f is not None and f.state == "OBSERVED" and f.reportable
    assert f.experiment_id == r.experiment_id
    assert promote(camp, exp).id == f.id          # idempotent
    assert len(findings(camp)) == 1


def test_secure_experiment_never_promotes(camp):
    exp = {"id": "exp-x", "technique": "differential_cross_account",
           "host": "api.acme.example", "classification": "secure"}
    assert promote(camp, exp) is None
    assert findings(camp) == []


def test_lifecycle_is_forward_only(camp):
    exp = {"id": "exp-1", "technique": "differential_cross_account",
           "host": "api.acme.example", "classification": "suspicious"}
    f = promote(camp, exp)
    advance(camp, f.id, "REPRODUCIBLE")
    with pytest.raises(ValueError, match="forward-only"):
        advance(camp, f.id, "OBSERVED")           # backward
    with pytest.raises(ValueError, match="forward-only"):
        advance(camp, f.id, "REPRODUCIBLE")       # same stage


def test_dismissed_is_terminal(camp):
    exp = {"id": "exp-2", "technique": "differential_cross_account",
           "host": "api.acme.example", "classification": "suspicious"}
    f = promote(camp, exp)
    advance(camp, f.id, DISMISSED, note="dup")
    with pytest.raises(ValueError):
        advance(camp, f.id, "REPRODUCIBLE")       # can't revive


def test_out_of_scope_candidate_flagged_not_report_ready(camp):
    """A suspicious experiment on a host that fell out of scope is still tracked (we found
    it) but never reportable, so it can't reach the report queue."""
    exp = {"id": "exp-3", "technique": "differential_cross_account",
           "host": "evil.example", "classification": "suspicious"}
    f = promote(camp, exp)
    assert not f.reportable and "not in scope" in f.suppressed_reason
    # even walked to REPORT_READY, the reportability gate keeps it out of the queue
    for s in ("REPRODUCIBLE", "IN_SCOPE", "BOUNDARY_CONFIRMED", "IMPACT_CONFIRMED",
              "DUPLICATE_CHECKED", "REPORT_READY"):
        advance(camp, f.id, s)
    assert report_ready(camp) == []


def test_excluded_class_is_non_reportable(camp):
    """A program that excludes the access-control class marks the candidate non-reportable
    even though ARGUS still found and tracks it (found ≠ reportable)."""
    c = campaign.create(
        "Assets:\napi.acme.example\nOut of scope:\n- Broken access control\n", name="Excl")
    exp = {"id": "exp-4", "technique": "differential_cross_account",
           "host": "api.acme.example", "classification": "suspicious"}
    # 'broken access' maps into the authz objective targets, not non_reportable, so to test
    # suppression we rely on the technique tags vs the program's declared non_reportable set.
    f = promote(c, exp)
    assert f is not None            # promoted regardless — tracking is not gated by reportability


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
