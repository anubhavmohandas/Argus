"""Program-response memory — research memory only. SUBMITTED requires a REPORT_READY finding;
outcomes accumulate with history; the priority signal is a read-only aggregate that can never
touch scope/policy/approval.
"""
import pytest

from argus import campaign, finding, program_response, reproduce, resource
from argus.differential import Variant, run
from argus.identity import Identity, register


@pytest.fixture
def camp(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_HOME", str(tmp_path))
    monkeypatch.setenv("A_TOK", "tok-a")
    monkeypatch.setenv("B_TOK", "tok-b")
    return campaign.create("Assets:\napi.acme.example\nRate: 9 requests/sec\n", name="acme")


def _report_ready(c):
    a = Identity(name="user_a", role="customer", tenant="t1", researcher_owned=True, credential_ref="A_TOK")
    b = Identity(name="user_b", role="customer", tenant="t1", researcher_owned=True, credential_ref="B_TOK")
    register(c, a); register(c, b)
    resource.assert_ownership(c, resource.Ownership(
        resource_type="order", resource_value="order-1", owner_identity="user_a", researcher_controlled=True))
    base = Variant(a, method="GET", path="/api/orders/1", resource="order-1", owner=a)
    mut = Variant(b, method="GET", path="/api/orders/1", resource="order-1", owner=a)
    leak = lambda *x: (200, {"content-type": "application/json"}, '{"total":9}')
    r = run(c, "differential_cross_account", "api.acme.example", base, mut, fetch=leak)
    f = finding.promote(c, next(e for e in c.experiments() if e["id"] == r.experiment_id))
    reproduce.verify(c, "differential_cross_account", "api.acme.example", base, mut,
                     trials=2, fetch=leak, finding_id=f.id)
    for step in (finding.confirm_scope, finding.confirm_boundary, finding.confirm_impact,
                 finding.complete_dedupe, finding.mark_report_ready):
        step(c, f.id)
    return f


def test_demo():
    program_response.demo()


def test_submitted_requires_report_ready(camp):
    a = Identity(name="user_a", researcher_owned=True, credential_ref="A_TOK")
    b = Identity(name="user_b", researcher_owned=True, credential_ref="B_TOK")
    register(camp, a); register(camp, b)
    base = Variant(a, method="GET", path="/api/orders/1", resource="o1", owner=a)
    mut = Variant(b, method="GET", path="/api/orders/1", resource="o1", owner=a)
    r = run(camp, "differential_cross_account", "api.acme.example", base, mut,
            fetch=lambda *x: (200, {"content-type": "application/json"}, '{"x":1}'))
    f = finding.promote(camp, next(e for e in camp.experiments() if e["id"] == r.experiment_id))
    with pytest.raises(ValueError, match="not REPORT_READY"):
        program_response.record(camp, f.id, "SUBMITTED")


def test_outcomes_recorded_with_history(camp):
    f = _report_ready(camp)
    program_response.record(camp, f.id, "SUBMITTED")
    rr = program_response.record(camp, f.id, "ACCEPTED", reward="$500", notes="good")
    assert rr.outcome == "ACCEPTED" and rr.reward == "$500" and rr.submitted_at
    assert len(rr.history) == 2
    assert program_response.response(camp, f.id).outcome == "ACCEPTED"


def test_priority_signal_aggregates_value(camp):
    f = _report_ready(camp)
    program_response.record(camp, f.id, "ACCEPTED")
    sig = program_response.priority_signal(camp)
    assert sig["by_boundary_type"]["OWNER_NONOWNER"]["valuable"] == 1


def test_unknown_outcome_rejected(camp):
    f = _report_ready(camp)
    with pytest.raises(ValueError, match="unknown program outcome"):
        program_response.record(camp, f.id, "BOGUS")


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
