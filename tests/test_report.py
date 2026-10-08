"""Report generation + deterministic critic. ARGUS-standalone: a submittable report is
produced with no NYX — the critic is a fixed checklist, not an LLM. Findings are earned
through the real lifecycle (reproduction + evidence-derived boundary/impact/dedupe), never
walked by fiat — that is what makes a submittable report trustworthy.
"""
import os

import pytest

from argus import campaign, finding, report, reproduce, resource
from argus.differential import Variant, run
from argus.identity import Identity, register


@pytest.fixture
def camp(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_HOME", str(tmp_path))
    monkeypatch.setenv("A_TOK", "tok-a")
    monkeypatch.setenv("B_TOK", "tok-b")
    c = campaign.create("Assets:\napi.acme.example\nRate: 9 requests/sec\n", name="Acme")
    return c


def _promote(c, host="api.acme.example", leak_body='{"total":9}', path="/api/orders/1"):
    """Run a real leaky cross-account GET differential and promote it to an OBSERVED finding,
    with the targeted order declared researcher-controlled."""
    a = Identity(name="user_a", role="customer", tenant="t1", researcher_owned=True, credential_ref="A_TOK")
    b = Identity(name="user_b", role="customer", tenant="t1", researcher_owned=True, credential_ref="B_TOK")
    register(c, a); register(c, b)
    resource.assert_ownership(c, resource.Ownership(
        resource_type="order", resource_value="order-1", owner_identity="user_a",
        researcher_controlled=True))
    base = Variant(a, method="GET", path=path, resource="order-1", owner=a)
    mut = Variant(b, method="GET", path=path, resource="order-1", owner=a)
    leak = lambda *x: (200, {"content-type": "application/json"}, leak_body)
    r = run(c, "differential_cross_account", host, base, mut, fetch=leak)
    f = finding.promote(c, next(e for e in c.experiments() if e["id"] == r.experiment_id))
    return f, base, mut, leak


def _earn_report_ready(c, f, base, mut, leak, host="api.acme.example"):
    reproduce.verify(c, "differential_cross_account", host, base, mut,
                     trials=2, fetch=leak, finding_id=f.id)
    finding.confirm_scope(c, f.id)
    finding.confirm_boundary(c, f.id)
    finding.confirm_impact(c, f.id)
    finding.complete_dedupe(c, f.id)
    finding.mark_report_ready(c, f.id)


def test_demo():
    report.demo()


def test_incomplete_finding_not_submittable(camp):
    f, *_ = _promote(camp)
    r = report.generate(camp, f.id)
    assert not r.submittable
    assert any("not reproduced" in i for i in r.critic_issues)
    assert any("lifecycle incomplete" in i for i in r.critic_issues)


def test_report_ready_finding_is_submittable(camp):
    f, base, mut, leak = _promote(camp)
    _earn_report_ready(camp, f, base, mut, leak)
    r = report.generate(camp, f.id)
    assert r.submittable and r.critic_issues == []
    assert r.reproduced
    md = report.render(r)
    assert md.startswith("# ") and "## Evidence" in md and "all checks passed" in md


def test_evidence_baseline_first(camp):
    f, *_ = _promote(camp)
    r = report.generate(camp, f.id)
    assert [e["label"] for e in r.evidence] == ["baseline", "mutation"]
    assert all(e["status"] == 200 for e in r.evidence)


def test_leaked_secret_reported_as_impact_never_raw(camp):
    f, base, mut, leak = _promote(camp, leak_body='{"key":"AKIAIOSFODNN7EXAMPLE"}')
    _earn_report_ready(camp, f, base, mut, leak)
    r = report.generate(camp, f.id)
    md = report.render(r)
    assert r.impact_signals                              # the leak is reported
    assert "AKIAIOSFODNN7EXAMPLE" not in md              # but never rendered raw
    assert "body withheld" in md


def test_out_of_scope_never_submittable(camp):
    # a real OOS differential is policy-blocked, so a suspicious OOS candidate is synthetic;
    # it is tracked but never submittable.
    f = finding.promote(camp, {"id": "exp-oos", "technique": "differential_cross_account",
                               "host": "evil.example", "classification": "suspicious"})
    r = report.generate(camp, f.id)
    assert not r.submittable
    assert any("NOT REPORTABLE" in i for i in r.critic_issues)


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
