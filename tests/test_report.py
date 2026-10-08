"""Reportability engine + structured report + deterministic critic. ARGUS-standalone (no
NYX). A report is assembled from earned evidence, never prose: it carries no credential
value, its reproduction steps point at real experiment records, it states expected vs
observed, and its impact text cannot exceed the structured impact evidence. The critic
BLOCKs anything that would mislead a triager.
"""
import pytest

from argus import campaign, finding, report, reproduce, resource
from argus.differential import Variant, run
from argus.identity import Identity, register


@pytest.fixture
def camp(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_HOME", str(tmp_path))
    monkeypatch.setenv("A_TOK", "tok-a")
    monkeypatch.setenv("B_TOK", "tok-b")
    return campaign.create("Assets:\napi.acme.example\nRate: 9 requests/sec\n", name="Acme")


def _promote(c, leak_body='{"total":9}', path="/api/orders/1"):
    a = Identity(name="user_a", role="customer", tenant="t1", researcher_owned=True, credential_ref="A_TOK")
    b = Identity(name="user_b", role="customer", tenant="t1", researcher_owned=True, credential_ref="B_TOK")
    register(c, a); register(c, b)
    resource.assert_ownership(c, resource.Ownership(
        resource_type="order", resource_value="order-1", owner_identity="user_a",
        researcher_controlled=True))
    base = Variant(a, method="GET", path=path, resource="order-1", owner=a)
    mut = Variant(b, method="GET", path=path, resource="order-1", owner=a)
    leak = lambda *x: (200, {"content-type": "application/json"}, leak_body)
    r = run(c, "differential_cross_account", "api.acme.example", base, mut, fetch=leak)
    f = finding.promote(c, next(e for e in c.experiments() if e["id"] == r.experiment_id))
    return f, base, mut, leak


def _earn(c, f, base, mut, leak):
    reproduce.verify(c, "differential_cross_account", "api.acme.example", base, mut,
                     trials=2, fetch=leak, finding_id=f.id)
    finding.confirm_scope(c, f.id); finding.confirm_boundary(c, f.id)
    finding.confirm_impact(c, f.id); finding.complete_dedupe(c, f.id); finding.mark_report_ready(c, f.id)


def test_demo():
    report.demo()


def test_incomplete_is_not_ready_and_critic_blocks(camp):
    f, *_ = _promote(camp)
    r = report.generate(camp, f.id)
    assert r.reportability == report.NOT_READY
    assert any("reproduced" in x for x in r.reportability_reasons)
    assert r.critic_verdict == report.BLOCK and not r.submittable


def test_report_ready_is_submittable(camp):
    f, base, mut, leak = _promote(camp)
    _earn(camp, f, base, mut, leak)
    r = report.generate(camp, f.id)
    assert r.reportability == report.REPORTABLE
    assert r.critic_verdict in (report.PASS, report.WARN) and r.submittable
    md = report.render(r)
    assert md.startswith("# ") and "## Steps to reproduce" in md


def test_no_credential_value_in_report(camp):
    f, base, mut, leak = _promote(camp)
    _earn(camp, f, base, mut, leak)
    md = report.render(report.generate(camp, f.id))
    assert "tok-a" not in md and "tok-b" not in md
    assert "Bearer tok" not in md
    # the only Authorization mention is the redacted placeholder
    for line in md.splitlines():
        if "Authorization" in line:
            assert "<redacted>" in line


def test_repro_steps_point_to_experiment_records(camp):
    f, base, mut, leak = _promote(camp)
    _earn(camp, f, base, mut, leak)
    r = report.generate(camp, f.id)
    trials = r.reproduction_status
    joined = " ".join(r.repro_steps)
    # the trial experiment ids are real records and are referenced in the steps
    repro_ev = finding._get(camp, f.id).evidence["REPRODUCIBLE"]
    real = {e["id"] for e in camp.experiments()}
    assert repro_ev["trial_experiment_ids"] and all(t in real for t in repro_ev["trial_experiment_ids"])
    assert any(t in joined for t in repro_ev["trial_experiment_ids"])
    assert trials["reproduced"]


def test_expected_vs_observed_exists(camp):
    f, base, mut, leak = _promote(camp)
    _earn(camp, f, base, mut, leak)
    r = report.generate(camp, f.id)
    assert r.expected and r.observed
    assert "denied" in r.expected.lower() and "200" in r.observed


def test_impact_text_cannot_exceed_evidence(camp):
    f, base, mut, leak = _promote(camp)
    _earn(camp, f, base, mut, leak)
    r = report.generate(camp, f.id)
    # every demonstrated-impact line is exactly the structured evidence, nothing invented
    imp = finding._get(camp, f.id).evidence["IMPACT_CONFIRMED"]["demonstrated_effects"]
    assert r.demonstrated_impact == imp


def test_critic_blocks_unsupported_severity(camp):
    f, base, mut, leak = _promote(camp)
    _earn(camp, f, base, mut, leak)
    r = report.generate(camp, f.id)
    # inject an overstated claim into the title (as a hostile/sloppy edit would) and re-critique
    r.title = "Critical account takeover via RCE affecting all customers"
    verdict, issues = report.critique(r)
    assert verdict == report.BLOCK
    assert any("overstated" in i["msg"] for i in issues)


def test_critic_blocks_missing_reproduction(camp):
    f, *_ = _promote(camp)
    r = report.generate(camp, f.id)
    assert r.critic_verdict == report.BLOCK
    assert any("not reproduced" in i["msg"] for i in r.critic_issues)


def test_report_ready_implies_no_block(camp):
    f, base, mut, leak = _promote(camp)
    _earn(camp, f, base, mut, leak)
    r = report.generate(camp, f.id)
    assert finding._get(camp, f.id).state == "REPORT_READY"
    assert r.critic_verdict != report.BLOCK


def test_leaked_secret_reported_never_raw(camp):
    f, base, mut, leak = _promote(camp, leak_body='{"key":"AKIAIOSFODNN7EXAMPLE"}')
    _earn(camp, f, base, mut, leak)
    md = report.render(report.generate(camp, f.id))
    assert "AKIAIOSFODNN7EXAMPLE" not in md
    assert "body withheld" in md


def test_out_of_scope_do_not_report(camp):
    f = finding.promote(camp, {"id": "exp-oos", "technique": "differential_cross_account",
                               "host": "evil.example", "classification": "suspicious"})
    r = report.generate(camp, f.id)
    assert r.reportability == report.DO_NOT_REPORT and not r.submittable


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
