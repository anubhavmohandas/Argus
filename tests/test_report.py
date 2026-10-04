"""Report generation + deterministic critic. ARGUS-standalone: a submittable report is
produced with no NYX — the critic is a fixed checklist, not an LLM.
"""
import os

import pytest

from argus import campaign, finding, report
from argus.campaign import Experiment, Observation


@pytest.fixture
def camp(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_HOME", str(tmp_path))
    return campaign.create("Assets:\napi.acme.example\n", name="Acme")


def _finding_with_obs(c, host="api.acme.example", leak_body="ok"):
    exp = c.save_experiment(Experiment(
        campaign_id=c.id, hypothesis="idor?", technique="differential_cross_account",
        host=host, verdict="ALLOW_WITH_LIMITS", verdict_reason="owned",
        status="EVALUATED", classification="suspicious"))
    b = c.save_observation(Observation(
        experiment_id=exp.id, request={"method": "POST", "url": f"https://{host}/o/1", "headers": {}, "body": ""},
        response={"status": 403, "headers": {}, "body_excerpt": "nope", "body_len": 4}))
    c.save_observation(Observation(
        experiment_id=exp.id, request={"method": "POST", "url": f"https://{host}/o/1", "headers": {}, "body": ""},
        response={"status": 200, "headers": {}, "body_excerpt": leak_body, "body_len": len(leak_body)}))
    exp.baseline_obs = b.id
    c.save_experiment(exp)
    return finding.promote(c, next(e for e in c.experiments() if e["id"] == exp.id))


def _walk_to_report_ready(c, fid, reproduced=True):
    if reproduced:
        finding.advance(c, fid, "REPRODUCIBLE", note="reproduced 3/3")
    else:
        finding.advance(c, fid, "REPRODUCIBLE")   # still records the state; history note differs
    for s in ("IN_SCOPE", "BOUNDARY_CONFIRMED", "IMPACT_CONFIRMED", "DUPLICATE_CHECKED", "REPORT_READY"):
        finding.advance(c, fid, s)


def test_demo():
    report.demo()


def test_incomplete_finding_not_submittable(camp):
    f = _finding_with_obs(camp)
    r = report.generate(camp, f.id)
    assert not r.submittable
    assert any("not reproduced" in i for i in r.critic_issues)
    assert any("lifecycle incomplete" in i for i in r.critic_issues)


def test_report_ready_finding_is_submittable(camp):
    f = _finding_with_obs(camp)
    _walk_to_report_ready(camp, f.id)
    r = report.generate(camp, f.id)
    assert r.submittable and r.critic_issues == []
    assert r.reproduced
    md = report.render(r)
    assert md.startswith("# ") and "## Evidence" in md and "all checks passed" in md


def test_evidence_baseline_first(camp):
    f = _finding_with_obs(camp)
    r = report.generate(camp, f.id)
    assert [e["label"] for e in r.evidence] == ["baseline", "mutation"]
    assert r.evidence[0]["status"] == 403 and r.evidence[1]["status"] == 200


def test_leaked_secret_reported_as_impact_never_raw(camp):
    f = _finding_with_obs(camp, leak_body="token AKIAIOSFODNN7EXAMPLE here")
    _walk_to_report_ready(camp, f.id)
    r = report.generate(camp, f.id)
    md = report.render(r)
    assert r.impact_signals                              # the leak is reported
    assert "AKIAIOSFODNN7EXAMPLE" not in md              # but never rendered raw
    assert "body withheld" in md


def test_out_of_scope_never_submittable(camp):
    f = _finding_with_obs(camp, host="evil.example")
    _walk_to_report_ready(camp, f.id)
    r = report.generate(camp, f.id)
    assert not r.submittable
    assert any("NOT REPORTABLE" in i for i in r.critic_issues)


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
