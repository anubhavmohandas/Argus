"""Reproducibility engine — a suspicious boundary must repeat before it's trusted.

ARGUS-standalone: reproduction is a deterministic re-run + strict stability check. No
NYX involved — a finding reaches REPRODUCIBLE on evidence alone.
"""
import os

import pytest

from argus import campaign, finding, identity, reproduce
from argus.differential import Variant, run
from argus.identity import Identity


@pytest.fixture
def camp(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_HOME", str(tmp_path))
    monkeypatch.setenv("A_TOK", "tok-a")
    monkeypatch.setenv("B_TOK", "tok-b")
    c = campaign.create("Assets:\napi.acme.example\nRate: 9 requests/sec\n", name="Acme")
    identity.register(c, Identity(name="user_a", researcher_owned=True, credential_ref="A_TOK"))
    identity.register(c, Identity(name="user_b", researcher_owned=True, credential_ref="B_TOK"))
    return c


A = Identity(name="user_a", researcher_owned=True, credential_ref="A_TOK")
B = Identity(name="user_b", researcher_owned=True, credential_ref="B_TOK")


def _pair(path="/o/1/cancel", resource="o1"):
    return (Variant(A, method="POST", path=path, resource=resource, owner=A),
            Variant(B, method="POST", path=path, resource=resource, owner=A))


def test_demo():
    reproduce.demo()


def test_stable_leak_reproduces_and_advances_finding(camp):
    base, mut = _pair()
    first = run(camp, "differential_cross_account", "api.acme.example", base, mut,
                fetch=lambda *x: (200, {}, "{}"))
    f = finding.promote(camp, next(e for e in camp.experiments() if e["id"] == first.experiment_id))

    rep = reproduce.verify(camp, "differential_cross_account", "api.acme.example", base, mut,
                           trials=3, fetch=lambda *x: (200, {}, "{}"), finding_id=f.id)
    assert rep.reproduced and len(rep.experiment_ids) == 3
    assert finding._get(camp, f.id).state == "REPRODUCIBLE"
    assert rep.finding_id == f.id


def test_flaky_target_does_not_reproduce(camp):
    base, mut = _pair("/o/2", "o2")
    g = finding.promote(camp, {"id": "e", "technique": "differential_cross_account",
                               "host": "api.acme.example", "classification": "suspicious"})
    flip = {"n": 0}

    def flaky(*x):
        flip["n"] += 1
        return (200 if flip["n"] % 2 else 403), {}, "{}"

    rep = reproduce.verify(camp, "differential_cross_account", "api.acme.example", base, mut,
                           trials=4, fetch=flaky, finding_id=g.id)
    assert not rep.reproduced
    assert finding._get(camp, g.id).state == "OBSERVED"       # not advanced on flaky evidence


def test_each_trial_is_its_own_experiment(camp):
    """Reproduction adds evidence, never overwrites it — every trial is a distinct
    policy-gated Experiment."""
    base, mut = _pair()
    before = len(camp.experiments())
    rep = reproduce.verify(camp, "differential_cross_account", "api.acme.example", base, mut,
                           trials=2, fetch=lambda *x: (200, {}, "{}"))
    assert len(camp.experiments()) == before + 2
    assert len(set(rep.experiment_ids)) == 2                  # distinct ids


def test_reproduction_still_gated_per_request(camp):
    """A reproduction trial is a real active request — it goes through can_test too. An
    out-of-scope host reproduces nothing (every trial blocked → inconclusive)."""
    base, mut = _pair()
    hits = []
    rep = reproduce.verify(camp, "differential_cross_account", "evil.example", base, mut,
                           trials=2, fetch=lambda *x: (hits.append(x) or (200, {}, "{}")))
    assert hits == [] and not rep.reproduced
    assert all(c == "inconclusive" for c in rep.classifications)


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
