"""Boundary derivation — ARGUS states exactly what failed, from evidence only. A 200 alone
never proves a boundary; only a different identity than the owner being GRANTED access does.
"""
import pytest

from argus import boundary, campaign, finding, identity, resource
from argus.differential import Variant, run
from argus.identity import Identity


@pytest.fixture
def camp(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_HOME", str(tmp_path))
    monkeypatch.setenv("A_TOK", "tok-a")
    monkeypatch.setenv("B_TOK", "tok-b")
    c = campaign.create("Assets:\napi.acme.example\nRate: 9 requests/sec\n", name="Acme")
    identity.register(c, Identity(name="user_a", role="customer", tenant="t1", researcher_owned=True, credential_ref="A_TOK"))
    identity.register(c, Identity(name="user_b", role="customer", tenant="t1", researcher_owned=True, credential_ref="B_TOK"))
    resource.assert_ownership(c, resource.Ownership(
        resource_type="order", resource_value="o1", owner_identity="user_a", researcher_controlled=True))
    return c


def _finding(c, fetch, path="/api/orders/1"):
    a = Identity(name="user_a", researcher_owned=True, credential_ref="A_TOK")
    b = Identity(name="user_b", researcher_owned=True, credential_ref="B_TOK")
    r = run(c, "differential_cross_account", "api.acme.example",
            Variant(a, method="GET", path=path, resource="o1", owner=a),
            Variant(b, method="GET", path=path, resource="o1", owner=a), fetch=fetch)
    return finding.promote(c, next(e for e in c.experiments() if e["id"] == r.experiment_id)), r


def test_demo():
    boundary.demo()


def test_granted_nonowner_is_owner_nonowner(camp):
    f, _ = _finding(camp, lambda *x: (200, {"content-type": "application/json"}, '{"x":1}'))
    ev = boundary.derive(camp, f)
    assert ev["confirmed"] and ev["boundary_type"] == "OWNER_NONOWNER"
    assert ev["nonowner_access"] == "granted" and len(ev["evidence_refs"]) == 3


def test_status_alone_is_not_a_boundary(camp):
    # identical 200s for a request where the ACTOR owns the object is not cross-identity →
    # boundary stays UNKNOWN (a 200 on its own proves nothing).
    a = Identity(name="user_a", researcher_owned=True, credential_ref="A_TOK")
    r = run(camp, "differential_same_account", "api.acme.example",
            Variant(a, method="GET", path="/api/orders/1", resource="o1", owner=a),
            Variant(a, method="POST", path="/api/orders/1", resource="o1", owner=a),
            fetch=lambda *x: (200, {}, "{}"))
    # same-account differential with no identity axis → not derivable as an identity boundary
    assert boundary.derive(camp, type("F", (), {"experiment_id": r.experiment_id})())["boundary_type"] == "UNKNOWN"


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
