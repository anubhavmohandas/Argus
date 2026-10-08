"""Root-cause / duplicate reasoning — cluster on the failed control point, never on a shared
200 or a similar URL. Same object family + same boundary = same root cause; a similar URL
under a DIFFERENT boundary is never a duplicate.
"""
import pytest

from argus import campaign, dedupe, finding, identity, resource
from argus.differential import Variant, run
from argus.identity import ANONYMOUS, Identity


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


_LEAK = lambda *x: (200, {"content-type": "application/json"}, '{"x":1}')


def _promote(c, method, path, actor=None):
    a = Identity(name="user_a", researcher_owned=True, credential_ref="A_TOK")
    b = actor or Identity(name="user_b", researcher_owned=True, credential_ref="B_TOK")
    r = run(c, "differential_cross_account", "api.acme.example",
            Variant(a, method=method, path=path, resource="o1", owner=a),
            Variant(b, method=method, path=path, resource="o1", owner=a), fetch=_LEAK)
    return finding.promote(c, next(e for e in c.experiments() if e["id"] == r.experiment_id))


def test_demo():
    dedupe.demo()


def test_same_family_same_boundary_clusters(camp):
    f_read = _promote(camp, "GET", "/api/orders/1")
    f_cancel = _promote(camp, "POST", "/api/orders/1/cancel")
    res = dedupe.check(camp, f_cancel)
    assert res["relation"] == dedupe.SAME_ROOT_CAUSE
    assert set(res["finding_ids"]) == {f_read.id, f_cancel.id}


def test_similar_url_different_boundary_not_duplicate(camp):
    # same orders family, but one boundary is OWNER_NONOWNER and the other is
    # ANONYMOUS_TO_AUTHENTICATED — a different boundary is never auto-merged.
    f_owner = _promote(camp, "GET", "/api/orders/1")
    f_anon = _promote(camp, "GET", "/api/orders/1", actor=ANONYMOUS)
    res = dedupe.check(camp, f_anon)
    assert f_owner.id not in res["finding_ids"]          # not merged
    assert res["relation"] in (dedupe.DISTINCT, dedupe.UNKNOWN)


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
