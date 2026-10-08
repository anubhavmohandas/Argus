"""Impact assessment — demonstrated consequence, never a severity guess. Confidentiality
only when protected data was actually returned; integrity only when a state change actually
succeeded; a status/size difference alone is NOT impact; real-user blast radius is never
fabricated.
"""
import pytest

from argus import campaign, finding, identity, impact, resource
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
        resource_type="order", resource_value="order-1", owner_identity="user_a", researcher_controlled=True))
    return c


def _finding(c, method, body, path):
    a = Identity(name="user_a", researcher_owned=True, credential_ref="A_TOK")
    b = Identity(name="user_b", researcher_owned=True, credential_ref="B_TOK")
    r = run(c, "differential_cross_account", "api.acme.example",
            Variant(a, method=method, path=path, resource="order-1", owner=a),
            Variant(b, method=method, path=path, resource="order-1", owner=a),
            fetch=lambda *x: (200, {"content-type": "application/json"}, body))
    return finding.promote(c, next(e for e in c.experiments() if e["id"] == r.experiment_id))


def test_demo():
    impact.demo()


def test_read_of_controlled_object_is_confidentiality(camp):
    f = _finding(camp, "GET", '{"total":42}', "/api/orders/1")
    ia = impact.assess(camp, f)
    assert ia["confidentiality"] and not ia["integrity"]
    assert "READ" in ia["demonstrated_effects"][0] and ia["resource_type"] == "order"


def test_controlled_write_is_integrity(camp):
    f = _finding(camp, "POST", '{"cancelled":true}', "/api/orders/1/cancel")
    ia = impact.assess(camp, f)
    assert ia["integrity"] and "MODIFY" in ia["demonstrated_effects"][0]


def test_status_difference_is_not_impact(camp):
    f = _finding(camp, "GET", "", "/api/orders/1")       # granted, but empty body
    ia = impact.assess(camp, f)
    assert ia["demonstrated_effects"] == [] and "not impact" in ia["severity_rationale"]


def test_blast_radius_never_fabricated(camp):
    f = _finding(camp, "GET", '{"total":42}', "/api/orders/1")
    ia = impact.assess(camp, f)
    assert ia["controlled_data_only"] is True
    blob = " ".join(ia["demonstrated_effects"]) + ia["severity_rationale"]
    for forbidden in ("all customers", "PII", "account takeover", "RCE", "critical"):
        assert forbidden.lower() not in blob.lower()
    assert "researcher-controlled" in blob


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
