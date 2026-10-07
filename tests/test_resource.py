"""Resource / object knowledge — pins the second research-memory layer's semantics.

A resource CANDIDATE is mined from captured traffic (a projection, provenance retained).
An ownership ASSERTION is explicit, durable, operator-entered trusted metadata. The
security invariant is absolute: researcher_controlled is NEVER inferred; an INFERRED
assertion can never authorize a cross-account test; an unattributed resource is UNKNOWN,
and unknown is a normal state, never a guess or a warning.
"""
import pytest

from argus import campaign as cmod, resource, traffic


@pytest.fixture
def camp(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_HOME", str(tmp_path))
    return cmod.create("In scope:\napi.acme.example\n", name="acme")


def _cap(c, path, ident="customer_a", status=200):
    traffic.capture(c, method="GET", url=f"https://api.acme.example{path}",
                    headers={"Authorization": "Bearer s"}, identity=ident,
                    response={"status": status})


def test_path_param_candidate_retains_provenance(camp):
    _cap(camp, "/api/orders/123")
    cand = {(x["resource_type"], x["value"]): x for x in resource.candidates(camp)}
    order = cand[("order", "123")]
    assert order["sources"] == ["path parameter"]
    assert order["fields"] == ["order_id"] and order["confidence"] == "medium"
    assert order["endpoint_refs"] and order["observations"] == 1


def test_prefixed_id_is_a_candidate(camp):
    _cap(camp, "/api/invoices/inv_918")
    cand = {(x["resource_type"], x["value"]): x for x in resource.candidates(camp)}
    assert ("invoice", "inv_918") in cand


def test_opaque_id_stays_unknown_type(camp):
    # no collection segment precedes the id -> type is UNKNOWN, never hallucinated
    _cap(camp, "/507f1f77bcf86cd799439011")
    cand = {(x["resource_type"], x["value"]): x for x in resource.candidates(camp)}
    assert ("unknown", "507f1f77bcf86cd799439011") in cand


def test_plain_word_segment_is_not_a_resource(camp):
    # a route action like /cancel must never be mined as a resource (no false positives)
    _cap(camp, "/api/orders/123/cancel")
    values = {x["value"] for x in resource.candidates(camp)}
    assert "cancel" not in values and "123" in values


def test_unknown_owner_is_never_researcher_controlled(camp):
    _cap(camp, "/api/orders/123")
    row = {(r["resource_type"], r["value"]): r for r in resource.resources(camp)}[("order", "123")]
    assert row["ownership_status"] == "" and row["owner_known"] is False
    assert row["researcher_controlled"] is False


def test_explicit_confirmed_ownership_is_represented(camp):
    _cap(camp, "/api/orders/123")
    resource.assert_ownership(camp, resource.Ownership(
        resource_type="order", resource_value="123", owner_identity="customer_a",
        tenant="tenant_a", researcher_controlled=True))
    row = {(r["resource_type"], r["value"]): r for r in resource.resources(camp)}[("order", "123")]
    assert row["researcher_controlled"] and row["owner_identity"] == "customer_a"
    assert row["tenant"] == "tenant_a" and row["ownership_status"] == "CONFIRMED"
    assert resource.ownership_for(camp, "order", "123").controlled_for_crossaccount()


def test_inferred_ownership_cannot_be_controlled(camp):
    own = resource.Ownership(
        resource_type="order", resource_value="999", owner_identity="customer_b",
        researcher_controlled=True, ownership_status="INFERRED", confidence=0.72,
        source="inferred")
    assert own.researcher_controlled is False            # forced at construction
    assert not own.controlled_for_crossaccount()
    resource.assert_ownership(camp, own)
    row = {(r["resource_type"], r["value"]): r for r in resource.resources(camp)}[("order", "999")]
    assert row["researcher_controlled"] is False and row["ownership_status"] == "INFERRED"


def test_bad_assertions_rejected_at_boundary(camp):
    for bad in (
        lambda: resource.Ownership(resource_type="o", resource_value="  "),
        lambda: resource.Ownership(resource_type="o", resource_value="x", ownership_status="MAYBE"),
        lambda: resource.Ownership(resource_type="o", resource_value="x", confidence=2.0),
    ):
        with pytest.raises(ValueError):
            bad()


def test_assertion_about_unseen_resource_still_surfaces(camp):
    # an ARGUS-created / operator-declared resource no capture referenced yet is honest:
    # it appears with observed=False, not hidden.
    resource.assert_ownership(camp, resource.Ownership(
        resource_type="order", resource_value="created_1", owner_identity="customer_a",
        researcher_controlled=True, source="created"))
    row = {(r["resource_type"], r["value"]): r for r in resource.resources(camp)}[("order", "created_1")]
    assert row["observed"] is False and row["researcher_controlled"] is True


def test_resources_deterministic_and_read_only(camp):
    _cap(camp, "/api/orders/123")
    before = sorted(p.name for p in camp.dir.rglob("*"))
    first = resource.resources(camp)
    assert resource.resources(cmod.load(camp.id)) == first
    assert sorted(p.name for p in camp.dir.rglob("*")) == before   # mining stores nothing


def test_demo_self_check():
    resource.demo()
