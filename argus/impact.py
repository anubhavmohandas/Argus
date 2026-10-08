"""Impact assessment — the structured statement of what a finding ACTUALLY demonstrated.

This is not a severity guess. It is a conservative, evidence-backed statement of the
consequence ARGUS proved, derived from the mutation observation and the confirmed boundary:

  * a READ (GET/HEAD) that returned a non-empty body  → confidentiality: a non-owner could
    read the owner's object data.
  * a state-changing request (POST/PUT/PATCH/DELETE) that succeeded → integrity: a non-owner
    could change the owner's object state.

The spec's hard rules are enforced here, not hoped for:

  * a mere status/size difference is NOT impact — a GET that returned nothing demonstrates no
    confidentiality, and `assess` leaves `demonstrated_effects` empty, which blocks
    IMPACT_CONFIRMED.
  * the blast radius is never fabricated. The demonstration ran against researcher-controlled
    test objects (cross-account auto-execution is only approval-free when the object's owner
    is a researcher account), so impact is stated as "researcher-controlled test data", never
    "all customers", "PII exposed", or "account takeover".

occam: a deterministic read over the stored observation + the boundary evidence already on
the finding (re-derived if absent). No LLM, no severity model — the demonstrated_effects list
IS the ceiling the report prose may not exceed.
"""
from __future__ import annotations

from . import boundary as boundary_mod, differential, resource as resource_mod

_STATE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_READ_METHODS = frozenset({"GET", "HEAD"})


def _resource_type(campaign, resource_value: str) -> str:
    """The object's type from an explicit ownership assertion, if one names this value —
    never guessed from the URL here (the resource layer already did that conservatively)."""
    for o in resource_mod.ownerships(campaign):
        if o.resource_value == resource_value and o.resource_type:
            return o.resource_type
    return "unknown"


def _boundary_evidence(campaign, finding) -> dict:
    ev = getattr(finding, "evidence", {}) or {}
    return ev.get("BOUNDARY_CONFIRMED") or boundary_mod.derive(campaign, finding)


def assess(campaign, finding) -> dict:
    """Derive an ImpactAssessment from the finding's confirmed boundary + the mutation
    observation. `demonstrated_effects` is empty (impact unproven) unless a concrete
    consequence — data actually returned, or a state change that actually succeeded — is in
    the evidence. Conservative by construction: it states only what the observation shows."""
    bnd = _boundary_evidence(campaign, finding)
    base = {
        "finding_id": getattr(finding, "id", ""),
        "boundary_type": bnd.get("boundary_type", boundary_mod.UNKNOWN),
        "action": "", "resource_type": "",
        "affected_identity_role": bnd.get("owner_role", ""),
        "affected_tenant_context": (
            "cross-tenant" if bnd.get("boundary_type") == "DIFFERENT_TENANT"
            else "same-tenant" if bnd.get("owner_tenant") else "unknown"),
        "confidentiality": False, "integrity": False,
        "availability": False, "privilege": False,
        "demonstrated_effects": [], "controlled_data_only": True,
        "evidence_refs": bnd.get("evidence_refs", []), "confidence": 0.0,
        "severity_rationale": "",
    }
    if not bnd.get("confirmed"):
        base["severity_rationale"] = "no confirmed boundary — nothing demonstrated"
        return base

    exp = next((e for e in campaign.experiments() if e["id"] == finding.experiment_id), None)
    if exp is None:
        base["severity_rationale"] = "source experiment missing"
        return base
    obs = [o for o in campaign.observations() if o["experiment_id"] == exp["id"]]
    nonowner = next((o for o in obs if o["id"] != exp.get("baseline_obs")), None)
    if nonowner is None:
        base["severity_rationale"] = "mutation observation missing"
        return base

    method = (nonowner.get("request", {}).get("method") or "").upper()
    resp = nonowner.get("response", {})
    status = resp.get("status", 0)
    body_len = int(resp.get("body_len", len(resp.get("body_excerpt", "") or "")))
    rtype = _resource_type(campaign, bnd.get("resource", "")) or "object"
    base["action"], base["resource_type"] = method, rtype
    access = differential._access_outcome(status)

    effects = []
    if access == "granted" and method in _READ_METHODS and body_len > 0:
        base["confidentiality"] = True
        effects.append(
            f"non-owner {bnd.get('nonowner_identity','')} could READ researcher-controlled "
            f"{rtype} data ({body_len} bytes returned)")
    if access == "granted" and method in _STATE_METHODS:
        base["integrity"] = True
        effects.append(
            f"non-owner {bnd.get('nonowner_identity','')} could MODIFY researcher-controlled "
            f"{rtype} state ({method} returned {status})")

    base["demonstrated_effects"] = effects
    base["confidence"] = 0.85 if effects else 0.0
    if effects:
        base["severity_rationale"] = (
            "Demonstrated on researcher-controlled test objects belonging to two authorized "
            "test accounts. Real-user blast radius is NOT established by this test.")
    else:
        # a granted read with no body, or an outcome that proves access but not consequence.
        base["severity_rationale"] = (
            "boundary confirmed but no concrete consequence demonstrated — a status/size "
            "difference alone is not impact")
    return base


def demo() -> None:
    """Self-check (offline): a non-owner READ that returns a body is confidentiality impact;
    a non-owner state-changing write is integrity impact; a granted GET with an EMPTY body
    demonstrates no impact (status alone is never impact)."""
    import os
    import tempfile
    from . import campaign as campaign_mod
    from .differential import Variant, run
    from .identity import Identity

    class _F:
        def __init__(self, exp_id): self.experiment_id, self.id, self.evidence = exp_id, "f1", {}

    with tempfile.TemporaryDirectory() as tmp:
        os.environ["ARGUS_HOME"] = tmp
        os.environ["A_TOK"], os.environ["B_TOK"] = "tok-a", "tok-b"
        c = campaign_mod.create("Assets:\napi.acme.example\nRate: 9 requests/sec\n", name="Acme")
        a = Identity(name="user_a", role="customer", tenant="t1", researcher_owned=True, credential_ref="A_TOK")
        b = Identity(name="user_b", role="customer", tenant="t1", researcher_owned=True, credential_ref="B_TOK")

        # READ with a body -> confidentiality
        rb = Variant(a, method="GET", path="/orders/1", resource="order-1", owner=a)
        rm = Variant(b, method="GET", path="/orders/1", resource="order-1", owner=a)
        rr = run(c, "differential_cross_account", "api.acme.example", rb, rm,
                 fetch=lambda *x: (200, {"content-type": "application/json"}, '{"total":42}'))
        resource_mod.assert_ownership(c, resource_mod.Ownership(
            resource_type="order", resource_value="order-1", owner_identity="user_a",
            researcher_controlled=True))
        ia = assess(c, _F(rr.experiment_id))
        assert ia["confidentiality"] and not ia["integrity"], ia
        assert ia["demonstrated_effects"] and "READ" in ia["demonstrated_effects"][0]
        assert ia["resource_type"] == "order" and ia["controlled_data_only"]

        # WRITE that succeeds -> integrity
        wb = Variant(a, method="POST", path="/orders/2/cancel", resource="order-2", owner=a)
        wm = Variant(b, method="POST", path="/orders/2/cancel", resource="order-2", owner=a)
        wr = run(c, "differential_cross_account", "api.acme.example", wb, wm,
                 fetch=lambda *x: (200, {"content-type": "application/json"}, '{"cancelled":true}'))
        iw = assess(c, _F(wr.experiment_id))
        assert iw["integrity"] and "MODIFY" in iw["demonstrated_effects"][0], iw

        # GET that returns an EMPTY body -> boundary confirmed but NO impact
        eb = Variant(a, method="GET", path="/orders/3", resource="order-3", owner=a)
        em = Variant(b, method="GET", path="/orders/3", resource="order-3", owner=a)
        er = run(c, "differential_cross_account", "api.acme.example", eb, em,
                 fetch=lambda *x: (200, {}, ""))
        ie = assess(c, _F(er.experiment_id))
        assert ie["demonstrated_effects"] == [], ie
        assert "not impact" in ie["severity_rationale"]

        del os.environ["A_TOK"], os.environ["B_TOK"]
    del os.environ["ARGUS_HOME"]
    print("impact demo passed")


if __name__ == "__main__":
    demo()
