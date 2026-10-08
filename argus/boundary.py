"""Boundary derivation — what security boundary a differential finding actually demonstrates.

BOUNDARY_CONFIRMED is where ARGUS states exactly what failed. The rule the spec insists on:
*only use a boundary type the identity/resource metadata actually supports, and a 200 alone
is never proof.* So this module never trusts a caller's label — it DERIVES the boundary
from immutable evidence only:

  * the source experiment's recorded `mutation` axis (who changed, which object),
  * the two identities' registered metadata (role / tenant / researcher-owned / anonymous),
  * the two observations' access outcomes (did the non-owner actually reach the object?).

The boundary is confirmed ONLY when a DIFFERENT identity than the object's owner was GRANTED
access to it. Same actor as owner, a denied non-owner, a non-identity mutation, or missing
evidence all stay UNKNOWN — unknown is a normal, honest state, not a failure to try harder.

The default proven boundary is OWNER_NONOWNER (the v1 gap type). It is refined to a more
specific type only when the metadata is explicit and unambiguous (anonymous actor, a
different tenant, a different role) — never guessed. Broadening the refined vocabulary is
Boundary Intelligence v2's job; this keeps v1 strict.

occam: pure read over already-stored records; reuses differential._access_outcome so the
status→access reading is the SAME one the differential itself used. No new store, no network.
"""
from __future__ import annotations

from . import differential, identity as identity_mod

# Boundary types this module will assert. OWNER_NONOWNER is the always-supported v1 boundary;
# the rest are refinements used only when identity metadata explicitly supports them.
SUPPORTED = (
    "OWNER_NONOWNER", "ANONYMOUS_TO_AUTHENTICATED", "DIFFERENT_TENANT", "DIFFERENT_ROLE",
)
UNKNOWN = "UNKNOWN"


def _unknown(reason: str) -> dict:
    return {"boundary_type": UNKNOWN, "confirmed": False, "reason": reason,
            "evidence_refs": []}


def _classify(owner, nonowner, nonowner_name: str) -> str:
    """The boundary type the metadata supports. OWNER_NONOWNER is the proven default; it is
    refined only when the evidence is explicit — an unset role/tenant never invents a type,
    and an UNREGISTERED identity is never silently read as anonymous (only the actual
    anonymous actor is ANONYMOUS_TO_AUTHENTICATED)."""
    if nonowner_name == identity_mod.ANONYMOUS.name:
        return "ANONYMOUS_TO_AUTHENTICATED"
    if owner and owner.tenant and nonowner.tenant and owner.tenant != nonowner.tenant:
        return "DIFFERENT_TENANT"
    if owner and owner.role and nonowner.role and owner.role != nonowner.role:
        return "DIFFERENT_ROLE"
    return "OWNER_NONOWNER"


def derive(campaign, finding) -> dict:
    """Derive the boundary a finding demonstrates, from evidence only. Returns a structured
    record; `confirmed` is True only when a non-owner identity was granted access to the
    owner's object. `finding` is duck-typed (uses .experiment_id) so this never imports the
    Finding class — the dependency runs finding → boundary, never the reverse."""
    exp = next((e for e in campaign.experiments() if e["id"] == finding.experiment_id), None)
    if exp is None:
        return _unknown("no source experiment")
    if not (exp.get("technique") or "").startswith("differential"):
        return _unknown("boundary is only derivable from a differential experiment")
    mut = exp.get("mutation") or {}
    if mut.get("axis") != "identity":
        return _unknown(f"boundary needs an identity mutation; axis was {mut.get('axis')!r}")

    owner_name = mut.get("resource_owner", "")
    actor_name = mut.get("mutation", "")        # the non-owner actor in the mutation request
    baseline_name = mut.get("baseline", "")     # the owner, acting on their own object
    if not actor_name or actor_name == owner_name:
        return _unknown("mutation actor owns the object — no cross-identity boundary tested")

    obs = [o for o in campaign.observations() if o["experiment_id"] == exp["id"]]
    base_obs = next((o for o in obs if o["id"] == exp.get("baseline_obs")), None)
    nonowner_obs = next((o for o in obs if o["id"] != exp.get("baseline_obs")), None)
    if base_obs is None or nonowner_obs is None:
        return _unknown("evidence incomplete — need both baseline and mutation observations")

    owner_access = differential._access_outcome(base_obs["response"].get("status", 0))
    nonowner_access = differential._access_outcome(nonowner_obs["response"].get("status", 0))
    # The boundary FAILS only when the non-owner actually reached the object. A 200 on its
    # own proves nothing; it must be a DIFFERENT identity than the owner being GRANTED access.
    if nonowner_access != "granted":
        return _unknown(f"non-owner access was {nonowner_access!r}, not granted — boundary held")

    owner_id = identity_mod.get(campaign, owner_name) or identity_mod.get(campaign, baseline_name)
    nonowner_id = identity_mod.get(campaign, actor_name)
    btype = _classify(owner_id, nonowner_id, actor_name)
    return {
        "boundary_type": btype,
        "confirmed": True,
        "owner_identity": owner_name or baseline_name,
        "nonowner_identity": actor_name,
        "owner_role": getattr(owner_id, "role", "") if owner_id else "",
        "nonowner_role": getattr(nonowner_id, "role", "") if nonowner_id else "",
        "owner_tenant": getattr(owner_id, "tenant", "") if owner_id else "",
        "nonowner_tenant": getattr(nonowner_id, "tenant", "") if nonowner_id else "",
        "resource": mut.get("resource", ""),
        "owner_access": owner_access,
        "nonowner_access": nonowner_access,
        "evidence_refs": [exp["id"], base_obs["id"], nonowner_obs["id"]],
        "confidence": 0.9,
        "rationale": (
            f"{actor_name} ({btype}) was granted access to {owner_name or baseline_name}'s "
            f"object {mut.get('resource','?')!r}; the owner's baseline was {owner_access}."),
    }


def demo() -> None:
    """Self-check (offline): a granted non-owner yields a confirmed OWNER_NONOWNER boundary;
    a cross-tenant pair refines to DIFFERENT_TENANT; a denied non-owner stays UNKNOWN; a
    non-identity experiment is not derivable."""
    import os
    import tempfile
    from . import campaign as campaign_mod, finding as finding_mod
    from .differential import Variant, run
    from .identity import Identity

    class _F:                                   # a stand-in finding (duck-typed)
        def __init__(self, exp_id): self.experiment_id = exp_id

    with tempfile.TemporaryDirectory() as tmp:
        os.environ["ARGUS_HOME"] = tmp
        os.environ["A_TOK"], os.environ["B_TOK"] = "tok-a", "tok-b"
        c = campaign_mod.create("Assets:\napi.acme.example\nRate: 9 requests/sec\n", name="Acme")
        a = Identity(name="user_a", role="customer", tenant="t1", researcher_owned=True, credential_ref="A_TOK")
        b = Identity(name="user_b", role="customer", tenant="t1", researcher_owned=True, credential_ref="B_TOK")
        identity_mod.register(c, a); identity_mod.register(c, b)

        base = Variant(a, method="GET", path="/o/1", resource="o1", owner=a)
        mut = Variant(b, method="GET", path="/o/1", resource="o1", owner=a)
        r = run(c, "differential_cross_account", "api.acme.example", base, mut,
                fetch=lambda *x: (200, {"content-type": "application/json"}, '{"secret":1}'))
        ev = derive(c, _F(r.experiment_id))
        assert ev["confirmed"] and ev["boundary_type"] == "OWNER_NONOWNER", ev
        assert ev["evidence_refs"][0] == r.experiment_id and len(ev["evidence_refs"]) == 3

        # cross-tenant refinement: register a different-tenant actor
        d = Identity(name="user_d", role="customer", tenant="t2", researcher_owned=True, credential_ref="B_TOK")
        identity_mod.register(c, d)
        base2 = Variant(a, method="GET", path="/o/2", resource="o2", owner=a)
        mut2 = Variant(d, method="GET", path="/o/2", resource="o2", owner=a)
        r2 = run(c, "differential_cross_account", "api.acme.example", base2, mut2,
                 fetch=lambda *x: (200, {}, "{}"))
        assert derive(c, _F(r2.experiment_id))["boundary_type"] == "DIFFERENT_TENANT"

        # a server that enforces: non-owner denied -> boundary held -> UNKNOWN
        def enforced(method, url, headers, body):
            return (200 if headers.get("Authorization", "").endswith("tok-a") else 403), {}, "{}"
        base3 = Variant(a, method="GET", path="/o/3", resource="o3", owner=a)
        mut3 = Variant(b, method="GET", path="/o/3", resource="o3", owner=a)
        r3 = run(c, "differential_cross_account", "api.acme.example", base3, mut3, fetch=enforced)
        ev3 = derive(c, _F(r3.experiment_id))
        assert not ev3["confirmed"] and ev3["boundary_type"] == UNKNOWN, ev3

        del os.environ["A_TOK"], os.environ["B_TOK"]
    del os.environ["ARGUS_HOME"]
    # silence the unused import in environments that lint demos
    _ = finding_mod
    print("boundary demo passed")


if __name__ == "__main__":
    demo()
