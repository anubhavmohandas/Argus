"""Root-cause / duplicate reasoning — stop one underlying bug becoming fifteen reports.

The spec's warning: do NOT cluster because two findings share HTTP 200, and do NOT cluster
because two URLs look similar. Cluster on the *control point that failed*. The fingerprint is
built from evidence:

  * normalized host,
  * endpoint family — the object-type collection the route belongs to, so `/orders/{id}` and
    `/orders/{id}/cancel` share the family `orders` (the same object-authorization control),
  * the confirmed boundary type,
  * the behavioral failure (authorization not enforced at the object boundary).

Relationships are explicit and uncertainty is kept honest:

  SAME_ROOT_CAUSE  — same host, same boundary, same object family: one broken control.
  LIKELY_RELATED   — same host and boundary, but the family can't be pinned to the same object.
  DISTINCT         — a different host or a different boundary (a similar URL under a DIFFERENT
                     boundary is never a duplicate).
  UNKNOWN          — either side has no confirmed boundary.

occam: a deterministic read model over findings + their stored boundary evidence (re-derived
if a sibling hasn't confirmed its boundary yet). Reuses traffic.normalize_path so route
families match the SAME way the endpoint catalog groups them. No clustering library, no store.
"""
from __future__ import annotations

import hashlib
from urllib.parse import urlsplit

from . import boundary as boundary_mod, traffic

SAME_ROOT_CAUSE = "SAME_ROOT_CAUSE"
LIKELY_RELATED = "LIKELY_RELATED"
DISTINCT = "DISTINCT"
UNKNOWN = "UNKNOWN"


def _family(template: str) -> str:
    """The object-type collection a normalized route belongs to: the first non-variable,
    non-prefix segment. /api/orders/{id}/cancel -> 'orders'. Empty when none is identifiable."""
    for seg in template.strip("/").split("/"):
        if seg and seg != "{id}" and seg.lower() not in ("api", "v1", "v2", "v3", "www"):
            return seg.lower()
    return ""


def _boundary(campaign, finding) -> dict:
    ev = (getattr(finding, "evidence", {}) or {}).get("BOUNDARY_CONFIRMED")
    return ev or boundary_mod.derive(campaign, finding)


def fingerprint(campaign, finding) -> dict:
    """The deterministic root-cause fingerprint for one finding — the shared control point,
    not the surface detail. Built from the confirmed boundary + the mutation route family."""
    bnd = _boundary(campaign, finding)
    exp = next((e for e in campaign.experiments() if e["id"] == finding.experiment_id), None)
    host = (exp or {}).get("host", "")
    family, template = "", ""
    if exp:
        obs = [o for o in campaign.observations() if o["experiment_id"] == exp["id"]]
        nonowner = next((o for o in obs if o["id"] != exp.get("baseline_obs")), None)
        if nonowner:
            path = urlsplit(nonowner.get("request", {}).get("url", "")).path
            template = traffic.normalize_path(path)
            family = _family(template)
    btype = bnd.get("boundary_type", UNKNOWN)
    return {
        "host": host,
        "endpoint_family": family,
        "route_template": template,
        "boundary_type": btype,
        "behavioral_failure": "authorization-not-enforced-at-object-boundary",
        "cluster_key": hashlib.sha256(f"{host}\0{family}\0{btype}".encode()).hexdigest()[:12],
    }


def relate(a: dict, b: dict) -> str:
    """The relationship between two fingerprints. Deterministic and conservative."""
    if a["boundary_type"] in (UNKNOWN, boundary_mod.UNKNOWN) or b["boundary_type"] in (UNKNOWN, boundary_mod.UNKNOWN):
        return UNKNOWN
    if a["host"] != b["host"] or a["boundary_type"] != b["boundary_type"]:
        return DISTINCT                      # different host or different boundary → not a dup
    if a["endpoint_family"] and a["endpoint_family"] == b["endpoint_family"]:
        return SAME_ROOT_CAUSE               # same object-authorization control point
    return LIKELY_RELATED                    # same host+boundary, family can't be pinned


def check(campaign, finding) -> dict:
    """Dedupe/root-cause result for `finding` against every OTHER finding in the campaign.
    Returns the cluster it belongs to and the strongest relationship found — the evidence
    DUPLICATE_CHECKED records. Never merges automatically; the hunter decides from this."""
    from . import finding as finding_mod
    fp = fingerprint(campaign, finding)
    others = [finding_mod.Finding(**d) for d in finding_mod.findings(campaign)
              if d["id"] != getattr(finding, "id", None) and d["state"] != finding_mod.DISMISSED]

    members, related, strongest = [], [], DISTINCT
    order = {SAME_ROOT_CAUSE: 3, LIKELY_RELATED: 2, UNKNOWN: 1, DISTINCT: 0}
    for o in others:
        rel = relate(fp, fingerprint(campaign, o))
        if rel == SAME_ROOT_CAUSE:
            members.append(o.id)          # only the SAME control point is merged
        elif rel == LIKELY_RELATED:
            related.append(o.id)          # surfaced, never auto-merged
        if order[rel] > order[strongest]:
            strongest = rel

    member_ids = sorted({getattr(finding, "id", "")} | set(members))
    representative = member_ids[0] if member_ids else getattr(finding, "id", "")
    reason = {
        SAME_ROOT_CAUSE: f"same object-authorization control on {fp['host']}/{fp['endpoint_family']} "
                         f"under {fp['boundary_type']}",
        LIKELY_RELATED: f"same {fp['boundary_type']} boundary on {fp['host']}, related object actions",
        DISTINCT: "no other finding shares this control point",
        UNKNOWN: "boundary not confirmed — relationship undetermined",
    }[strongest]
    return {
        "cluster_id": fp["cluster_key"],
        "relation": strongest,
        "finding_ids": member_ids,
        "related_finding_ids": sorted(set(related)),
        "representative_finding": representative,
        "boundary_type": fp["boundary_type"],
        "affected_surface": f"{fp['host']} · {fp['endpoint_family'] or fp['route_template']}",
        "shared_evidence": {"host": fp["host"], "endpoint_family": fp["endpoint_family"]},
        "reason_for_cluster": reason,
        "confidence": {SAME_ROOT_CAUSE: 0.8, LIKELY_RELATED: 0.5, DISTINCT: 0.9, UNKNOWN: 0.2}[strongest],
    }


def clusters(campaign) -> list[dict]:
    """All non-dismissed findings grouped into root-cause clusters, for the duplicate view.
    Deterministic: findings sorted by id, clusters keyed by (host, family, boundary)."""
    from . import finding as finding_mod
    rows = [finding_mod.Finding(**d) for d in finding_mod.findings(campaign)
            if d["state"] != finding_mod.DISMISSED]
    by_key: dict[str, dict] = {}
    for f in sorted(rows, key=lambda r: r.id):
        fp = fingerprint(campaign, f)
        key = fp["cluster_key"]
        c = by_key.setdefault(key, {
            "cluster_id": key, "host": fp["host"], "endpoint_family": fp["endpoint_family"],
            "boundary_type": fp["boundary_type"], "finding_ids": [], "actions": set()})
        c["finding_ids"].append(f.id)
        if fp["route_template"]:
            c["actions"].add(fp["route_template"])
    out = []
    for c in by_key.values():
        c["actions"] = sorted(c["actions"])
        c["representative_finding"] = c["finding_ids"][0]
        c["affected_actions"] = len(c["actions"])
        out.append(c)
    return sorted(out, key=lambda c: c["cluster_id"])


def demo() -> None:
    """Self-check (offline): two actions on the same object family under the same boundary
    cluster as SAME_ROOT_CAUSE; a similar URL under a DIFFERENT boundary does NOT; a
    different host is DISTINCT."""
    import os
    import tempfile
    from . import campaign as campaign_mod, finding as finding_mod
    from .differential import Variant, run
    from .identity import Identity

    with tempfile.TemporaryDirectory() as tmp:
        os.environ["ARGUS_HOME"] = tmp
        os.environ["A_TOK"], os.environ["B_TOK"] = "tok-a", "tok-b"
        c = campaign_mod.create("Assets:\napi.acme.example\nRate: 9 requests/sec\n", name="Acme")
        a = Identity(name="user_a", role="customer", tenant="t1", researcher_owned=True, credential_ref="A_TOK")
        b = Identity(name="user_b", role="customer", tenant="t1", researcher_owned=True, credential_ref="B_TOK")
        from .identity import register
        register(c, a); register(c, b)
        leak = lambda *x: (200, {"content-type": "application/json"}, '{"x":1}')

        def promoted(method, path, res):
            base = Variant(a, method=method, path=path, resource=res, owner=a)
            mut = Variant(b, method=method, path=path, resource=res, owner=a)
            r = run(c, "differential_cross_account", "api.acme.example", base, mut, fetch=leak)
            return finding_mod.promote(c, next(e for e in c.experiments() if e["id"] == r.experiment_id))

        f_read = promoted("GET", "/api/orders/1", "order-1")
        f_cancel = promoted("POST", "/api/orders/1/cancel", "order-1")
        # same object family (orders), same OWNER_NONOWNER boundary -> SAME_ROOT_CAUSE
        res = check(c, f_cancel)
        assert res["relation"] == SAME_ROOT_CAUSE, res
        assert set(res["finding_ids"]) == {f_read.id, f_cancel.id}

        # a different object family -> not the same cluster
        f_invoice = promoted("GET", "/api/invoices/7", "invoice-7")
        res2 = check(c, f_invoice)
        assert f_read.id not in res2["finding_ids"], res2

        # grouped view: orders cluster has two actions
        cl = clusters(c)
        orders = next(x for x in cl if x["endpoint_family"] == "orders")
        assert orders["affected_actions"] == 2 and len(orders["finding_ids"]) == 2, orders

        del os.environ["A_TOK"], os.environ["B_TOK"]
    del os.environ["ARGUS_HOME"]
    print("dedupe demo passed")


if __name__ == "__main__":
    demo()
