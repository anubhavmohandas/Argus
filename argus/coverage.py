"""Ownership-aware authorization coverage + structured ResearchGaps — the third layer.

Identity × endpoint coverage (matrix.py) answers "who used this route?". This layer adds
the dimension that actually matters for authorization bugs:

    identity  ×  endpoint  ×  the OWNERSHIP of the resource that was acted on

The high-value cell is not "endpoint X never seen by identity Y"; it is "the OWNER of a
controlled object was observed performing an action on it, but no NON-OWNER was ever
observed attempting the same action on that same object". That untested owner→non-owner
boundary is where IDOR / broken-object-level-authorization lives.

A ResearchGap is MISSING RESEARCH EVIDENCE, never a finding. It is derived deterministically
from coverage, carries a stable gap_id (so re-deriving after an experiment re-attaches its
lifecycle), and quotes the policy verdict a test of it WOULD get — it never executes
anything. Only an explicit researcher-controlled (CONFIRMED) resource produces an
owner→non-owner gap: ARGUS proposes controlled experiments against the researcher's own
objects, never auto-targets a real user's data.

occam: one gap TYPE for now — OWNER_NONOWNER_UNTESTED, the spec's one meaningful boundary.
No combinatorial role/tenant fuzzing (the spec's NO RANDOM FUZZING rule). Role/tenant
relations are recorded as boundary sub-labels on the gap, not as a separate gap explosion.
Lifecycle state persists in gaps.json keyed by the deterministic gap_id, exactly as
ownership.json overlays candidates — the derivation stays pure, the state is the overlay.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
from pathlib import Path

from . import identity as identity_mod, resource, traffic

GAP_STATES = ("OPEN", "PROPOSED", "TESTED", "RESOLVED", "BLOCKED", "DISMISSED")
# method -> the policy technique a test of this endpoint would use. A write is a
# cross-account STATE change; a read is a cross-account READ — both high-risk, both gated.
_STATE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_EST_REQUESTS = 2                           # owner baseline re-observe + one non-owner attempt


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


# --- resource-aware observation index -------------------------------------
def _observation_index(campaign) -> dict[tuple[str, str, str], dict]:
    """(endpoint_id, resource_type, resource_value) -> which identities were observed acting
    on that object there, with evidence. Built in one pass over captures, reusing the resource
    layer's path-candidate extraction so the same provenance rules apply."""
    idx: dict[tuple[str, str, str], dict] = {}
    for cap in traffic.captures(campaign):
        ep_id = traffic._fingerprint(
            cap.get("method", ""), cap.get("host", ""),
            traffic.normalize_path(cap.get("path", "")))
        ikey = (cap.get("identity") or "").strip() or identity_mod.ANONYMOUS.name
        for cand in resource._path_candidates(cap):
            key = (ep_id, cand["resource_type"], cand["value"])
            cell = idx.setdefault(key, {
                "endpoint_id": ep_id, "method": cap.get("method", ""),
                "host": cap.get("host", ""),
                "path_template": traffic.normalize_path(cap.get("path", "")),
                "identities": {}})
            per = cell["identities"].setdefault(ikey, {"count": 0, "capture_refs": []})
            per["count"] += 1
            if len(per["capture_refs"]) < 5:
                per["capture_refs"].append(cap.get("id", ""))
    return idx


# --- boundary classification (only when metadata supports it) -------------
def _boundary_labels(owner: identity_mod.Identity, mut: identity_mod.Identity) -> list[str]:
    """Deterministic relationship labels between the resource owner and the mutation
    identity. Only emitted when the underlying metadata exists — unknown stays unknown,
    never guessed."""
    labels = ["OWNER_TO_NONOWNER", "OTHER_RESEARCHER_OWNED_RESOURCE"]
    if owner.role and mut.role:
        labels.append("SAME_ROLE_DIFFERENT_IDENTITY" if owner.role == mut.role else "DIFFERENT_ROLE")
    if owner.tenant and mut.tenant:
        labels.append("SAME_TENANT" if owner.tenant == mut.tenant else "DIFFERENT_TENANT")
    return labels


def _gap_id(gap_type, ep_id, baseline, mutation, rtype, rvalue) -> str:
    raw = f"{gap_type}|{ep_id}|{baseline}|{mutation}|{rtype}|{rvalue}"
    return "gap-" + hashlib.sha1(raw.encode()).hexdigest()[:12]


def _technique(method: str) -> str:
    # both read and write cross-account are the SAME policy technique (high-risk,
    # researcher-owned -> ALLOW_WITH_LIMITS single_object); method is kept as evidence.
    return "differential_cross_account"


# --- gap derivation -------------------------------------------------------
def _derive_gaps(campaign) -> list[dict]:
    idents = {i.name: i for i in identity_mod.identities(campaign)}
    # researcher-owned declared identities are the only safe mutation candidates.
    owned_names = [n for n, i in idents.items() if i.researcher_owned]
    idx = _observation_index(campaign)
    gaps: list[dict] = []

    for o in resource.ownerships(campaign):
        # only an explicit, CONFIRMED, researcher-controlled resource yields a safe gap.
        if not o.controlled_for_crossaccount():
            continue
        owner = idents.get(o.owner_identity)
        if owner is None or not owner.researcher_owned:
            continue                            # owner must be a declared researcher-owned account
        for (ep_id, rtype, rvalue), cell in idx.items():
            if rtype != o.resource_type or rvalue != o.resource_value:
                continue
            owner_obs = cell["identities"].get(o.owner_identity)
            if not owner_obs:
                continue                        # owner flow not observed here -> not this gap
            for m in owned_names:
                if m == o.owner_identity or m in cell["identities"]:
                    continue                    # self, or non-owner already observed -> no gap
                mut = idents[m]
                decision = campaign.policy.can_test(
                    cell["host"], _technique(cell["method"]), account=owner)
                conf = round(min(0.9, 0.6 + 0.3 * min(1.0, owner_obs["count"] / 3.0)), 2)
                gaps.append({
                    "gap_id": _gap_id("OWNER_NONOWNER_UNTESTED", ep_id, o.owner_identity, m,
                                      rtype, rvalue),
                    "gap_type": "OWNER_NONOWNER_UNTESTED",
                    "boundary": _boundary_labels(owner, mut),
                    "endpoint_id": ep_id, "method": cell["method"], "host": cell["host"],
                    "path_template": cell["path_template"],
                    "baseline_identity": o.owner_identity, "mutation_identity": m,
                    "resource_type": rtype, "resource_id": rvalue,
                    "ownership_context": {
                        "owner": o.owner_identity, "tenant": o.tenant,
                        "researcher_controlled": True, "ownership_status": o.ownership_status},
                    "evidence": {"owner_observations": owner_obs["count"],
                                 "owner_capture_refs": owner_obs["capture_refs"]},
                    "confidence": conf,
                    "reason": (f"owner {o.owner_identity} observed performing "
                               f"{cell['method']} on {rtype} {rvalue}; non-owner {m} "
                               f"boundary never observed"),
                    "policy_preview": {"verdict": decision.verdict.value,
                                       "reason": decision.reason, "limits": decision.limits},
                    "estimated_requests": _EST_REQUESTS,
                    "technique": _technique(cell["method"]),
                })
    gaps.sort(key=lambda g: (g["endpoint_id"], g["baseline_identity"], g["mutation_identity"],
                             g["resource_id"]))
    return gaps


def _derive_anonymous_gaps(campaign) -> list[dict]:
    """Boundary v2 — ANONYMOUS_TO_AUTHENTICATED gaps. An endpoint where a researcher-owned
    AUTHENTICATED identity was observed, but anonymous (unauthenticated) was NEVER observed:
    the authentication boundary is untested. One meaningful comparison per endpoint (the first
    authed baseline), never a combinatorial sweep.

    SAFETY — the anonymous replay only happens when there is no uncontrolled user/resource
    interaction: the baseline request touches NO object, or only researcher-controlled objects.
    An unauthenticated request is never sent at a possibly-real user's object; unknown stays a
    non-gap. This is a GAP (missing evidence), never a verdict: unobserved ≠ vulnerable."""
    idents = {i.name: i for i in identity_mod.identities(campaign)}
    owned_authed = {n: i for n, i in idents.items()
                    if i.researcher_owned and i.credential_ref and n != identity_mod.ANONYMOUS.name}
    if not owned_authed:
        return []
    controlled = {(o.resource_type, o.resource_value)
                  for o in resource.ownerships(campaign) if o.controlled_for_crossaccount()}
    seen: dict[str, dict] = {}
    for cap in traffic.captures(campaign):
        ep_id = traffic._fingerprint(cap.get("method", ""), cap.get("host", ""),
                                     traffic.normalize_path(cap.get("path", "")))
        ikey = (cap.get("identity") or "").strip() or identity_mod.ANONYMOUS.name
        cell = seen.setdefault(ep_id, {
            "endpoint_id": ep_id, "method": cap.get("method", ""), "host": cap.get("host", ""),
            "path_template": traffic.normalize_path(cap.get("path", "")),
            "identities": set(), "authed_caps": {}})
        cell["identities"].add(ikey)
        if ikey in owned_authed:
            cell["authed_caps"].setdefault(ikey, []).append(cap)

    gaps: list[dict] = []
    for ep_id, cell in seen.items():
        if identity_mod.ANONYMOUS.name in cell["identities"]:
            continue                            # anonymous already observed here -> not this gap
        authed_here = sorted(cell["authed_caps"])
        if not authed_here:
            continue                            # no researcher-owned authed baseline to replay
        baseline = authed_here[0]
        caps = cell["authed_caps"][baseline]
        cands = resource._path_candidates(caps[0])
        if any((c["resource_type"], c["value"]) not in controlled for c in cands):
            continue                            # uncontrolled object in path -> unknown, no gap
        decision = campaign.policy.can_test(cell["host"], "differential_anonymous",
                                            account=owned_authed[baseline])
        conf = round(min(0.9, 0.6 + 0.3 * min(1.0, len(caps) / 3.0)), 2)
        gaps.append({
            "gap_id": _gap_id("ANONYMOUS_TO_AUTHENTICATED", ep_id, baseline,
                              identity_mod.ANONYMOUS.name, "", ""),
            "gap_type": "ANONYMOUS_TO_AUTHENTICATED",
            "boundary": ["ANONYMOUS_TO_AUTHENTICATED"],
            "endpoint_id": ep_id, "method": cell["method"], "host": cell["host"],
            "path_template": cell["path_template"],
            "baseline_identity": baseline, "mutation_identity": identity_mod.ANONYMOUS.name,
            "resource_type": "", "resource_id": "",
            "ownership_context": {},
            "evidence": {"owner_observations": len(caps),
                         "owner_capture_refs": [c.get("id", "") for c in caps[:5]]},
            "confidence": conf,
            "reason": (f"authenticated {baseline} observed performing {cell['method']} on "
                       f"{cell['path_template']}; no anonymous request ever observed"),
            "policy_preview": {"verdict": decision.verdict.value,
                               "reason": decision.reason, "limits": decision.limits},
            "estimated_requests": _EST_REQUESTS,
            "technique": "differential_anonymous",
        })
    gaps.sort(key=lambda g: (g["endpoint_id"], g["baseline_identity"]))
    return gaps


# --- lifecycle overlay (persisted, keyed by deterministic gap_id) ---------
def _state_path(campaign) -> Path:
    return campaign.dir / "gaps.json"


def _states(campaign) -> dict[str, dict]:
    p = _state_path(campaign)
    return json.loads(p.read_text()) if p.exists() else {}


def set_gap_state(campaign, gap_id: str, status: str, *, note: str = "",
                  experiment_id: str = "", classification: str = "") -> dict:
    """Record a gap lifecycle transition (OPEN->PROPOSED->TESTED->RESOLVED/...). Keyed by the
    deterministic gap_id so re-deriving coverage re-attaches it. This is how negative tests
    are remembered — a RESOLVED/DISMISSED gap is never re-recommended."""
    if status not in GAP_STATES:
        raise ValueError(f"bad gap status {status!r}")
    states = _states(campaign)
    rec = states.get(gap_id, {})
    rec.update({"status": status, "updated_at": _now()})
    if note:
        rec["note"] = note
    if experiment_id:
        rec["experiment_id"] = experiment_id
    if classification:
        rec["classification"] = classification
    states[gap_id] = rec
    p = _state_path(campaign)
    p.touch(mode=0o600)
    p.write_text(json.dumps(states, indent=2))
    campaign.audit("gap_transition", gap=gap_id, status=status,
                   experiment=experiment_id, classification=classification)
    return rec


def gaps(campaign) -> list[dict]:
    """Derived ResearchGaps overlaid with persisted lifecycle state. A derived gap defaults
    to OPEN; a persisted transition (TESTED/RESOLVED/DISMISSED/...) overrides it. A persisted
    state whose gap is no longer derivable is kept as an orphan record (the memory of a dead
    boundary) so it is never silently re-proposed."""
    states = _states(campaign)
    out = []
    seen = set()
    for g in _derive_gaps(campaign) + _derive_anonymous_gaps(campaign):
        st = states.get(g["gap_id"])
        g = {**g, "status": (st or {}).get("status", "OPEN"),
             "lifecycle": st or {"status": "OPEN"}}
        out.append(g)
        seen.add(g["gap_id"])
    for gid, st in states.items():
        if gid not in seen:
            out.append({"gap_id": gid, "gap_type": "", "status": st.get("status", ""),
                        "orphan": True, "lifecycle": st})
    return out


def build(campaign) -> dict:
    """The authorization-coverage read model: ownership-aware gaps + a deterministic summary.
    Read-only — deriving gaps touches no target and stores nothing (only set_gap_state writes)."""
    gs = gaps(campaign)
    live = [g for g in gs if not g.get("orphan")]
    by_status: dict[str, int] = {}
    for g in gs:
        by_status[g["status"]] = by_status.get(g["status"], 0) + 1
    return {
        "campaign_id": campaign.id,
        "gaps": gs,
        "summary": {
            "total_gaps": len(gs),
            "open_gaps": sum(1 for g in gs if g["status"] == "OPEN"),
            "owner_nonowner_untested": sum(1 for g in live
                                           if g["gap_type"] == "OWNER_NONOWNER_UNTESTED"),
            "anonymous_to_authenticated": sum(1 for g in live
                                              if g["gap_type"] == "ANONYMOUS_TO_AUTHENTICATED"),
            "by_status": by_status,
        },
    }


def demo() -> None:
    """Self-check (offline): owner customer_a is observed cancelling a researcher-controlled
    order; customer_b (also researcher-owned) never is => one OWNER_NONOWNER_UNTESTED gap
    whose policy preview is ALLOW_WITH_LIMITS (both researcher-owned). The gap is OPEN; once
    marked RESOLVED it stays RESOLVED across re-derivation (the dead boundary is remembered)."""
    import os
    import tempfile
    from . import campaign as cmod
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["ARGUS_HOME"] = tmp
        c = cmod.create("In scope:\napi.acme.example\nRate: 2 requests/sec\n", name="acme")
        identity_mod.register(c, identity_mod.Identity(
            name="customer_a", role="customer", tenant="t1", researcher_owned=True))
        identity_mod.register(c, identity_mod.Identity(
            name="customer_b", role="customer", tenant="t1", researcher_owned=True))

        # owner customer_a cancels their own researcher-controlled order
        traffic.capture(c, method="POST", url="https://api.acme.example/api/orders/777/cancel",
                        headers={"Authorization": "Bearer s"}, identity="customer_a",
                        response={"status": 204})
        resource.assert_ownership(c, resource.Ownership(
            resource_type="order", resource_value="777", owner_identity="customer_a",
            tenant="t1", researcher_controlled=True))

        g = build(c)
        live = [x for x in g["gaps"] if not x.get("orphan")]
        assert len(live) == 1, live
        gap = live[0]
        assert gap["gap_type"] == "OWNER_NONOWNER_UNTESTED"
        assert gap["baseline_identity"] == "customer_a" and gap["mutation_identity"] == "customer_b"
        assert gap["resource_type"] == "order" and gap["resource_id"] == "777"
        assert "SAME_ROLE_DIFFERENT_IDENTITY" in gap["boundary"] and "SAME_TENANT" in gap["boundary"]
        assert gap["policy_preview"]["verdict"] == "ALLOW_WITH_LIMITS"   # both researcher-owned
        assert gap["status"] == "OPEN" and gap["estimated_requests"] == 2
        # the gap carries NO verdict vocabulary — it is an opportunity, not a finding
        assert "vulnerable" not in str(gap).lower()

        # a resource with NO researcher-controlled ownership produces NO owner-nonowner gap
        traffic.capture(c, method="POST", url="https://api.acme.example/api/invoices/900/void",
                        headers={"Authorization": "Bearer s"}, identity="customer_a",
                        response={"status": 204})
        assert not any(x["resource_id"] == "900" for x in build(c)["gaps"] if not x.get("orphan"))

        # lifecycle persists: mark RESOLVED, re-derive -> still RESOLVED (dead boundary remembered)
        gid = gap["gap_id"]
        set_gap_state(c, gid, "RESOLVED", classification="secure", experiment_id="exp-x")
        again = next(x for x in build(c)["gaps"] if x.get("gap_id") == gid)
        assert again["status"] == "RESOLVED" and again["lifecycle"]["classification"] == "secure"
        assert build(cmod.load(c.id))  # reload-stable

        try:
            set_gap_state(c, gid, "BOGUS")
            raise AssertionError("bad gap status accepted")
        except ValueError:
            pass
    del os.environ["ARGUS_HOME"]
    print("coverage demo passed")


if __name__ == "__main__":
    demo()
