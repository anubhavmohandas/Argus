"""Deterministic research-priority engine — rank the gaps worth testing first.

Once real ResearchGaps exist (coverage.py) ARGUS must answer the hunter's actual question:
of everything unexplored, what is the single highest-value boundary to test next? This is
a transparent, deterministic scoring function — NO LLM — over the OPEN gaps. Every point a
gap scores is attributable to a named factor, so the ranking is explainable and reproducible
rather than an opaque number: the same campaign state always yields the same order.

The score is research signal, NEVER severity: a high-priority gap is "most worth looking
at", not "a vulnerability". Scoring reads only derived knowledge; it executes nothing and
never sends a request (that is the orchestrator's sole job, Phase 5).

occam: a weighted sum of signals already present on the gap + endpoint, with the component
contributions returned alongside the total. Weights are module constants, tuned by a human
who sees the breakdown — the calibration knob a minimal model needs, not a learned ranker.
The trigger to make it learned is a human repeatedly overriding the order, not a guess.
"""
from __future__ import annotations

from . import coverage, identity as identity_mod, resource as resource_mod

# path tokens that mark a sensitive action/object — a write to one of these is where real
# authorization impact concentrates. Tuned by a human reading the breakdown, not learned.
_SENSITIVE_TOKENS = {
    "admin": 12, "payment": 12, "payments": 12, "refund": 12, "refunds": 12,
    "invoice": 8, "invoices": 8, "order": 6, "orders": 6, "account": 8, "accounts": 8,
    "user": 6, "users": 6, "billing": 10, "transfer": 12, "withdraw": 12, "payout": 12,
    "delete": 8, "cancel": 6, "export": 6, "download": 4, "token": 10, "key": 8,
    "password": 10, "role": 8, "permission": 8, "settings": 4, "member": 6, "members": 6,
}
_STATE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

_W = {                                  # factor -> max points; the base is every live gap
    "base": 25,
    "state_changing": 18,
    "sensitivity": 20,                  # capped sum of token weights
    "boundary": 15,
    "actionable": 10,                   # runnable now (ALLOW*) beats needs-approval
    "confidence": 10,                   # from the gap's own confidence
    "cheap": 4,                         # fewer requests => slightly higher
}


def _sensitivity(path: str) -> int:
    toks = [t for t in path.lower().replace("{id}", "").split("/") if t]
    score = sum(_SENSITIVE_TOKENS.get(t, 0) for t in toks)
    return min(_W["sensitivity"], score)


def _boundary_points(labels: list[str]) -> int:
    # cross-tenant > anonymous-to-authenticated (missing authN) > cross-role >
    # same-role-different-identity (classic IDOR) > the rest.
    if "DIFFERENT_TENANT" in labels:
        return _W["boundary"]
    if "ANONYMOUS_TO_AUTHENTICATED" in labels:
        return 14
    if "DIFFERENT_ROLE" in labels:
        return 11
    if "SAME_ROLE_DIFFERENT_IDENTITY" in labels:
        return 9
    if "OTHER_RESEARCHER_OWNED_RESOURCE" in labels:
        return 5
    return 0


# Priority v2: a bounded, explainable nudge from VALIDATED program feedback. It can never
# dominate the signal (±_FEEDBACK_CAP) and it only moves RESEARCH ATTENTION, never scope /
# policy / approval. A boundary type the program has historically rewarded is nudged up; one
# that has historically duplicated/been informative is nudged down — so ARGUS stops leading
# the hunter back to patterns that don't pay. Needs a minimum of evidence before it moves.
_FEEDBACK_CAP = 6
_FEEDBACK_MIN_EVIDENCE = 2


def _signal_key(labels: list[str]) -> str:
    """Map a gap's boundary labels to the finding boundary_type the feedback signal is keyed
    on. Conservative — an unrecognized label falls back to the v1 OWNER_NONOWNER boundary."""
    if "DIFFERENT_TENANT" in labels:
        return "DIFFERENT_TENANT"
    if "DIFFERENT_ROLE" in labels:
        return "DIFFERENT_ROLE"
    return "OWNER_NONOWNER"


def _feedback_points(labels: list[str], signal: dict | None) -> int:
    """The feedback nudge for a gap, from program-response history. 0 until there is enough
    evidence; otherwise ±_FEEDBACK_CAP scaled by how often that boundary type paid off."""
    if not signal:
        return 0
    slot = (signal.get("by_boundary_type") or {}).get(_signal_key(labels))
    if not slot or slot.get("total", 0) < _FEEDBACK_MIN_EVIDENCE:
        return 0
    total = slot["total"]
    ratio = (slot.get("valuable", 0) - slot.get("low_value", 0)) / total   # in [-1, 1]
    return round(ratio * _FEEDBACK_CAP)


def _score(gap: dict, signal: dict | None = None) -> dict:
    method = (gap.get("method") or "").upper()
    factors = {
        "base": _W["base"],
        "state_changing": _W["state_changing"] if method in _STATE_METHODS else 0,
        "sensitivity": _sensitivity(gap.get("path_template", "")),
        "boundary": _boundary_points(gap.get("boundary", []) or []),
        "actionable": _W["actionable"]
        if (gap.get("policy_preview") or {}).get("verdict", "").startswith("ALLOW") else 3,
        "confidence": round(float(gap.get("confidence", 0.0)) * _W["confidence"]),
        "cheap": max(0, _W["cheap"] - max(0, int(gap.get("estimated_requests", 2)) - 2)),
        "feedback": _feedback_points(gap.get("boundary", []) or [], signal),
    }
    total = max(0, min(100, sum(factors.values())))
    return {"priority_score": total, "priority_factors": factors}


def rank(campaign) -> list[dict]:
    """OPEN, derivable gaps scored and sorted highest-value first. Deterministic: ties break
    on gap_id so the same campaign state always yields the same order. Each gap carries its
    score and the per-factor breakdown — the ranking is explainable, not a black box. v2: a
    bounded nudge from validated program feedback (research attention only; never authority)."""
    from . import program_response
    try:
        signal = program_response.priority_signal(campaign)
    except Exception:                       # noqa: BLE001 — feedback is best-effort, never fatal
        signal = None
    live = [g for g in coverage.gaps(campaign)
            if not g.get("orphan") and g.get("status") == "OPEN"]
    scored = [{**g, **_score(g, signal)} for g in live]
    scored.sort(key=lambda g: (-g["priority_score"], g["gap_id"]))
    for i, g in enumerate(scored):
        g["priority_rank"] = i + 1
    return scored


def intel(campaign) -> dict:
    """Command Center research intelligence: deterministic coverage counts + the single
    highest-value unexplored boundary. This is DERIVED RESEARCH STATE, kept strictly separate
    from execution progress (campaign.progress) — a refreshed matrix never moves a run's
    percentage. It is not an AI recommendation; it is computed knowledge state."""
    from . import matrix
    m = matrix.build(campaign)
    cov = coverage.build(campaign)
    resources = resource_mod.resources(campaign)
    confirmed = sum(1 for o in resource_mod.ownerships(campaign)
                    if o.ownership_status == "CONFIRMED")
    ranked = rank(campaign)
    anon = identity_mod.ANONYMOUS.name
    return {
        "campaign_id": campaign.id,
        "research_coverage": {
            "endpoints": m["summary"]["endpoints"],
            "identities": m["summary"]["identities"],
            "authorization_cells_observed": m["summary"]["observed_cells"],
            "authorization_cells_possible": m["summary"]["possible_cells"],
            "research_coverage_pct": m["summary"]["research_coverage_pct"],
            "resources_known": sum(1 for r in resources if r["observed"]),
            "ownership_confirmed": confirmed,
            "open_boundary_gaps": cov["summary"]["open_gaps"],
            # label, not a security score — 90% covered != 90% secure
            "note": "research coverage, not a security score",
            "anonymous_dimension": any(c["name"] == anon for c in m["identities"]),
        },
        "highest_value_boundary": _top_card(ranked[0]) if ranked else None,
        "ranked_preview": [_top_card(g) for g in ranked[:5]],
        "workflow": workflow(campaign),
    }


def workflow(campaign) -> dict:
    """The daily-workflow counts the Command Center surfaces beyond unexplored gaps: where the
    hunter's attention is valuable right now. Purely DERIVED from existing state (findings by
    earned stage, pending approvals, suspicious experiments, duplicate clusters) — it computes
    no new analysis and runs nothing."""
    from . import dedupe, finding as finding_mod, report as report_mod
    finds = finding_mod.findings(campaign)
    def in_state(*states):
        return sum(1 for f in finds if f["state"] in states)
    # reports a triager would reject right now: reportable finding whose critic BLOCKs.
    blocked = sum(1 for r in report_mod.queue(campaign) if r["queue_status"] == "BLOCKED")
    suspicious_exps = sum(1 for e in campaign.experiments()
                          if e.get("classification") in ("suspicious", "vulnerable"))
    approvals = sum(1 for t in campaign.tasks() if t.get("state") == "APPROVAL_REQUIRED")
    clusters = dedupe.clusters(campaign)
    return {
        "open_research_gaps": sum(1 for g in coverage.gaps(campaign)
                                  if not g.get("orphan") and g.get("status") == "OPEN"),
        "experiments_awaiting_approval": approvals,
        "suspicious_observations": suspicious_exps,
        "candidates_needing_reproduction": in_state("OBSERVED"),
        "reproduced_findings": in_state("REPRODUCIBLE", "IN_SCOPE", "BOUNDARY_CONFIRMED"),
        "impact_confirmed_findings": in_state("IMPACT_CONFIRMED", "DUPLICATE_CHECKED"),
        "likely_duplicate_clusters": sum(1 for c in clusters if len(c["finding_ids"]) > 1),
        "reports_ready": sum(1 for f in finds if f["state"] == "REPORT_READY" and f["reportable"]),
        "reports_blocked": blocked,
    }


def _top_card(g: dict) -> dict:
    """The compact, operator-facing view of one ranked gap — enough to decide, not a dump."""
    return {
        "gap_id": g["gap_id"],
        "priority_rank": g.get("priority_rank"),
        "priority_score": g["priority_score"],
        "priority_factors": g["priority_factors"],
        "gap_type": g["gap_type"],
        "endpoint": f"{g.get('method', '')} {g.get('path_template', '')}".strip(),
        "host": g.get("host", ""),
        "boundary": g.get("boundary", []),
        "baseline_identity": g.get("baseline_identity", ""),
        "mutation_identity": g.get("mutation_identity", ""),
        "resource_type": g.get("resource_type", ""),
        "resource_id": g.get("resource_id", ""),
        "reason": g.get("reason", ""),
        "policy_preview": g.get("policy_preview"),
        "estimated_requests": g.get("estimated_requests"),
        "confidence": g.get("confidence"),
    }


def demo() -> None:
    """Self-check (offline): two gaps score deterministically; the state-changing, sensitive,
    cross-identity boundary outranks a bland read; the breakdown sums to the total; the intel
    summary reports research coverage (never a security score) + the top boundary."""
    import os
    import tempfile
    from . import campaign as cmod, traffic
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["ARGUS_HOME"] = tmp
        c = cmod.create("In scope:\napi.acme.example\nRate: 2 requests/sec\n", name="acme")
        for name in ("customer_a", "customer_b"):
            identity_mod.register(c, identity_mod.Identity(
                name=name, role="customer", tenant="t1", researcher_owned=True))

        # a high-value write boundary: cancelling a controlled order
        traffic.capture(c, method="POST", url="https://api.acme.example/api/refunds/5/approve",
                        headers={"Authorization": "Bearer s"}, identity="customer_a",
                        response={"status": 200})
        resource_mod.assert_ownership(c, resource_mod.Ownership(
            resource_type="refund", resource_value="5", owner_identity="customer_a",
            tenant="t1", researcher_controlled=True))
        # a bland read boundary
        traffic.capture(c, method="GET", url="https://api.acme.example/api/profile/9",
                        headers={"Authorization": "Bearer s"}, identity="customer_a",
                        response={"status": 200})
        resource_mod.assert_ownership(c, resource_mod.Ownership(
            resource_type="profile", resource_value="9", owner_identity="customer_a",
            tenant="t1", researcher_controlled=True))

        ranked = rank(c)
        assert len(ranked) == 2
        assert ranked[0]["priority_rank"] == 1 and ranked[1]["priority_rank"] == 2
        # the refund-approve write outranks the profile read
        assert "refunds" in ranked[0]["path_template"]
        assert ranked[0]["priority_score"] > ranked[1]["priority_score"]
        # the breakdown is honest — factors sum to the (pre-clamp) total
        for g in ranked:
            assert sum(g["priority_factors"].values()) in (g["priority_score"],)  # no clamp here
        # deterministic
        assert [g["gap_id"] for g in rank(cmod.load(c.id))] == [g["gap_id"] for g in ranked]

        it = intel(c)
        assert it["highest_value_boundary"]["gap_id"] == ranked[0]["gap_id"]
        assert it["research_coverage"]["note"] == "research coverage, not a security score"
        assert it["research_coverage"]["ownership_confirmed"] == 2
        assert it["research_coverage"]["open_boundary_gaps"] == 2
    del os.environ["ARGUS_HOME"]
    print("priority demo passed")


if __name__ == "__main__":
    demo()
