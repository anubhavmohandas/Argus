"""Deterministic research planner — the hunter brain: what to test next, and when to stop.

ARGUS can already derive gaps (coverage), rank them (priority), turn one into a bounded
experiment (proposal) and execute it through the orchestrator. This module is the decision
that sits on top: of everything unexplored, what is the single highest-value SAFE next
research action — and when there is none, WHY (an honest stop reason, never "application
secure"). It is what the autonomous loop asks each cycle and what the Command Center shows a
hunter deciding where to spend the next five minutes.

Pure and read-only. It executes nothing and sends no request — the orchestrator stays the
sole executor and every per-request gate is unchanged. "Safe" here means exactly what policy
already decided: a gap whose recorded policy preview is ALLOW / ALLOW_WITH_LIMITS can run
without a human; HUMAN_APPROVAL parks for the operator; DENY is excluded. The planner never
widens that — it only chooses among already-permitted bounded experiments, which is precisely
what "autonomous within policy" is allowed to mean.

occam: "safe next action" = the top priority.rank() gap whose policy preview is ALLOW* and
whose score clears a useful-work threshold (a module constant, the calibration knob a human
tunes from the breakdown). Request budget is a PER-RUN politeness cap held by the orchestrator,
not a durable ledger, so the planner only reasons about it when the caller (the run driver)
passes the live remaining count — it never fabricates an executed-so-far number from campaign
state. Completion is honest: the terminal state is RESEARCH_EXHAUSTED, never "secure".
"""
from __future__ import annotations

from . import coverage, priority, proposal

# A safe gap must clear this to be worth a researcher's (or an autonomous cycle's) attention.
# base is 25; this keeps trivial reads from being auto-selected. Tuned by a human, not learned.
USEFUL_SCORE_THRESHOLD = 40

# Closed vocabulary of why the planner has no safe next action. Honest — none of these is
# "the application is secure"; absence of a next test is never a security verdict.
STOP_REASONS = (
    "",                                  # not stopped: a next action exists
    "no_open_gaps",                      # nothing unexplored is derivable from current knowledge
    "all_remaining_need_approval",       # open gaps exist, every one needs human approval
    "all_remaining_denied",              # open gaps exist, policy denies every one
    "below_useful_threshold",            # safe gaps exist but none clears the useful-work bar
    "budget_exhausted",                  # caller's live request budget can't afford the cheapest
)


def _verdict(gap: dict) -> str:
    return (gap.get("policy_preview") or {}).get("verdict", "")


def _safe(gap: dict) -> bool:
    return _verdict(gap).startswith("ALLOW")


def assess(campaign, *, budget_remaining: int | None = None,
           min_score: int = USEFUL_SCORE_THRESHOLD) -> dict:
    """The next-best-safe-action decision. Returns the single highest-value runnable experiment
    (as a ready proposal), the gaps parked for human approval, and — when nothing can safely
    run — an honest stop_reason. Deterministic: driven entirely by priority.rank()'s order."""
    ranked = priority.rank(campaign)
    safe = [g for g in ranked if _safe(g)]
    parked = [g for g in ranked if _verdict(g) == "HUMAN_APPROVAL"]
    denied = [g for g in ranked if _verdict(g) == "DENY"]

    chosen = None
    for g in safe:                       # ranked order: the first affordable, worthwhile one
        if g["priority_score"] < min_score:
            break                        # ranked desc — nothing after clears the bar either
        if budget_remaining is not None and budget_remaining < int(g.get("estimated_requests", 2)):
            continue                     # too expensive for what's left; try a cheaper one
        chosen = g
        break

    stop_reason = _stop_reason(ranked, safe, denied, chosen, budget_remaining, min_score)
    return {
        "campaign_id": campaign.id,
        "next_action": {
            "gap": priority._top_card(chosen),
            "proposal": proposal.build(campaign, chosen),
        } if chosen else None,
        "stopped": chosen is None,
        "stop_reason": stop_reason,
        "parked_for_approval": [priority._top_card(g) for g in parked],
        "ranked_preview": [priority._top_card(g) for g in ranked[:5]],
        "counts": {
            "open_gaps": len(ranked),
            "safe_runnable": len(safe),
            "need_approval": len(parked),
            "denied": len(denied),
        },
    }


def _stop_reason(ranked, safe, denied, chosen, budget_remaining, min_score) -> str:
    if chosen is not None:
        return ""
    if not ranked:
        return "no_open_gaps"
    if safe:
        # safe gaps exist but none was chosen: either too costly for the budget or below the bar
        if budget_remaining is not None and all(
                budget_remaining < int(g.get("estimated_requests", 2)) for g in safe):
            return "budget_exhausted"
        return "below_useful_threshold"
    if denied and not any(_verdict(g) == "HUMAN_APPROVAL" for g in ranked):
        return "all_remaining_denied"
    return "all_remaining_need_approval"


def completion(campaign, *, budget_remaining: int | None = None) -> dict:
    """The campaign operator handoff — the final hunter summary. What was mapped, what was
    tested, what was confirmed, what remains, and WHY the useful research stopped. Composed
    from the existing derived aggregates (never a parallel count), so it can never disagree
    with the surfaces the operator already sees."""
    a = assess(campaign, budget_remaining=budget_remaining)
    cov = coverage.build(campaign)["summary"]
    intel = priority.intel(campaign)["research_coverage"]
    wf = priority.workflow(campaign)
    exps = campaign.experiments()
    secure = sum(1 for e in exps if e.get("classification") == "secure")

    stopped = a["stopped"]
    return {
        "campaign_id": campaign.id,
        "mapped": {
            "assets_in_scope": len(campaign.policy.scope.include_patterns()),
            "endpoints_known": intel["endpoints"],
            "identities": intel["identities"],
            "resources_observed": intel["resources_known"],
            "ownership_confirmed": intel["ownership_confirmed"],
        },
        "researched": {
            "research_gaps_total": cov["total_gaps"],
            "open_gaps": cov["open_gaps"],
            "experiments_run": len(exps),
            "secure_boundaries_confirmed": secure,
            "suspicious_candidates": wf["suspicious_observations"],
            "reproduced_findings": wf["reproduced_findings"],
            "impact_confirmed": wf["impact_confirmed_findings"],
            "reports_ready": wf["reports_ready"],
            "reports_blocked": wf["reports_blocked"],
        },
        "remaining": {
            "untested_boundaries": a["counts"]["open_gaps"],
            "awaiting_approval": a["counts"]["need_approval"],
            "safe_runnable_now": a["counts"]["safe_runnable"],
        },
        # honest terminal state: never "secure" — only that useful research is exhausted under
        # what ARGUS currently knows. More knowledge (traffic, identities) can reopen it.
        "status": "RESEARCH_EXHAUSTED" if stopped else "RESEARCH_ACTIVE",
        "why_stopped": a["stop_reason"] if stopped else "",
        "next_action": a["next_action"],
        "research_coverage_note": "research coverage, not a security score",
    }


def demo() -> None:
    """Self-check (offline): with two safe owner->non-owner gaps the planner picks the
    highest-ranked worthwhile one and is RESEARCH_ACTIVE; a tight budget that can't afford any
    gap stops with budget_exhausted; raising the threshold above every score stops with
    below_useful_threshold; the completion handoff reports honest counts and never 'secure'."""
    import os
    import tempfile
    from . import campaign as cmod, identity as id_mod, resource as res_mod, traffic
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["ARGUS_HOME"] = tmp
        c = cmod.create("In scope:\napi.acme.example\nRate: 5 requests/sec\n", name="acme")
        for name in ("customer_a", "customer_b"):
            id_mod.register(c, id_mod.Identity(name=name, role="customer", tenant="t1",
                                               researcher_owned=True, credential_ref=""))
        traffic.capture(c, method="POST", url="https://api.acme.example/api/refunds/5/approve",
                        headers={"Authorization": "Bearer s"}, identity="customer_a",
                        response={"status": 200})
        res_mod.assert_ownership(c, res_mod.Ownership(
            resource_type="refund", resource_value="5", owner_identity="customer_a",
            tenant="t1", researcher_controlled=True))
        traffic.capture(c, method="GET", url="https://api.acme.example/api/orders/9",
                        headers={"Authorization": "Bearer s"}, identity="customer_a",
                        response={"status": 200})
        res_mod.assert_ownership(c, res_mod.Ownership(
            resource_type="order", resource_value="9", owner_identity="customer_a",
            tenant="t1", researcher_controlled=True))

        a = assess(c)
        assert a["next_action"] is not None and not a["stopped"]
        assert a["stop_reason"] == ""
        # the chosen action is the top-ranked gap and it is policy-safe (ALLOW*)
        top = priority.rank(c)[0]
        assert a["next_action"]["gap"]["gap_id"] == top["gap_id"]
        assert a["next_action"]["proposal"]["gap_id"] == top["gap_id"]
        assert a["counts"]["safe_runnable"] == a["counts"]["open_gaps"] >= 2

        # a budget that can't afford even the cheapest gap -> honest budget_exhausted stop
        broke = assess(c, budget_remaining=0)
        assert broke["stopped"] and broke["stop_reason"] == "budget_exhausted"

        # a threshold above every score -> below_useful_threshold (safe gaps exist, none worth it)
        picky = assess(c, min_score=101)
        assert picky["stopped"] and picky["stop_reason"] == "below_useful_threshold"

        # completion handoff: honest status, never "secure", counts line up with the aggregates
        done = completion(c)
        assert done["status"] == "RESEARCH_ACTIVE" and done["why_stopped"] == ""
        assert done["mapped"]["ownership_confirmed"] == 2
        assert done["remaining"]["untested_boundaries"] == a["counts"]["open_gaps"]
        assert done["research_coverage_note"] == "research coverage, not a security score"

        # an empty campaign has nothing to do, and says so honestly (not "secure")
        empty = cmod.create("In scope:\napi.empty.example\n", name="empty")
        ea = assess(empty)
        assert ea["stopped"] and ea["stop_reason"] == "no_open_gaps"
        assert completion(empty)["status"] == "RESEARCH_EXHAUSTED"
    del os.environ["ARGUS_HOME"]
    print("planner demo passed")


if __name__ == "__main__":
    demo()
