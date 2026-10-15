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


def autonomous_run(campaign, orch, *, max_actions: int = 25,
                   budget_remaining: int | None = None) -> dict:
    """Bounded autonomous research loop — "autonomous within policy". Each cycle: ask the
    planner for the single highest-value SAFE action, run it through the GIVEN orchestrator,
    update knowledge (reconcile), re-assess — until the planner stops (no safe worthwhile gap)
    or max_actions is reached. Returns the action trace + the final completion handoff.

    Safety is inherited, not reinvented: it runs ONLY gaps whose policy preview is ALLOW*, and
    even then each task is re-gated by can_test inside orch.propose and every outbound request
    is re-gated again — a gap that policy re-decides as approval/deny at propose time is parked
    (BLOCKED), never auto-run. The orchestrator is the SOLE executor; this drives it, it does
    not bypass it. It proposes on the caller's orchestrator (the one that will run) so each
    cycle's task is actually drained, and the caller owns the one-execution-owner guarantee
    (don't drive an orchestrator for a campaign a coordinator is actively running).

    occam: synchronous, the same shape the golden E2E runs for one gap, generalized to a
    bounded sequence. It converges because reconcile moves every run gap out of OPEN, so the
    planner never re-picks it; max_actions is the hard backstop."""
    actions: list[dict] = []
    for _ in range(max_actions):
        decision = assess(campaign, budget_remaining=budget_remaining)
        if decision["stopped"]:
            break
        gap = decision["next_action"]["gap"]
        gap_id = gap["gap_id"]
        # use the proposal assess() already built from the FULL gap — _top_card is a trimmed
        # view and would lose the concrete request path proposal.build derives from evidence.
        prop = decision["next_action"]["proposal"]
        task = proposal.to_task(campaign, prop)
        orch.propose(task)                       # re-gate on the SAME orch that will run it
        coverage.set_gap_state(campaign, gap_id, "PROPOSED", note=f"task={task.id}")
        if not (task.verdict or "").startswith("ALLOW"):
            # policy re-decided stricter than the preview — park it, do not run, move on
            coverage.set_gap_state(campaign, gap_id, "BLOCKED", note=f"verdict {task.verdict}")
            actions.append({"gap_id": gap_id, "verdict": task.verdict, "ran": False})
            continue
        orch.run()
        rec = proposal.reconcile(campaign)
        actions.append({"gap_id": gap_id, "verdict": task.verdict, "ran": True, "reconciled": rec})
        if budget_remaining is not None:
            budget_remaining -= int(gap.get("estimated_requests", 2))
    return {"campaign_id": campaign.id, "actions": actions,
            "completion": completion(campaign, budget_remaining=budget_remaining)}


def background_autonomous(campaign, *, max_actions: int = 25,
                          budget_remaining: int | None = None):
    """Return (planner, on_complete) that drive "autonomous within policy" through a
    CampaignRunCoordinator — the SAME single-writer execution owner as a pivot/queue, not a
    new engine. planner is None (no up-front batch); on_complete is a RE-ARMABLE cycle the
    coordinator calls each time its queue drains empty:

        reconcile the finished experiment  ->  knowledge.updated
        assess the single next SAFE action ->  planner.assessed
          stopped / budget / max_actions   ->  planner.exhausted, finish (COMPLETE)
          else propose exactly ONE action  ->  planner.selected, keep looping

    Same safety as the synchronous autonomous_run: it proposes ONLY gaps assess() already
    classified ALLOW* (HUMAN_APPROVAL gaps are never auto-proposed — they stay operator-queued
    via the plan's parked list), each task is re-gated by can_test inside orch.propose, and a
    task policy re-decides stricter than its preview is cancelled + the gap BLOCKED, never run
    and never left to silently park the loop. The coordinator owns pause/resume/stop/approval;
    this only decides WHAT the next bounded experiment is. Converges because reconcile moves
    every run gap out of OPEN so it is never re-picked; max_actions is the hard backstop.

    occam: a closure over a tiny mutable counter dict, returned as the coordinator's existing
    on_complete hook — the loop's re-arm is a 2-line change in run.py, not a second runner."""
    st = {"actions": 0, "budget": budget_remaining}

    def on_complete(co) -> bool:
        rec = proposal.reconcile(co.c)                 # idempotent; a no-op on the first cycle
        if rec:
            co.c.audit("knowledge_updated", reconciled=len(rec),
                       gaps=[r.get("gap_id", "") for r in rec if isinstance(r, dict)])
        if st["actions"] >= max_actions:
            co.c.audit("planner_exhausted", reason="max_actions", actions=st["actions"])
            return False
        decision = assess(co.c, budget_remaining=st["budget"])
        co.c.audit("planner_assessed", actions=st["actions"], stopped=decision["stopped"],
                   **decision["counts"])
        if decision["stopped"]:
            co.c.audit("planner_exhausted", reason=decision["stop_reason"], actions=st["actions"])
            return False
        gap = decision["next_action"]["gap"]
        gap_id = gap["gap_id"]
        task = co.orch.propose(proposal.to_task(co.c, decision["next_action"]["proposal"]))
        coverage.set_gap_state(co.c, gap_id, "PROPOSED", note=f"task={task.id}")
        st["actions"] += 1
        if st["budget"] is not None:
            st["budget"] -= int(gap.get("estimated_requests", 2))
        if not (task.verdict or "").startswith("ALLOW"):
            # defense-in-depth re-decided stricter than the preview: cancel it (so the loop
            # does not park on an approval the operator never asked for) + mark the gap BLOCKED,
            # then re-assess — the blocked gap is out of OPEN and won't be re-picked.
            co.orch.cancel(task.id, "autonomous", "policy re-decided stricter than preview")
            coverage.set_gap_state(co.c, gap_id, "BLOCKED", note=f"verdict {task.verdict}")
            co.c.audit("planner_blocked", gap_id=gap_id, verdict=task.verdict)
            return True
        co.c.audit("planner_selected", gap_id=gap_id, endpoint=gap.get("endpoint", ""),
                   boundary=gap.get("boundary", []), reason=gap.get("reason", ""),
                   estimated_requests=gap.get("estimated_requests"), action=st["actions"])
        return True

    return None, on_complete


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
