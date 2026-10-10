"""Experiment proposals + the knowledge-update loop — closing the research loop.

This is the seam between KNOWING and DOING, and it is deliberately thin:

    ResearchGap → ExperimentProposal → (existing Orchestrator) → Observation →
    FindingCandidate → gap transition → knowledge recomputes

A proposal is a PLAN, never an execution. Nothing in this module sends an HTTP request.
Building a proposal is pure derivation over the gap + its capture evidence; executing one
means handing an orchestrator.Task to the EXISTING orchestrator/coordinator, which re-gates
it through can_test and drives the EXISTING differential runner. There is no new request
mutation engine here, and the matrix / priority / proposal layers never touch the network.

The knowledge-update loop is the other half: when an experiment the orchestrator ran
completes, its classification updates the gap. A secure result RESOLVES the gap (the
boundary is remembered as tested — a negative result is a result, never re-recommended); a
suspicious/vulnerable result promotes a FindingCandidate (via the existing finding pipeline)
and marks the gap TESTED. Either way ARGUS learns, and the same dead boundary is never
proposed twice.

occam: proposals are derived on demand from ranked gaps (no new store); the only durable
write is the gap's own lifecycle overlay (coverage.set_gap_state) + the finding pipeline's
own records. Execution reuses coordinator_for — the one execution owner — so there is still
exactly one writer of the task table.
"""
from __future__ import annotations

from . import coverage, finding as finding_mod, identity as identity_mod, priority, traffic
from .orchestrator import Task


def _capture_by_id(campaign, cap_id: str) -> dict | None:
    if not cap_id:
        return None
    for c in traffic.captures(campaign):
        if c.get("id") == cap_id:
            return c
    return None


def _concrete_request(campaign, gap: dict) -> tuple[str, str]:
    """The concrete (method, path) the non-owner experiment must replay — taken from the
    OWNER's observed capture, so the mutation hits the exact same object the owner used,
    differing only in identity. Falls back to the template path if the evidence is gone."""
    refs = (gap.get("evidence") or {}).get("owner_capture_refs") or []
    cap = _capture_by_id(campaign, refs[0]) if refs else None
    if cap:
        return cap.get("method", gap.get("method", "GET")), cap.get("path", gap.get("path_template", "/"))
    return gap.get("method", "GET"), gap.get("path_template", "/")


def build(campaign, gap: dict) -> dict:
    """Derive an ExperimentProposal from one OWNER_NONOWNER_UNTESTED gap. Pure: reads the gap
    + its owner capture evidence, quotes the policy verdict a run WOULD get, and names the
    ownership assertions it relies on. It executes nothing."""
    method, path = _concrete_request(campaign, gap)
    owner = gap.get("baseline_identity", "")
    mutation = gap.get("mutation_identity", "")
    resource_id = gap.get("resource_id", "")
    rtype = gap.get("resource_type", "")
    preview = gap.get("policy_preview") or {}
    safe = preview.get("verdict", "").startswith("ALLOW")

    if gap.get("gap_type") == "ANONYMOUS_TO_AUTHENTICATED":
        # No shared object: the authenticated baseline is replayed with NO credentials. The
        # bridge owner is the authed baseline identity (both variants), so to_task + boundary
        # derivation work unchanged; required ownership assertions are empty (no object).
        endpoint = f"{method} {gap.get('path_template', path)}".strip()
        return {
            "proposal_id": f"prop-{gap['gap_id']}",
            "gap_id": gap["gap_id"], "gap_type": gap.get("gap_type", ""),
            "host": gap.get("host", ""), "endpoint": endpoint, "method": method, "path": path,
            "hypothesis": f"does {endpoint} succeed with NO credentials (anonymous)?",
            "baseline_identity": owner, "mutation_identity": mutation,
            "baseline_resource": "", "target_resource": "",
            "security_boundary": gap.get("boundary", []),
            "expected_secure_behavior": (f"the unauthenticated request is rejected (401/403) — "
                                         f"{endpoint} requires authentication"),
            "reason": gap.get("reason", ""), "policy_decision_preview": preview,
            "request_count": gap.get("estimated_requests", 2),
            "risk": ("controlled — anonymous replay of a researcher-observed request; no object "
                     "interaction" if safe else "requires explicit human approval before any request"),
            "required_ownership_assertions": [],
            "technique": gap.get("technique", "differential_anonymous"),
            "confidence": gap.get("confidence"),
            "priority_score": gap.get("priority_score"), "priority_rank": gap.get("priority_rank"),
        }

    return {
        "proposal_id": f"prop-{gap['gap_id']}",
        "gap_id": gap["gap_id"],
        "gap_type": gap.get("gap_type", ""),
        "host": gap.get("host", ""),
        "endpoint": f"{method} {gap.get('path_template', path)}".strip(),
        "method": method,
        "path": path,                                   # concrete, targets the owner's object
        "hypothesis": (f"can {mutation} perform {method} on {rtype} {resource_id}, "
                       f"a resource owned by {owner}?"),
        "baseline_identity": owner,
        "mutation_identity": mutation,
        "baseline_resource": resource_id,
        "target_resource": resource_id,                 # the SAME owner-owned object
        "security_boundary": gap.get("boundary", []),
        "expected_secure_behavior": (f"the request as {mutation} is rejected — {owner}'s "
                                      f"{rtype} is never exposed to a non-owner"),
        "reason": gap.get("reason", ""),
        "policy_decision_preview": preview,
        "request_count": gap.get("estimated_requests", 2),
        "risk": ("controlled — both identities researcher-owned, one researcher-owned object"
                 if safe else "requires explicit human approval before any request"),
        "required_ownership_assertions": [{
            "resource_type": rtype, "resource_value": resource_id,
            "owner_identity": owner, "researcher_controlled": True}],
        "technique": gap.get("technique", "differential_cross_account"),
        "confidence": gap.get("confidence"),
        "priority_score": gap.get("priority_score"),
        "priority_rank": gap.get("priority_rank"),
    }


def proposals(campaign, limit: int | None = None) -> list[dict]:
    """A proposal for each ranked OPEN gap (highest value first). Pure/read-only."""
    ranked = priority.rank(campaign)
    if limit is not None:
        ranked = ranked[:limit]
    return [build(campaign, g) for g in ranked]


def to_task(campaign, proposal: dict) -> Task:
    """Translate a proposal into the orchestrator Task the EXISTING differential worker
    understands. The task is NOT executed here — it is handed to the orchestrator/coordinator,
    which re-gates it through can_test. `account` is the OWNER (the targeted object's owner);
    can_test's cross-account row makes the test approval-free only if the owner is a
    researcher-owned test account — the same safety gate, not a new one."""
    owner_name = proposal["baseline_identity"]
    owner = identity_mod.get(campaign, owner_name)
    variant = {
        "method": proposal["method"], "path": proposal["path"],
        "resource": proposal["target_resource"], "owner": owner_name,
    }
    spec = {
        "baseline": {**variant, "identity": owner_name},
        "mutation": {**variant, "identity": proposal["mutation_identity"]},
    }
    return Task(
        campaign_id=campaign.id, technique=proposal["technique"], host=proposal["host"],
        hypothesis=proposal["hypothesis"], identity=proposal["mutation_identity"],
        account=owner, account_name=owner_name, spec=spec,
        impact=2.0, confidence=float(proposal.get("confidence") or 0.6),
        cost=float(proposal.get("request_count") or 2))


def queue(campaign, gap_id: str) -> dict:
    """Bridge a gap's proposal into the EXISTING orchestrator: build the proposal + task,
    propose() it (which gates via can_test and makes it durable), and mark the gap PROPOSED
    with its task id so the knowledge loop can reconcile it. Returns the proposal, the task
    record, and the policy verdict. This gates + enqueues; the coordinator executes."""
    from .orchestrator import Orchestrator
    gap = _gap(campaign, gap_id)
    if gap is None:
        raise ValueError(f"no derivable OPEN gap {gap_id!r}")
    prop = build(campaign, gap)
    task = to_task(campaign, prop)
    orch = Orchestrator(campaign)
    orch.propose(task)                                  # gate via can_test; durable task record
    rec = campaign.tasks()
    task_rec = next((t for t in rec if t["id"] == task.id), task.to_record())
    # remember the task id on the gap lifecycle so reconcile() can find the result later
    coverage.set_gap_state(campaign, gap_id, "PROPOSED", note=f"task={task.id}")
    return {"proposal": prop, "task": task_rec, "verdict": task.verdict,
            "verdict_reason": task.verdict_reason, "task_id": task.id}


def background_queue(campaign, gap_id: str):
    """Return (planner, on_complete) to run a gap's proposal through a CampaignRunCoordinator
    — the SAME execution owner as a pivot/reproduce, not a new engine. The planner proposes
    the differential Task on the coordinator's thread (re-gated by can_test) and marks the gap
    PROPOSED; on_complete reconciles the finished experiment back into the gap (RESOLVED /
    TESTED + a promoted FindingCandidate). Raises ValueError (the caller makes it a 4xx) if
    the gap is not a derivable OPEN gap."""
    gap = _gap(campaign, gap_id)
    if gap is None:
        raise ValueError(f"no derivable OPEN gap {gap_id!r}")
    prop = build(campaign, gap)

    def planner(co):
        task = to_task(co.c, prop)
        co.orch.propose(task)
        coverage.set_gap_state(co.c, gap_id, "PROPOSED", note=f"task={task.id}")

    def on_complete(co):
        reconcile(co.c)

    return planner, on_complete, prop


def ingest(campaign, gap_id: str, experiment: dict) -> dict:
    """The knowledge-update loop for ONE completed experiment: promote a FindingCandidate if
    the result is suspicious/vulnerable (via the existing, idempotent finding pipeline), then
    transition the gap. Secure => RESOLVED (dead boundary remembered); suspicious/vulnerable
    => TESTED with the finding attached; inconclusive => TESTED (needs a cleaner run). A
    negative result is a result — it is stored, never re-proposed."""
    classification = (experiment or {}).get("classification", "")
    exp_id = (experiment or {}).get("id", "")
    found = finding_mod.promote(campaign, experiment) if classification else None
    if classification == "secure":
        status = "RESOLVED"
    elif classification in ("suspicious", "vulnerable"):
        status = "TESTED"
    else:
        status = "TESTED"                               # inconclusive/empty: observed, not resolved
    rec = coverage.set_gap_state(
        campaign, gap_id, status, experiment_id=exp_id, classification=classification,
        note=(f"finding={found.id}" if found else ""))
    return {"gap_id": gap_id, "status": status, "classification": classification,
            "finding_id": found.id if found else "", "lifecycle": rec}


def reconcile(campaign) -> list[dict]:
    """Close the loop after an orchestrator run: for every gap marked PROPOSED whose task has
    EVALUATED, ingest the experiment the differential runner produced. Idempotent — a gap
    already TESTED/RESOLVED is skipped, and finding promotion is itself idempotent."""
    tasks = {t["id"]: t for t in campaign.tasks()}
    exps = {e.get("id"): e for e in campaign.experiments()}
    out = []
    for g in coverage.build(campaign)["gaps"]:
        if g.get("status") != "PROPOSED":
            continue
        note = (g.get("lifecycle") or {}).get("note", "")
        task_id = note[len("task="):] if note.startswith("task=") else ""
        task = tasks.get(task_id)
        if not task or task.get("state") not in ("EVALUATED", "COMPLETED"):
            continue
        exp = exps.get(task.get("experiment_id"))
        if exp:
            out.append(ingest(campaign, g["gap_id"], exp))
    return out


def _gap(campaign, gap_id: str) -> dict | None:
    for g in coverage.gaps(campaign):
        if g.get("gap_id") == gap_id and not g.get("orphan"):
            return g
    return None


def demo() -> None:
    """Self-check (offline): a gap becomes a proposal with the concrete owner path; queue()
    gates it through the orchestrator (ALLOW_WITH_LIMITS for two researcher-owned identities)
    and marks the gap PROPOSED; a suspicious experiment ingested promotes a finding and marks
    the gap TESTED; a secure one RESOLVES it. No proposal ever sends a request."""
    import os
    import tempfile
    from . import campaign as cmod, resource as resource_mod
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["ARGUS_HOME"] = tmp
        c = cmod.create("In scope:\napi.acme.example\nRate: 2 requests/sec\n", name="acme")
        for name in ("customer_a", "customer_b"):
            identity_mod.register(c, identity_mod.Identity(
                name=name, role="customer", tenant="t1", researcher_owned=True))
        traffic.capture(c, method="POST", url="https://api.acme.example/api/orders/777/cancel",
                        headers={"Authorization": "Bearer s"}, identity="customer_a",
                        response={"status": 204})
        resource_mod.assert_ownership(c, resource_mod.Ownership(
            resource_type="order", resource_value="777", owner_identity="customer_a",
            tenant="t1", researcher_controlled=True))

        gid = priority.rank(c)[0]["gap_id"]
        props = proposals(c)
        assert props and props[0]["gap_id"] == gid
        p = props[0]
        assert p["path"] == "/api/orders/777/cancel" and p["method"] == "POST"
        assert p["mutation_identity"] == "customer_b" and p["target_resource"] == "777"
        assert p["required_ownership_assertions"][0]["researcher_controlled"] is True

        q = queue(c, gid)
        assert q["verdict"] == "ALLOW_WITH_LIMITS"      # both researcher-owned, controlled object
        assert next(x for x in coverage.build(c)["gaps"] if x["gap_id"] == gid)["status"] == "PROPOSED"
        # the durable task is a differential_cross_account task the EXISTING worker runs
        task = next(t for t in c.tasks() if t["id"] == q["task_id"])
        assert task["technique"] == "differential_cross_account"
        assert task["spec"]["mutation"]["identity"] == "customer_b"

        # knowledge loop: a suspicious experiment promotes a finding + marks the gap TESTED
        susp = c.save_experiment(cmod.Experiment(
            campaign_id=c.id, hypothesis=p["hypothesis"], technique="differential_cross_account",
            host="api.acme.example", verdict="ALLOW_WITH_LIMITS", verdict_reason="",
            identity="customer_b", status="EVALUATED", classification="suspicious"))
        res = ingest(c, gid, _as_dict(susp))
        assert res["status"] == "TESTED" and res["finding_id"]
        assert len(finding_mod.findings(c)) == 1

        # a secure experiment on another gap RESOLVES it (dead boundary remembered)
        traffic.capture(c, method="POST", url="https://api.acme.example/api/orders/888/refund",
                        headers={"Authorization": "Bearer s"}, identity="customer_a",
                        response={"status": 200})
        resource_mod.assert_ownership(c, resource_mod.Ownership(
            resource_type="order", resource_value="888", owner_identity="customer_a",
            tenant="t1", researcher_controlled=True))
        gid2 = next(g["gap_id"] for g in coverage.gaps(c)
                    if g.get("resource_id") == "888" and not g.get("orphan"))
        secure = c.save_experiment(cmod.Experiment(
            campaign_id=c.id, hypothesis="x", technique="differential_cross_account",
            host="api.acme.example", verdict="ALLOW", verdict_reason="",
            status="EVALUATED", classification="secure"))
        r2 = ingest(c, gid2, _as_dict(secure))
        assert r2["status"] == "RESOLVED" and not r2["finding_id"]
    del os.environ["ARGUS_HOME"]
    print("proposal demo passed")


def _as_dict(exp):
    from dataclasses import asdict
    return asdict(exp)


if __name__ == "__main__":
    demo()
