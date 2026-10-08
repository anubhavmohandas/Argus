"""Finding candidates — the interpretation layer the spec puts ON TOP of experiments.

An Experiment records what ARGUS *did* and what it observed; a Finding is a claim that
one of those observations is a real issue worth reporting. The two are kept separate on
purpose (campaign.py's core idea): the durable record is the experiment, a finding is a
later, revisable judgement layered over it — and it moves through a lifecycle rather
than springing into existence as "a vuln".

The lifecycle is the spec's candidate pipeline, as a closed, forward-only vocabulary:

    OBSERVED → REPRODUCIBLE → IN_SCOPE → BOUNDARY_CONFIRMED → IMPACT_CONFIRMED
             → DUPLICATE_CHECKED → REPORT_READY        (or DISMISSED, from anywhere)

The hard rule this module exists to enforce: **a state describes what ARGUS has EARNED, not
what a caller asked it to call the issue.** So the lifecycle is NOT a free forward walk — the
generic `advance()` is internal, and the ONLY public way forward is through an earned
transition that verifies evidence:

    mark_reproducible  requires linked reproduction trials that actually reproduced
    confirm_scope      requires the frozen campaign policy to govern an in-scope asset
    confirm_boundary   requires a boundary DERIVED from evidence (never a caller's label)
    confirm_impact     requires a demonstrated, evidence-backed consequence
    complete_dedupe    requires a root-cause/dedupe result
    mark_report_ready  requires every prior stage's evidence to be present

A caller therefore cannot jump OBSERVED → REPORT_READY: each transition checks the finding is
at exactly the preceding stage AND that the evidence that stage demands exists and traces back
to immutable experiments/observations. The evidence each transition earned is stored on the
finding, so a report is assembled from provenance, never from prose.

occam: one JSON file per finding under the campaign dir, mirroring experiments/observations
exactly — no new store. The state machine is an index comparison on a tuple; evidence is a
dict keyed by stage. Boundary/impact/dedupe reasoning lives in their own modules, imported
lazily so the dependency runs finding → {boundary,impact,dedupe}, never the reverse.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field

# The pipeline, in order. Index position IS the ordering rule: a transition is legal
# only to a LATER stage (or DISMISSED). A typo can't invent a stage that skips the gate.
LIFECYCLE = (
    "OBSERVED", "REPRODUCIBLE", "IN_SCOPE", "BOUNDARY_CONFIRMED",
    "IMPACT_CONFIRMED", "DUPLICATE_CHECKED", "REPORT_READY",
)
DISMISSED = "DISMISSED"
STATES = LIFECYCLE + (DISMISSED,)

# the evidence stage each lifecycle state must carry before REPORT_READY is legal.
_EVIDENCE_STAGES = ("REPRODUCIBLE", "IN_SCOPE", "BOUNDARY_CONFIRMED",
                    "IMPACT_CONFIRMED", "DUPLICATE_CHECKED")

# experiment.classification values that are worth promoting to a candidate. "secure"
# and "inconclusive" are NOT findings; "vulnerable" would be (a later slice may set it).
_PROMOTABLE = {"suspicious", "vulnerable"}

# differential technique -> the vulnerability-class tags it implies, so reportability can
# be checked against the program's non_reportable set (which is keyed on those tags).
_TECHNIQUE_TAGS: dict[str, set[str]] = {
    "differential_cross_account": {"access-control", "authz"},
    "differential_same_account": {"access-control", "authz"},
}


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def _policy_version(campaign) -> str:
    """A stable fingerprint of the FROZEN campaign policy (its program text). Referencing
    this proves scope was decided under the same contract the experiment ran under —
    without recompiling a fresh policy to re-litigate history."""
    return hashlib.sha256((campaign.program_text or "").encode()).hexdigest()[:12]


@dataclass
class Finding:
    """A candidate issue promoted from an experiment. Carries its source experiment (so
    every claim traces back to immutable evidence), its lifecycle state, the evidence each
    earned stage produced, and the full transition history. `reportable` is the policy's
    answer at promotion time; `title` is a short human label."""
    campaign_id: str
    experiment_id: str
    host: str
    technique: str
    title: str
    classification: str
    state: str = "OBSERVED"
    reportable: bool = True
    suppressed_reason: str = ""              # why not reportable (out of scope / excluded class)
    evidence: dict = field(default_factory=dict)   # stage -> the evidence record that earned it
    history: list[dict] = field(default_factory=list)
    id: str = field(default_factory=lambda: f"find-{uuid.uuid4().hex[:12]}")
    created_at: str = field(default_factory=_now)

    def __post_init__(self):
        if self.state not in STATES:
            raise ValueError(f"bad finding state {self.state!r}")


def _dir(campaign):
    d = campaign.dir / "findings"
    d.mkdir(parents=True, exist_ok=True)
    d.chmod(0o700)
    return d


def _save(campaign, f: Finding) -> Finding:
    p = _dir(campaign) / f"{f.id}.json"
    p.touch(mode=0o600)
    p.write_text(json.dumps(asdict(f), indent=2))
    return f


def findings(campaign) -> list[dict]:
    out = []
    for fp in sorted(_dir(campaign).glob("*.json")):
        try:
            out.append(json.loads(fp.read_text()))
        except (OSError, ValueError):
            continue
    return out


def _get(campaign, finding_id: str) -> Finding | None:
    for d in findings(campaign):
        if d["id"] == finding_id:
            return Finding(**d)
    return None


def _reportability(campaign, host: str, technique: str, tags: set[str]) -> tuple[bool, str]:
    """The policy's deterministic answer: may this candidate be reported? False (with a
    reason) when the host fell out of scope or the program declared the class non-
    reportable. Reuses the exact policy predicates — found ≠ reportable."""
    pol = campaign.policy
    if not pol.scope.allows(host):
        return False, "host not in scope"
    if tags & pol.non_reportable:
        return False, f"program excludes this class: {sorted(tags & pol.non_reportable)}"
    return True, ""


def promote(campaign, experiment: dict, title: str = "") -> Finding | None:
    """Promote a `suspicious`/`vulnerable` Experiment to an OBSERVED candidate, once.
    Returns the (existing or new) Finding, or None if the experiment isn't promotable.
    Idempotent: a second call for the same experiment returns the first finding, never a
    duplicate — so re-running the pipeline can't multiply candidates."""
    if experiment.get("classification") not in _PROMOTABLE:
        return None
    exp_id = experiment["id"]
    for d in findings(campaign):
        if d["experiment_id"] == exp_id:
            return Finding(**d)                 # already promoted — idempotent

    technique = experiment.get("technique", "")
    host = experiment.get("host", "")
    tags = _TECHNIQUE_TAGS.get(technique, set())
    reportable, reason = _reportability(campaign, host, technique, tags)
    f = Finding(
        campaign_id=campaign.id, experiment_id=exp_id, host=host, technique=technique,
        title=title or f"{technique} on {host}",
        classification=experiment.get("classification", ""),
        reportable=reportable, suppressed_reason=reason,
        history=[{"to": "OBSERVED", "at": _now(), "note": "promoted from experiment"}])
    _save(campaign, f)
    campaign.audit("finding_promoted", finding=f.id, experiment=exp_id, host=host,
                   technique=technique, reportable=reportable, reason=reason)
    return f


# --- the internal mover ----------------------------------------------------
def _advance(campaign, finding_id: str, to_state: str, evidence: dict | None = None,
             note: str = "", by: str = "") -> Finding:
    """INTERNAL. Move a candidate forward (or DISMISS it), attaching the evidence the earned
    transition produced. Rejects a backward or same-stage move — the lifecycle is forward-
    only so a withdrawn finding can't be quietly re-promoted. Not a public bypass: the public
    lifecycle API is the earned transitions below, which each verify evidence before calling
    this. Appends to history + the campaign audit."""
    if to_state not in STATES:
        raise ValueError(f"unknown finding state {to_state!r}")
    f = _get(campaign, finding_id)
    if f is None:
        raise KeyError(f"no finding {finding_id!r}")
    if f.state == DISMISSED:
        raise ValueError(f"finding {finding_id} is DISMISSED — terminal; promote a fresh one")
    if to_state != DISMISSED and LIFECYCLE.index(to_state) <= LIFECYCLE.index(f.state):
        raise ValueError(f"illegal transition {f.state} → {to_state}: lifecycle is forward-only")
    f.state = to_state
    if evidence is not None:
        f.evidence[to_state] = evidence
    f.history.append({"to": to_state, "at": _now(), "note": note, "by": by})
    _save(campaign, f)
    campaign.audit("finding_transition", finding=f.id, to=to_state, note=note, by=by)
    return f


def _require(campaign, finding_id: str, prior: str) -> Finding:
    """Load a finding and require it be at exactly `prior` — the stage this transition
    builds on. This is what makes OBSERVED → REPORT_READY impossible: every earned step
    demands the one before it, so the gates can't be skipped."""
    f = _get(campaign, finding_id)
    if f is None:
        raise KeyError(f"no finding {finding_id!r}")
    if f.state == DISMISSED:
        raise ValueError(f"finding {finding_id} is DISMISSED — terminal")
    if f.state != prior:
        raise ValueError(
            f"transition needs the finding at {prior}, but it is at {f.state} — "
            f"earn the intermediate stages first")
    return f


def _refs_exist(campaign, refs: list[str]) -> bool:
    """Every evidence ref must name a real immutable record (experiment or observation) in
    this campaign — evidence is never a dangling id."""
    ids = {e["id"] for e in campaign.experiments()} | {o["id"] for o in campaign.observations()}
    return bool(refs) and all(r in ids for r in refs)


# --- earned transitions (the public lifecycle API) -------------------------
def dismiss(campaign, finding_id: str, note: str = "", by: str = "") -> Finding:
    """Withdraw a candidate. Terminal — a dismissed finding is never revived (promote a
    fresh one if new evidence appears)."""
    return _advance(campaign, finding_id, DISMISSED, note=note, by=by)


def mark_reproducible(campaign, finding_id: str, repro: dict, note: str = "", by: str = "") -> Finding:
    """OBSERVED → REPRODUCIBLE. Requires real linked reproduction evidence: `repro` must show
    it reproduced, with trial experiment ids that exist in this campaign. A suspicious first
    observation is NOT reproducibility — the reproduction system (reproduce.py) produces this."""
    f = _require(campaign, finding_id, "OBSERVED")
    if not repro.get("reproduced"):
        raise ValueError("not reproducible: reproduction did not confirm the original result")
    trials = list(repro.get("trial_experiment_ids") or [])
    if not _refs_exist(campaign, trials):
        raise ValueError("reproduction evidence must link real trial experiments")
    if repro.get("original") != "suspicious":
        raise ValueError("only a suspicious original reproduces into a finding")
    ev = {
        "reproduced": True,
        "original_experiment": f.experiment_id,
        "trial_experiment_ids": trials,
        "requested_trials": repro.get("requested_trials", len(trials)),
        "completed_trials": len(trials),
        "classifications": list(repro.get("classifications") or []),
        "policy_version": _policy_version(campaign),
        "first_seen": repro.get("first_seen", ""),
        "last_verified": _now(),
    }
    return _advance(campaign, finding_id, "REPRODUCIBLE", evidence=ev, note=note, by=by)


def confirm_scope(campaign, finding_id: str, note: str = "", by: str = "") -> Finding:
    """REPRODUCIBLE → IN_SCOPE. Ties the finding to the FROZEN campaign policy: the asset is
    in the frozen scope, the program does not exclude the class, and the source experiment's
    recorded verdict (the historical decision at execution time) permitted the test. Reads the
    historical campaign policy metadata — it does not recompile a fresh policy to prove scope."""
    f = _require(campaign, finding_id, "REPRODUCIBLE")
    if not f.reportable:
        raise ValueError(f"not in scope / reportable: {f.suppressed_reason or 'excluded by program'}")
    if not campaign.policy.scope.allows(f.host):
        raise ValueError(f"asset {f.host} is not in the frozen campaign scope")
    exp = next((e for e in campaign.experiments() if e["id"] == f.experiment_id), None)
    verdict = (exp or {}).get("verdict", "")
    if not verdict.startswith("ALLOW"):
        raise ValueError(f"source experiment was not policy-permitted (verdict {verdict!r})")
    ev = {
        "campaign_id": campaign.id,
        "policy_version": _policy_version(campaign),
        "asset": f.host,
        "in_scope_at_execution": True,
        "experiment_id": f.experiment_id,
        "experiment_verdict": verdict,
        "technique": f.technique,
    }
    return _advance(campaign, finding_id, "IN_SCOPE", evidence=ev, note=note, by=by)


def confirm_boundary(campaign, finding_id: str, note: str = "", by: str = "") -> Finding:
    """IN_SCOPE → BOUNDARY_CONFIRMED. The boundary is DERIVED from evidence (boundary.derive),
    never taken from a caller. Refuses when the evidence does not support a confirmed boundary
    — unknown stays unknown, and a 200 alone never counts."""
    from . import boundary as boundary_mod
    f = _require(campaign, finding_id, "IN_SCOPE")
    ev = boundary_mod.derive(campaign, f)
    if not ev.get("confirmed"):
        raise ValueError(f"boundary not confirmed by evidence: {ev.get('reason', 'unsupported')}")
    if not _refs_exist(campaign, ev.get("evidence_refs", [])):
        raise ValueError("boundary evidence must reference real experiment/observation records")
    return _advance(campaign, finding_id, "BOUNDARY_CONFIRMED", evidence=ev, note=note, by=by)


def confirm_impact(campaign, finding_id: str, note: str = "", by: str = "") -> Finding:
    """BOUNDARY_CONFIRMED → IMPACT_CONFIRMED. Impact is DERIVED from the observations
    (impact.assess) and must be a demonstrated consequence — a status/size difference alone
    is refused. The stored ImpactAssessment is the ceiling the report prose may not exceed."""
    from . import impact as impact_mod
    f = _require(campaign, finding_id, "BOUNDARY_CONFIRMED")
    ev = impact_mod.assess(campaign, f)
    if not ev.get("demonstrated_effects"):
        raise ValueError(f"no demonstrated impact: {ev.get('severity_rationale', 'nothing proven')}")
    if not _refs_exist(campaign, ev.get("evidence_refs", [])):
        raise ValueError("impact evidence must reference real experiment/observation records")
    return _advance(campaign, finding_id, "IMPACT_CONFIRMED", evidence=ev, note=note, by=by)


def complete_dedupe(campaign, finding_id: str, note: str = "", by: str = "") -> Finding:
    """IMPACT_CONFIRMED → DUPLICATE_CHECKED. Records the root-cause/dedupe result
    (dedupe.check) so the hunter decides one systemic report vs several — never auto-merged."""
    from . import dedupe as dedupe_mod
    _require(campaign, finding_id, "IMPACT_CONFIRMED")
    ev = dedupe_mod.check(campaign, _get(campaign, finding_id))
    return _advance(campaign, finding_id, "DUPLICATE_CHECKED", evidence=ev, note=note, by=by)


def mark_report_ready(campaign, finding_id: str, note: str = "", by: str = "") -> Finding:
    """DUPLICATE_CHECKED → REPORT_READY. The final gate: every prior stage's evidence must be
    present and the finding still reportable. This is the only path to REPORT_READY, so the
    state genuinely means 'ARGUS earned every prerequisite', not 'a caller said so'."""
    f = _require(campaign, finding_id, "DUPLICATE_CHECKED")
    if not f.reportable:
        raise ValueError(f"not reportable: {f.suppressed_reason or 'excluded by program'}")
    missing = [s for s in _EVIDENCE_STAGES if s not in f.evidence]
    if missing:
        raise ValueError(f"missing earned evidence for: {missing}")
    return _advance(campaign, finding_id, "REPORT_READY",
                    evidence={"earned_at": _now(), "prerequisites": list(_EVIDENCE_STAGES)},
                    note=note, by=by)


def validate(campaign, finding_id: str) -> tuple[Finding, str]:
    """Run every earned transition the evidence currently supports, from the finding's
    current stage onward, stopping at the first gate it cannot yet pass. Each gate still
    verifies its own evidence — this only SEQUENCES the deterministic derivations (scope →
    boundary → impact → dedupe → report-ready). It never runs reproduction, which executes
    requests and stays operator-controlled. Returns (finding, stopped_reason)."""
    steps = [("REPRODUCIBLE", confirm_scope), ("IN_SCOPE", confirm_boundary),
             ("BOUNDARY_CONFIRMED", confirm_impact), ("IMPACT_CONFIRMED", complete_dedupe),
             ("DUPLICATE_CHECKED", mark_report_ready)]
    stopped = ""
    for prior, fn in steps:
        cur = _get(campaign, finding_id)
        if cur is None:
            raise KeyError(f"no finding {finding_id!r}")
        if cur.state == DISMISSED:
            stopped = "finding is dismissed"
            break
        if LIFECYCLE.index(cur.state) < LIFECYCLE.index(prior):
            stopped = "needs reproduction first — run [Reproduce]"
            break
        if cur.state != prior:
            continue                    # already past this gate
        try:
            fn(campaign, finding_id)
        except ValueError as e:
            stopped = str(e)
            break
    return _get(campaign, finding_id), stopped


def report_ready(campaign) -> list[dict]:
    """Candidates that completed the pipeline AND the program will accept — the queue the
    report generator draws from."""
    return [d for d in findings(campaign)
            if d["state"] == "REPORT_READY" and d["reportable"]]


def walk_to_report_ready(campaign, finding_id: str, repro: dict, by: str = "") -> Finding:
    """Convenience for tests/CLI: run every earned transition in order from OBSERVED. Each
    step still verifies its own evidence — this is NOT a bypass, just the sequence."""
    mark_reproducible(campaign, finding_id, repro, by=by)
    confirm_scope(campaign, finding_id, by=by)
    confirm_boundary(campaign, finding_id, by=by)
    confirm_impact(campaign, finding_id, by=by)
    complete_dedupe(campaign, finding_id, by=by)
    return mark_report_ready(campaign, finding_id, by=by)


def asdict_exp(exp) -> dict:
    """An Experiment -> the dict form promote() consumes (same shape campaign.experiments()
    returns). Small shim so the demo/tests can pass a live Experiment object."""
    from dataclasses import asdict as _ad
    return _ad(exp)


def demo() -> None:
    """Self-check (offline): a suspicious differential promotes once (idempotent); the
    lifecycle cannot be jumped (OBSERVED → REPORT_READY is refused); each earned transition
    requires its evidence; and a finding that genuinely earns every stage reaches
    REPORT_READY with its evidence attached. Uses a temp ARGUS_HOME + injected transport."""
    import os
    import tempfile
    from . import campaign as campaign_mod, reproduce
    from .differential import Variant, run
    from .identity import Identity, register

    with tempfile.TemporaryDirectory() as tmp:
        os.environ["ARGUS_HOME"] = tmp
        os.environ["A_TOK"], os.environ["B_TOK"] = "tok-a", "tok-b"
        c = campaign_mod.create("Assets:\napi.acme.example\nRate: 9 requests/sec\n", name="Acme")
        a = Identity(name="user_a", role="customer", tenant="t1", researcher_owned=True, credential_ref="A_TOK")
        b = Identity(name="user_b", role="customer", tenant="t1", researcher_owned=True, credential_ref="B_TOK")
        register(c, a); register(c, b)
        leak = lambda *x: (200, {"content-type": "application/json"}, '{"total":9}')
        base = Variant(a, method="GET", path="/api/orders/1", resource="order-1", owner=a)
        mut = Variant(b, method="GET", path="/api/orders/1", resource="order-1", owner=a)
        from . import resource as resource_mod
        resource_mod.assert_ownership(c, resource_mod.Ownership(
            resource_type="order", resource_value="order-1", owner_identity="user_a",
            researcher_controlled=True))

        r = run(c, "differential_cross_account", "api.acme.example", base, mut, fetch=leak)
        f = promote(c, next(e for e in c.experiments() if e["id"] == r.experiment_id))
        assert f.state == "OBSERVED" and f.reportable
        assert promote(c, next(e for e in c.experiments() if e["id"] == r.experiment_id)).id == f.id

        # the bypass is gone: no earned step jumps to REPORT_READY, and advancing out of
        # order is refused.
        try:
            mark_report_ready(c, f.id); raise AssertionError("jumped to REPORT_READY")
        except ValueError:
            pass
        try:
            confirm_boundary(c, f.id); raise AssertionError("confirmed boundary before scope")
        except ValueError:
            pass

        # REPRODUCIBLE requires real reproduction evidence — a bare claim is refused.
        try:
            mark_reproducible(c, f.id, {"reproduced": True, "original": "suspicious",
                                        "trial_experiment_ids": ["exp-does-not-exist"]})
            raise AssertionError("accepted a dangling trial ref")
        except ValueError:
            pass

        # reproduce it for real (same differential, re-run), then walk the earned ladder.
        rep = reproduce.verify(c, "differential_cross_account", "api.acme.example", base, mut,
                               trials=2, fetch=leak, finding_id=f.id)
        assert rep.reproduced
        assert _get(c, f.id).state == "REPRODUCIBLE"            # reproduce earned it
        assert "REPRODUCIBLE" in _get(c, f.id).evidence
        confirm_scope(c, f.id)
        confirm_boundary(c, f.id)
        confirm_impact(c, f.id)
        complete_dedupe(c, f.id)
        g = mark_report_ready(c, f.id)
        assert g.state == "REPORT_READY"
        assert all(s in g.evidence for s in _EVIDENCE_STAGES)
        assert [d["id"] for d in report_ready(c)] == [f.id]
        # scope evidence pins the frozen policy version
        assert g.evidence["IN_SCOPE"]["policy_version"] == _policy_version(c)

        # dismissed is terminal
        f2 = promote(c, {"id": "exp-x", "technique": "differential_cross_account",
                         "host": "api.acme.example", "classification": "suspicious"})
        dismiss(c, f2.id, note="dup")
        try:
            mark_reproducible(c, f2.id, {"reproduced": True}); raise AssertionError("revived")
        except ValueError:
            pass

        events = [a2["event"] for a2 in c.audit_trail()]
        assert "finding_promoted" in events and "finding_transition" in events
        del os.environ["A_TOK"], os.environ["B_TOK"]
    del os.environ["ARGUS_HOME"]
    print("finding demo passed")


if __name__ == "__main__":
    demo()
