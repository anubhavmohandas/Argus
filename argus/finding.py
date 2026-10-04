"""Finding candidates — the interpretation layer the spec puts ON TOP of experiments.

An Experiment records what ARGUS *did* and what it observed; a Finding is a claim that
one of those observations is a real issue worth reporting. The two are kept separate on
purpose (campaign.py's core idea): the durable record is the experiment, a finding is a
later, revisable judgement layered over it — and it moves through a lifecycle rather
than springing into existence as "a vuln".

The lifecycle is the spec's candidate pipeline, as a closed, forward-only vocabulary:

    OBSERVED → REPRODUCIBLE → IN_SCOPE → BOUNDARY_CONFIRMED → IMPACT_CONFIRMED
             → DUPLICATE_CHECKED → REPORT_READY        (or DISMISSED, from anywhere)

Forward-only (you can't un-confirm impact by fiat; you DISMISS and start over) so the
state can't be walked backwards to launder a withdrawn finding into a report. Each
transition is appended to the finding's history AND the campaign audit — the same
replayable-provenance rule as every other state change.

ARGUS/NYX boundary: promotion is deterministic (only a `suspicious` experiment becomes
an OBSERVED candidate, idempotently) and reportability is a deterministic policy check.
Deciding a candidate is REPRODUCIBLE / has IMPACT is the job of later ARGUS slices
(reproducibility, impact) and NYX's interpretation — this module owns the record and
the gate on transitions, not the reasoning that earns them.

occam: one JSON file per finding under the campaign dir, mirroring experiments/
observations exactly — no new store, no ORM. The state machine is an index comparison
on a tuple, not a graph library.
"""
from __future__ import annotations

import datetime as _dt
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


@dataclass
class Finding:
    """A candidate issue promoted from an experiment. Carries its source experiment (so
    every claim traces back to immutable evidence), its lifecycle state, and the full
    transition history. `reportable` is the policy's answer at promotion time; `title`
    is a short human label."""
    campaign_id: str
    experiment_id: str
    host: str
    technique: str
    title: str
    classification: str
    state: str = "OBSERVED"
    reportable: bool = True
    suppressed_reason: str = ""              # why not reportable (out of scope / excluded class)
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


def advance(campaign, finding_id: str, to_state: str, note: str = "", by: str = "") -> Finding:
    """Move a candidate forward in the pipeline (or DISMISS it). Rejects a backward or
    same-stage move — the lifecycle is forward-only so a withdrawn finding can't be
    quietly re-promoted into a report. Appends to history + the campaign audit."""
    if to_state not in STATES:
        raise ValueError(f"unknown finding state {to_state!r}")
    f = _get(campaign, finding_id)
    if f is None:
        raise KeyError(f"no finding {finding_id!r}")
    if f.state == DISMISSED:
        raise ValueError(f"finding {finding_id} is DISMISSED — terminal; promote a fresh one")
    if to_state != DISMISSED:
        if f.state == DISMISSED or LIFECYCLE.index(to_state) <= LIFECYCLE.index(f.state):
            raise ValueError(
                f"illegal transition {f.state} → {to_state}: lifecycle is forward-only")
    f.state = to_state
    f.history.append({"to": to_state, "at": _now(), "note": note, "by": by})
    _save(campaign, f)
    campaign.audit("finding_transition", finding=f.id, to=to_state, note=note, by=by)
    return f


def report_ready(campaign) -> list[dict]:
    """Candidates that completed the pipeline AND the program will accept — the queue the
    report generator (a later slice) draws from."""
    return [d for d in findings(campaign)
            if d["state"] == "REPORT_READY" and d["reportable"]]


def demo() -> None:
    """Self-check (offline): a suspicious experiment promotes once (idempotent), walks the
    pipeline forward, can't walk backward, and a non-reportable class is flagged but still
    tracked. Uses a temp ARGUS_HOME."""
    import os
    import tempfile
    from . import campaign as campaign_mod
    from .campaign import Experiment

    with tempfile.TemporaryDirectory() as tmp:
        os.environ["ARGUS_HOME"] = tmp
        c = campaign_mod.create(
            "Assets:\napi.acme.example\nOut of scope:\n- Missing security headers\n", name="Acme")

        susp = c.save_experiment(Experiment(
            campaign_id=c.id, hypothesis="idor?", technique="differential_cross_account",
            host="api.acme.example", verdict="ALLOW_WITH_LIMITS", verdict_reason="owned",
            status="EVALUATED", classification="suspicious"))
        secure = c.save_experiment(Experiment(
            campaign_id=c.id, hypothesis="idor?", technique="differential_cross_account",
            host="api.acme.example", verdict="ALLOW", verdict_reason="",
            status="EVALUATED", classification="secure"))

        # only the suspicious one promotes; secure/inconclusive never become findings
        assert promote(c, asdict_exp(secure)) is None
        f = promote(c, asdict_exp(susp))
        assert f is not None and f.state == "OBSERVED" and f.reportable
        # idempotent: same experiment -> same finding, no duplicate
        assert promote(c, asdict_exp(susp)).id == f.id
        assert len(findings(c)) == 1

        # forward-only lifecycle
        advance(c, f.id, "REPRODUCIBLE", note="re-ran, held")
        advance(c, f.id, "IN_SCOPE")
        try:
            advance(c, f.id, "OBSERVED")                 # backward — refused
            raise AssertionError("walked the lifecycle backward")
        except ValueError as e:
            assert "forward-only" in str(e)
        # finish the pipeline
        for s in ("BOUNDARY_CONFIRMED", "IMPACT_CONFIRMED", "DUPLICATE_CHECKED", "REPORT_READY"):
            advance(c, f.id, s)
        assert [d["id"] for d in report_ready(c)] == [f.id]

        # a non-reportable class is promoted (we still found it) but flagged, not report-ready
        excluded = c.save_experiment(Experiment(
            campaign_id=c.id, hypothesis="x", technique="header_probe", host="api.acme.example",
            verdict="ALLOW", verdict_reason="", status="EVALUATED", classification="suspicious"))
        # header_probe has no implied authz tags, so it stays reportable here; instead test
        # an out-of-scope host is flagged non-reportable
        oos = c.save_experiment(Experiment(
            campaign_id=c.id, hypothesis="x", technique="differential_cross_account",
            host="evil.example", verdict="ALLOW_WITH_LIMITS", verdict_reason="",
            status="EVALUATED", classification="suspicious"))
        g = promote(c, asdict_exp(oos))
        assert g is not None and not g.reportable and "not in scope" in g.suppressed_reason
        # it can still be tracked/dismissed, just never report-ready
        advance(c, g.id, DISMISSED, note="out of scope, no further work")
        assert _get(c, g.id).state == DISMISSED
        try:
            advance(c, g.id, "REPRODUCIBLE")             # dismissed is terminal
            raise AssertionError("revived a dismissed finding")
        except ValueError:
            pass

        events = [a["event"] for a in c.audit_trail()]
        assert "finding_promoted" in events and "finding_transition" in events
    del os.environ["ARGUS_HOME"]
    print("finding demo passed")


def asdict_exp(exp) -> dict:
    """An Experiment -> the dict form promote() consumes (same shape campaign.experiments()
    returns). Small shim so the demo/tests can pass a live Experiment object."""
    from dataclasses import asdict as _ad
    return _ad(exp)


if __name__ == "__main__":
    demo()
