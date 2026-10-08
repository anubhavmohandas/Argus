"""Program-response memory — what the program said after a report was sent.

The spec's Phase 11: after the report pipeline works, model the program's response as research
memory. ARGUS does NOT scrape or auto-submit — the operator records the outcome by hand, and
ARGUS remembers it so the next campaign is smarter about where value is.

The hard boundary the spec draws: feedback adjusts RESEARCH PRIORITY only. It may teach the
priority engine which gap types and root-cause patterns tend to duplicate or pay, but it can
NEVER weaken scope, policy, ownership, human approval, or any safety gate. So this module
stores facts and exposes a read-only aggregate; it touches nothing authoritative.

Each record is per finding: the outcome, the triager's request, timestamps, a duplicate
reference if supplied, any reward the operator enters, and notes — with an append-only history
so the trail of outcomes is replayable. A report can only be SUBMITTED once the finding is
genuinely REPORT_READY (earned), so triage memory never launders an unready finding.

occam: one JSON file per finding under the campaign's triage/ dir, mirroring findings/ exactly
— no new store. The aggregate is a Counter over records, not a model.
"""
from __future__ import annotations

import datetime as _dt
import json
from dataclasses import asdict, dataclass, field

from . import finding as finding_mod

# the program's response vocabulary — closed so a typo can't invent an outcome. "" = recorded
# but not yet submitted (the operator is tracking intent).
OUTCOMES = (
    "SUBMITTED", "ACCEPTED", "DUPLICATE", "INFORMATIVE",
    "NOT_APPLICABLE", "NEEDS_MORE_INFO", "RESOLVED",
)
# outcomes that count as the program agreeing the finding had value (for the priority signal).
_VALUABLE = {"ACCEPTED", "RESOLVED"}
_LOW_VALUE = {"DUPLICATE", "INFORMATIVE", "NOT_APPLICABLE"}


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


@dataclass
class ProgramResponse:
    finding_id: str
    campaign_id: str
    outcome: str = ""
    triager_request: str = ""
    duplicate_reference: str = ""
    reward: str = ""                         # operator-entered; free text (e.g. "$500")
    notes: str = ""
    submitted_at: str = ""
    response_at: str = ""
    history: list[dict] = field(default_factory=list)


def _dir(campaign):
    d = campaign.dir / "triage"
    d.mkdir(parents=True, exist_ok=True)
    d.chmod(0o700)
    return d


def _save(campaign, r: ProgramResponse) -> ProgramResponse:
    p = _dir(campaign) / f"{r.finding_id}.json"
    p.touch(mode=0o600)
    p.write_text(json.dumps(asdict(r), indent=2))
    return r


def response(campaign, finding_id: str) -> ProgramResponse | None:
    p = _dir(campaign) / f"{finding_id}.json"
    if not p.exists():
        return None
    try:
        return ProgramResponse(**json.loads(p.read_text()))
    except (OSError, ValueError):
        return None


def responses(campaign) -> list[dict]:
    out = []
    for fp in sorted(_dir(campaign).glob("*.json")):
        try:
            out.append(json.loads(fp.read_text()))
        except (OSError, ValueError):
            continue
    return out


def record(campaign, finding_id: str, outcome: str, *, triager_request: str = "",
           duplicate_reference: str = "", reward: str = "", notes: str = "") -> ProgramResponse:
    """Record a program outcome for a finding (research memory; no submission happens here).
    SUBMITTED requires the finding to be genuinely REPORT_READY — triage memory never records
    a submission for an unearned finding. Appends to the record's history."""
    if outcome not in OUTCOMES:
        raise ValueError(f"unknown program outcome {outcome!r}; expected one of {OUTCOMES}")
    f = finding_mod._get(campaign, finding_id)
    if f is None:
        raise KeyError(f"no finding {finding_id!r}")
    if outcome == "SUBMITTED" and f.state != "REPORT_READY":
        raise ValueError(
            f"cannot record SUBMITTED: finding is {f.state}, not REPORT_READY — earn it first")

    r = response(campaign, finding_id) or ProgramResponse(
        finding_id=finding_id, campaign_id=campaign.id)
    now = _now()
    r.outcome = outcome
    if triager_request:
        r.triager_request = triager_request
    if duplicate_reference:
        r.duplicate_reference = duplicate_reference
    if reward:
        r.reward = reward
    if notes:
        r.notes = notes
    if outcome == "SUBMITTED" and not r.submitted_at:
        r.submitted_at = now
    if outcome != "SUBMITTED":
        r.response_at = now
    r.history.append({"outcome": outcome, "at": now, "notes": notes})
    _save(campaign, r)
    campaign.audit("program_response", finding=finding_id, outcome=outcome,
                   duplicate_reference=duplicate_reference, reward=reward)
    return r


def priority_signal(campaign) -> dict:
    """A READ-ONLY aggregate of outcomes by boundary type and endpoint family — the only thing
    the priority engine may consult from triage memory. It reports where value and duplicates
    have historically landed; it changes no scope/policy/approval. Deterministic."""
    from . import boundary as boundary_mod
    by_boundary: dict[str, dict] = {}
    for d in responses(campaign):
        f = finding_mod._get(campaign, d["finding_id"])
        if f is None:
            continue
        bnd = (f.evidence.get("BOUNDARY_CONFIRMED")
               or boundary_mod.derive(campaign, f))
        btype = bnd.get("boundary_type", "UNKNOWN")
        slot = by_boundary.setdefault(btype, {"valuable": 0, "low_value": 0, "total": 0})
        slot["total"] += 1
        if d["outcome"] in _VALUABLE:
            slot["valuable"] += 1
        elif d["outcome"] in _LOW_VALUE:
            slot["low_value"] += 1
    return {"by_boundary_type": by_boundary}


def demo() -> None:
    """Self-check (offline): a SUBMITTED outcome requires a REPORT_READY finding; outcomes are
    recorded with history; the priority signal aggregates value vs duplicates by boundary — and
    nothing here can touch scope/policy."""
    import os
    import tempfile
    from . import campaign as campaign_mod, reproduce, resource as resource_mod
    from .differential import Variant, run
    from .identity import Identity, register

    with tempfile.TemporaryDirectory() as tmp:
        os.environ["ARGUS_HOME"] = tmp
        os.environ["A_TOK"], os.environ["B_TOK"] = "tok-a", "tok-b"
        c = campaign_mod.create("Assets:\napi.acme.example\nRate: 9 requests/sec\n", name="Acme")
        a = Identity(name="user_a", role="customer", tenant="t1", researcher_owned=True, credential_ref="A_TOK")
        b = Identity(name="user_b", role="customer", tenant="t1", researcher_owned=True, credential_ref="B_TOK")
        register(c, a); register(c, b)
        resource_mod.assert_ownership(c, resource_mod.Ownership(
            resource_type="order", resource_value="order-1", owner_identity="user_a",
            researcher_controlled=True))
        base = Variant(a, method="GET", path="/api/orders/1", resource="order-1", owner=a)
        mut = Variant(b, method="GET", path="/api/orders/1", resource="order-1", owner=a)
        leak = lambda *x: (200, {"content-type": "application/json"}, '{"total":9}')
        r = run(c, "differential_cross_account", "api.acme.example", base, mut, fetch=leak)
        f = finding_mod.promote(c, next(e for e in c.experiments() if e["id"] == r.experiment_id))

        # SUBMITTED before REPORT_READY is refused
        try:
            record(c, f.id, "SUBMITTED"); raise AssertionError("recorded submission for unearned finding")
        except ValueError:
            pass

        reproduce.verify(c, "differential_cross_account", "api.acme.example", base, mut,
                         trials=2, fetch=leak, finding_id=f.id)
        for step in (finding_mod.confirm_scope, finding_mod.confirm_boundary,
                     finding_mod.confirm_impact, finding_mod.complete_dedupe,
                     finding_mod.mark_report_ready):
            step(c, f.id)

        record(c, f.id, "SUBMITTED")
        rr = record(c, f.id, "ACCEPTED", reward="$500", notes="nice find")
        assert rr.outcome == "ACCEPTED" and rr.reward == "$500" and rr.submitted_at
        assert len(rr.history) == 2

        sig = priority_signal(c)
        assert sig["by_boundary_type"]["OWNER_NONOWNER"]["valuable"] == 1

        del os.environ["A_TOK"], os.environ["B_TOK"]
    del os.environ["ARGUS_HOME"]
    print("program_response demo passed")


if __name__ == "__main__":
    demo()
