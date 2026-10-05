"""Reproducibility engine — is a suspicious differential a real, repeatable result?

A single leaky response can be a cache hit, a race, a flaky backend. Before a candidate
is worth a human's attention it has to REPRODUCE: run the exact same controlled
differential again, with fresh requests, and get the same answer. This module does that
and judges stability deterministically.

Each trial is a full `differential.run` — its own policy-gated Experiment with its own
Observations — so reproduction doesn't overwrite the original evidence, it adds more of
it. The `ReproReport` links every trial, so "it reproduced 3/3" is itself auditable.

The judgement is deliberately strict: reproduced ⇔ EVERY trial agrees with the original
classification AND that class is `suspicious`. A split (2 suspicious, 1 secure) is NOT
reproduced — it's flaky, which is a finding about the target's nondeterminism, not a
confirmed boundary. On reproduction, the linked finding advances OBSERVED → REPRODUCIBLE;
nothing here invents `vulnerable` (that's impact, a later stage).

occam: trial count defaults to 2 extra runs (3 total observations of the boundary); the
provider throttle already paces them, so no sleep here. Majority-vote and statistical
flakiness scoring are the upgrade path when a target proves genuinely noisy.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from . import differential, finding as finding_mod


@dataclass
class ReproReport:
    technique: str
    host: str
    original: str                              # the classification being checked ("suspicious")
    trials: int
    classifications: list[str] = field(default_factory=list)
    experiment_ids: list[str] = field(default_factory=list)
    reproduced: bool = False
    finding_id: str = ""                       # set when a finding was advanced to REPRODUCIBLE


def verify(campaign, technique: str, host: str, baseline, mutation,
           original: str = "suspicious", trials: int = 2, fetch=None,
           finding_id: str = "") -> ReproReport:
    """Re-run the differential `trials` times and judge whether `original` reproduces.
    Strict: reproduced only if every trial matches `original` AND that class is
    suspicious. When reproduced and `finding_id` is given, advances that finding
    OBSERVED → REPRODUCIBLE (idempotent — skips if already past OBSERVED). Returns a
    ReproReport linking every trial experiment."""
    rep = ReproReport(technique=technique, host=host, original=original, trials=trials)
    for _ in range(max(1, trials)):
        r = differential.run(campaign, technique, host, baseline, mutation,
                             hypothesis=f"reproduce: {original}", fetch=fetch)
        rep.classifications.append(r.classification)
        rep.experiment_ids.append(r.experiment_id)

    rep.reproduced = (original == "suspicious"
                      and all(c == original for c in rep.classifications))
    campaign.audit("reproducibility_check", technique=technique, host=host,
                   original=original, trials=trials,
                   classifications=rep.classifications, reproduced=rep.reproduced)

    if rep.reproduced and finding_id:
        f = finding_mod._get(campaign, finding_id)
        if f is not None and f.state == "OBSERVED":
            finding_mod.advance(campaign, finding_id, "REPRODUCIBLE",
                                note=f"reproduced {len(rep.classifications)}/"
                                     f"{len(rep.classifications)} trials")
            rep.finding_id = finding_id
    return rep


def background_verify(campaign, finding_id: str, trials: int = 2):
    """Return (planner, on_complete) to reproduce a finding through a CampaignRunCoordinator
    — the SAME execution system as a pivot, not a separate one. The planner proposes
    `trials` differential Tasks (reusing the orchestrator's differential worker and the
    ORIGINAL task's persisted baseline/mutation spec, so the exact controlled differential
    re-runs); the coordinator drains them under can_test like any task, so pause/stop apply.
    on_complete judges stability from the trial Observations' classifications and advances
    the finding OBSERVED → REPRODUCIBLE on a clean reproduction.

    Strict judgement is unchanged: reproduced ⇔ every trial agrees AND the class is
    suspicious. Raises ValueError (the caller turns it into a 4xx) if the finding or its
    original differential task cannot be found — reproduction is never fabricated."""
    from .orchestrator import Task
    f = finding_mod._get(campaign, finding_id)
    if f is None:
        raise ValueError(f"no finding {finding_id!r}")
    if not f.technique.startswith("differential"):
        raise ValueError(f"finding {finding_id!r} is not a differential — nothing to re-run")
    group = f"repro-{uuid.uuid4().hex[:8]}"

    def planner(co):
        orig = next((t for t in co.orch.tasks.values()
                     if t.experiment_id == f.experiment_id and t.spec and "baseline" in t.spec), None)
        if orig is None:
            raise ValueError(f"no original differential task for finding {finding_id!r} to reproduce")
        original = next((e.get("classification") for e in co.c.experiments()
                         if e["id"] == f.experiment_id), "") or "suspicious"
        # carry the original's executing identity so a trial re-runs under the SAME
        # authorization as the original (not re-parked for approval on a technicality).
        acct = orig.account
        if acct is None and orig.account_name:
            from . import identity as id_mod
            acct = id_mod.get(co.c, orig.account_name)
        for _ in range(max(1, trials)):
            spec = dict(orig.spec)
            spec.update(_repro=group, _finding=finding_id, _original=original)
            co.orch.propose(Task(campaign_id=co.c.id, technique=f.technique, host=f.host,
                                 hypothesis=f"reproduce: {original}", intensity=orig.intensity,
                                 account=acct, account_name=orig.account_name, spec=spec))

    def on_complete(co):
        trials_done = [t for t in co.orch.tasks.values()
                       if (t.spec or {}).get("_repro") == group]
        if not trials_done:
            return
        original = (trials_done[0].spec or {}).get("_original", "suspicious")
        by_exp = {e["id"]: e for e in co.c.experiments()}
        classes = [by_exp.get(t.experiment_id, {}).get("classification", "")
                   for t in trials_done if t.state == "EVALUATED"]
        reproduced = (original == "suspicious" and len(classes) == len(trials_done)
                      and all(cl == original for cl in classes))
        co.c.audit("reproducibility_check", technique=f.technique, host=f.host,
                   original=original, trials=len(trials_done), classifications=classes,
                   reproduced=reproduced, finding=finding_id)
        if reproduced:
            cur = finding_mod._get(co.c, finding_id)
            if cur is not None and cur.state == "OBSERVED":
                finding_mod.advance(co.c, finding_id, "REPRODUCIBLE",
                                    note=f"reproduced {len(classes)}/{len(trials_done)} trials")

    return planner, on_complete


def demo() -> None:
    """Self-check (offline): a stably-leaky boundary reproduces and advances the finding;
    a flaky one (alternating 200/403) does not reproduce and leaves the finding OBSERVED."""
    import os
    import tempfile
    from . import campaign as campaign_mod
    from .differential import Variant, run
    from .identity import Identity

    with tempfile.TemporaryDirectory() as tmp:
        os.environ["ARGUS_HOME"] = tmp
        os.environ["A_TOK"], os.environ["B_TOK"] = "tok-a", "tok-b"
        c = campaign_mod.create("Assets:\napi.acme.example\nRate: 9 requests/sec\n", name="Acme")
        a = Identity(name="user_a", researcher_owned=True, credential_ref="A_TOK")
        b = Identity(name="user_b", researcher_owned=True, credential_ref="B_TOK")
        base = Variant(a, method="POST", path="/o/1/cancel", resource="o1", owner=a)
        mut = Variant(b, method="POST", path="/o/1/cancel", resource="o1", owner=a)

        # a stable leak: B always gets 200 on A's object
        leak = lambda *x: (200, {"content-type": "application/json"}, "{}")
        first = run(c, "differential_cross_account", "api.acme.example", base, mut, fetch=leak)
        assert first.classification == "suspicious"
        f = finding_mod.promote(c, next(e for e in c.experiments() if e["id"] == first.experiment_id))
        assert f.state == "OBSERVED"

        rep = verify(c, "differential_cross_account", "api.acme.example", base, mut,
                     trials=3, fetch=leak, finding_id=f.id)
        assert rep.reproduced and rep.classifications == ["suspicious"] * 3
        assert len(rep.experiment_ids) == 3
        assert finding_mod._get(c, f.id).state == "REPRODUCIBLE"    # advanced

        # a flaky target: alternates granted/denied — NOT reproduced
        flip = {"n": 0}
        def flaky(*x):
            flip["n"] += 1
            return (200 if flip["n"] % 2 else 403), {}, "{}"
        base2 = Variant(a, method="GET", path="/o/2", resource="o2", owner=a)
        mut2 = Variant(b, method="GET", path="/o/2", resource="o2", owner=a)
        g = finding_mod.promote(c, {"id": "exp-flaky", "technique": "differential_cross_account",
                                    "host": "api.acme.example", "classification": "suspicious"})
        rep2 = verify(c, "differential_cross_account", "api.acme.example", base2, mut2,
                      trials=4, fetch=flaky, finding_id=g.id)
        assert not rep2.reproduced, rep2.classifications
        assert finding_mod._get(c, g.id).state == "OBSERVED"       # unchanged — not confirmed

        del os.environ["A_TOK"], os.environ["B_TOK"]
    del os.environ["ARGUS_HOME"]
    print("reproduce demo passed")


if __name__ == "__main__":
    demo()
