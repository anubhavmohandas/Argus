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
