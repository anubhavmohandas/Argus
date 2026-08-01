"""Behavioral invariants of the Investigator Rule Engine.

These are NOT unit tests of code paths — test_argus.py covers those. These are
end-to-end investigations that protect the *philosophy* of the engine: how it
must behave for a human investigator to trust it. Each test builds a real graph,
runs the one reasoning entry point (engine.investigate), and asserts a property
that must never regress no matter how the rule packs grow.

    python3 test_investigation_invariants.py   # asserts, exits 0 on pass

The four invariants:
  1. Discovery alone is never overconfident — a name is a lead, not a finding.
  2. Verified evidence always outranks a same-named suspicion.
  3. A fully-probed investigation carries no lingering unknowns.
  4. Silence is never a negative — the differentiator (invariant I-1).
"""
from argus import engine
from argus.pivot import Graph, Entity

_RULES = engine.load_rules()


def _has_open_unknowns(c) -> bool:
    return any(ln.startswith("open:") for ln in engine.ledger_lines(c))


def test_discovery_only_is_never_overconfident():
    """Names are leads. With zero probes, no conclusion may reach the
    probe-confirmed band (>=65), every lead must still surface its unknowns,
    and the run must still produce investigative recommendations."""
    g = Graph()
    for v in ("jenkins.example.com", "admin.example.com", "staging.example.com",
              "cdn-static.example.com", "www.example.com"):
        g.add(Entity("subdomain", v, 1))
    r = engine.investigate(g, _RULES)

    assert r.conclusions, "discovery should still yield leads"
    assert max(c.confidence for c in r.conclusions) < 65, \
        "a name-only lead must never score like a verified finding"
    for c in r.conclusions:
        if c.priority == "noise":
            continue  # noise rules are static deprioritize notes, no probes to open
        assert _has_open_unknowns(c), f"{c.rule} hides that nothing was probed"
    assert r.recommendations, "leads must produce investigative recommendations"


def test_verified_outranks_suspected():
    """A probe-confirmed fact must rank above a same-named suspicion, and the
    verified host must lead the ranked output."""
    g = Graph()
    g.add(Entity("subdomain", "jenkins.example.com", 1,
                 evidence={"technology": "jenkins", "internet_facing": True}))
    g.add(Entity("subdomain", "admin.example.com", 1))   # name-only, never probed
    r = engine.investigate(g, _RULES)

    confirmed = max(c.confidence for c in r.conclusions if c.rule == "jenkins_confirmed")
    suspected = max(c.confidence for c in r.conclusions if c.rule == "jenkins_suspected")
    assert confirmed > suspected, f"verified ({confirmed}) must outrank suspected ({suspected})"
    assert r.conclusions[0].target == "jenkins.example.com", \
        "ranked output must lead with the probe-verified host"


def test_fully_probed_investigation_has_no_unknowns():
    """When every predicate a rule reads has been probed — including the
    confirmed-negatives — no conclusion may still report open unknowns, and the
    verified facts must yield a strong (>=65) conclusion."""
    g = Graph()
    g.add(Entity("subdomain", "jenkins.example.com", 1, evidence={
        "technology": "jenkins", "internet_facing": True,
        "public_exploit": True, "known_exploited": True,
        "authentication_required": True,          # a real negative, honestly recorded
    }))
    g.add(Entity("subdomain", "admin.example.com", 1, evidence={
        "has_admin_interface": True, "internet_facing": True,
        "authentication_required": True,
        "public_exploit": False,                  # probed confirmed-negative, not unknown
    }))
    r = engine.investigate(g, _RULES)

    for c in r.conclusions:
        assert not _has_open_unknowns(c), \
            f"{c.rule} reports unknowns though every predicate was probed"
    assert max(c.confidence for c in r.conclusions) >= 65, \
        "confirmed facts must yield a strong conclusion"


def test_silence_is_never_a_negative():
    """The differentiator (I-1): a rule requiring a negative must NOT fire on a
    host nobody probed. 'No provider asserted it' is not 'it is false'."""
    g = Graph()
    g.add(Entity("subdomain", "unchecked.example.com", 1))
    assumes_no_auth = [{"id": "assumes_no_auth", "base_confidence": 50,
                        "requires": {"authentication_required": False}, "outputs": {}}]
    assert engine.evaluate(g, assumes_no_auth) == [], \
        "silence must never satisfy a requirement — that would invent negative evidence"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  PASS {name}")
    print("all investigation invariants hold")
