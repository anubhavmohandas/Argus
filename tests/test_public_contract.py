"""Public contract guard — `InvestigationResult` and the shapes it carries.

This file exists to FAIL when a public shape changes. It asserts nothing about
whether Argus reasons well; it asserts that everything downstream of the engine
— the dossier, JSON output, the memory store, and every consumer not written yet
— can still read what the engine hands back.

Adding a field is compatible: update the frozen list below deliberately, in the
same commit, and say so. Removing or renaming one is not — that is a breaking
change to a contract with independent consumers, and it needs the compatibility
reasoning described in docs/ENGINEERING_PRINCIPLES.md ("Public contract
stability"), not just a passing test suite.

The last two checks are the ones that matter most. The shape is only half the
contract; the other half is the *guarantee* — a malformed rule pack costs you
reasoning, never the whole investigation.

    python3 test_public_contract.py
"""
import dataclasses
import json

from argus import engine
from argus.pivot import Graph, Entity

# --- the frozen surface ---------------------------------------------------
# Breaking change, made deliberately: `priority` stopped being a second output
# type and became a Conclusion kind. One list, one type, `kind` says which — so
# `PriorityItem` is gone, `Conclusion.priority` is now `severity` (it labels
# urgency, and could not keep a name that also names a kind), and `priority` is
# a filtered view rather than a field. The guarantee below is unchanged: what
# makes _priority() the floor is that it runs outside investigate()'s try, on
# every path, from engine code — never the shape it arrives in.
RESULT_FIELDS = ["conclusions", "fingerprint", "error"]
RESULT_PROPERTIES = ["risks", "priority", "interesting", "noise", "recommendations"]
RESULT_KEYS = ["conclusions", "recommendations", "fingerprint", "error"]
CONCLUSION_KEYS = ["kind", "rule", "rule_version", "name", "target", "target_type",
                   "confidence", "severity", "score", "ledger", "recommendations",
                   "hypotheses", "tags"]
KINDS = ["risk", "priority"]

_BREAKING = ("removing or renaming is a breaking change — see 'Public contract "
             "stability' in docs/ENGINEERING_PRINCIPLES.md; adding is fine, "
             "update this list in the same commit")


def _result():
    g = Graph()
    g.add(Entity("subdomain", "admin.example.com", 1))
    g.add(Entity("subdomain", "cdn.example.com", 1))
    return engine.investigate(g)


def _field_names(cls):
    return [f.name for f in dataclasses.fields(cls)]


def test_investigation_result_fields_are_frozen():
    assert _field_names(engine.InvestigationResult) == RESULT_FIELDS, _BREAKING


def test_investigation_result_properties_are_frozen():
    for p in RESULT_PROPERTIES:
        assert isinstance(getattr(engine.InvestigationResult, p, None), property), \
            f"{p} is part of the public surface — {_BREAKING}"


def test_carried_shapes_are_frozen():
    # Key SETS, not order: reordering to_dict() breaks nobody, adding or removing
    # a key breaks every consumer that reads the wire format.
    assert set(engine.Conclusion(
        rule="r", name="n", target="t", confidence=1, ledger={}).to_dict()) == set(CONCLUSION_KEYS), _BREAKING


def test_every_output_is_a_conclusion_of_a_known_kind():
    """The one-abstraction guarantee. A consumer switches on `kind` and is done —
    it never has to learn a second output type to read the whole result."""
    r = _result()
    assert r.conclusions, "a graph with entities always concludes something"
    for c in r.conclusions:
        assert isinstance(c, engine.Conclusion), f"{c!r} is not a Conclusion"
        assert c.kind in KINDS, f"unknown kind {c.kind!r} — {_BREAKING}"
        assert c.ledger["final"] == c.score, f"{c.rule} carries a score its ledger does not explain"
    assert r.risks and r.priority, "both kinds must be present in a healthy run"
    assert sorted(r.risks + r.priority, key=id) == sorted(r.conclusions, key=id), \
        "the views must partition the list, not shadow a hidden output"


def test_wire_format_is_frozen_and_serializable():
    d = _result().to_dict()
    assert set(d) == set(RESULT_KEYS), _BREAKING
    # to_dict() IS the wire format: JSON output, the memory store, any future API.
    # A field that cannot serialize breaks all of them at once.
    json.dumps(d)


def test_investigate_is_the_only_entry_point_and_returns_the_result():
    assert isinstance(_result(), engine.InvestigationResult)


# --- the guarantee, which is the half a shape test cannot cover -----------
def test_a_broken_rule_pack_costs_reasoning_but_never_the_investigation():
    """Rules can fail to load; "where do I look first?" still has to be answered.

    Unifying priority into `conclusions` did not weaken this — the floor is a
    property of where `_priority()` runs (engine code, outside the try, every
    path), not of which list it lands in."""
    g = Graph()
    g.add(Entity("subdomain", "admin.example.com", 1))
    for broken in ([{"no_id": True}],                        # malformed rule
                   [{"id": "x", "requires": {"not_a_predicate": True}}],  # outside vocabulary
                   ["not-a-table"],                          # malformed element
                   "not-a-list"):                            # malformed container
        r = engine.investigate(g, rules=broken)
        assert r.error, f"{broken!r} degraded silently — a config bug must never look like a clean result"
        assert r.risks == [], f"{broken!r} must not produce reasoning"
        assert r.priority, f"{broken!r} blanked the floor — investigate() must still rank the graph"


def test_the_error_is_carried_not_raised():
    g = Graph()
    g.add(Entity("subdomain", "admin.example.com", 1))
    r = engine.investigate(g, rules="not-a-list")   # must not raise
    assert r.error.startswith("RuleError"), r.error
    assert "error" in r.to_dict(), "consumers can only surface the failure if it reaches the wire"


def test_a_healthy_run_carries_no_error():
    r = _result()
    assert r.error == ""
    assert r.fingerprint, "a healthy run is reproducible — the fingerprint is part of the contract"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  PASS {name}")
    print("public contract intact")
