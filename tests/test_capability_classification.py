"""Slice 4 — explicit capability classification + legacy-gate coverage.

Every capability is PASSIVE, ACTIVE, or ACTIVE_HIGH_RISK, and the taxonomy is derived
from one table (policy._TECHNIQUES) so it cannot drift. The security invariant this
guards: every legacy provider that interacts with a target routes through `_gate`
with a technique that is genuinely active in that table — so no active capability can
ship gated only by the host-level backstop, or by a technique the gate doesn't know.
"""
import re
from pathlib import Path

from argus import policy

PROVIDERS_SRC = (Path(__file__).resolve().parent.parent / "argus" / "providers.py").read_text()
# every `_gate(host, "technique", ...)` literal the legacy active providers declare
_GATED = set(re.findall(r'_gate\([^,]+,\s*"([a-z_]+)"', PROVIDERS_SRC))


def test_classify_is_the_three_way_taxonomy():
    assert policy.classify("passive_lookup") == "PASSIVE"
    assert policy.classify("http_probe") == "ACTIVE"
    assert policy.classify("port_scan") == "ACTIVE"
    assert policy.classify("state_change") == "ACTIVE_HIGH_RISK"
    assert policy.classify("differential_cross_account") == "ACTIVE_HIGH_RISK"


def test_unknown_technique_classifies_as_most_restricted():
    # fail-safe: an unregistered capability is never treated as PASSIVE/safe
    assert policy.classify("totally_unknown") == "ACTIVE_HIGH_RISK"


def test_every_technique_maps_to_a_valid_class():
    for tech, (active, _risk) in policy._TECHNIQUES.items():
        cls = policy.classify(tech)
        assert cls in policy.CAPABILITY_CLASSES
        assert (cls == "PASSIVE") == (not active)   # PASSIVE iff not active — no mismatch


def test_legacy_active_providers_gate_on_a_real_active_technique():
    assert _GATED, "no _gate call sites found — the regex or the providers moved"
    for tech in _GATED:
        assert tech in policy._TECHNIQUES, f"_gate declares unknown technique {tech!r}"
        active, _ = policy._TECHNIQUES[tech]
        assert active, f"{tech!r} is gated for target interaction but classed PASSIVE"
        assert policy.classify(tech) in ("ACTIVE", "ACTIVE_HIGH_RISK")
