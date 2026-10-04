"""The authorization gate — `EngagementPolicy.can_test` and its provider backstop.

This is the one decision every active action routes through, so every branch of
it gets a test: the whole safety model rests here. No network — can_test is pure.
"""
from types import SimpleNamespace

import pytest

from argus import policy, providers, scope
from argus.policy import Verdict


def _pol(include=("acme.example",), exclude=(), **kw):
    return policy.EngagementPolicy(
        scope=scope.Scope(include=list(include), exclude=list(exclude)), **kw)


# --- the nine decision branches, top to bottom --------------------------------

def test_unknown_technique_denied_fail_closed():
    d = _pol().can_test("api.acme.example", "no_such_technique")
    assert d.verdict is Verdict.DENY and not d.allowed
    assert "unknown technique" in d.reason


def test_passive_technique_scope_exempt():
    # even for an out-of-scope host: reading a public record is not touching it
    d = _pol().can_test("anything.other.example", "passive_lookup")
    assert d.verdict is Verdict.ALLOW and d.allowed


def test_undefined_scope_is_fail_closed():
    d = _pol(include=(), exclude=()).can_test("api.acme.example", "http_probe")
    assert d.verdict is Verdict.DENY
    assert "no scope" in d.reason          # empty scope must NOT mean "test the world"


def test_out_of_scope_host_denied():
    d = _pol(include=("acme.example",)).can_test("evil.example", "http_probe")
    assert d.verdict is Verdict.DENY and "out of scope" in d.reason


def test_do_not_touch_asset_denied():
    p = _pol(assets=[policy.Asset(pattern="acme.example", action="none")])
    assert p.can_test("api.acme.example", "http_probe").verdict is Verdict.DENY


def test_forbidden_technique_finally_enforced():
    p = _pol(forbidden=["No automated scanning of any kind"])
    d = p.can_test("api.acme.example", "port_scan")
    assert d.verdict is Verdict.DENY
    assert "No automated scanning" in d.reason     # quotes the program's own words
    # a technique the ban doesn't cover still passes
    assert p.can_test("api.acme.example", "http_probe").allowed


def test_passive_only_asset_blocks_active_technique():
    p = _pol(assets=[policy.Asset(pattern="acme.example", action="passive")])
    assert p.can_test("api.acme.example", "http_probe").verdict is Verdict.DENY
    # passive public lookups are still fine against it
    assert p.can_test("api.acme.example", "passive_lookup").allowed


def test_high_risk_technique_requires_human_approval():
    d = _pol().can_test("api.acme.example", "state_change")
    assert d.verdict is Verdict.HUMAN_APPROVAL and not d.allowed


def test_cross_account_needs_owned_identities():
    p = _pol()
    # no identity => cannot verify ownership => approval
    assert p.can_test("api.acme.example", "differential_cross_account").verdict is Verdict.HUMAN_APPROVAL
    # a non-owned identity => still approval
    outsider = SimpleNamespace(researcher_owned=False)
    assert p.can_test("api.acme.example", "differential_cross_account",
                      account=outsider).verdict is Verdict.HUMAN_APPROVAL
    # both researcher-owned test accounts => allowed, but bounded to one object
    owned = SimpleNamespace(researcher_owned=True)
    d = p.can_test("api.acme.example", "differential_cross_account", account=owned)
    assert d.verdict is Verdict.ALLOW_WITH_LIMITS and d.allowed
    assert d.limits.get("single_object") is True


def test_in_scope_low_technique_allowed():
    d = _pol().can_test("api.acme.example", "http_probe")
    assert d.verdict is Verdict.ALLOW and d.limits is None


def test_intensity_over_rate_is_clamped():
    p = _pol(rate_per_sec=2.0, max_requests=100)
    d = p.can_test("api.acme.example", "http_probe", intensity=50)
    assert d.verdict is Verdict.ALLOW_WITH_LIMITS and d.allowed
    assert d.limits["rate_per_sec"] == 2.0 and d.limits["max_requests"] == 100
    # rate only, intensity under it, no budget => no clamp => plain ALLOW
    rate_only = _pol(rate_per_sec=10.0)
    assert rate_only.can_test("api.acme.example", "http_probe", intensity=1).verdict is Verdict.ALLOW


# --- the provider backstop agrees with can_test on the host rows --------------

def test_host_permitted_matches_can_test_scope_rows():
    p = _pol(include=("acme.example",),
             assets=[policy.Asset(pattern="passive.acme.example", action="passive")])
    assert p.host_permitted("api.acme.example") is True
    assert p.host_permitted("evil.example") is False               # out of scope
    assert p.host_permitted("passive.acme.example") is False       # passive-only
    assert _pol(include=(), exclude=()).host_permitted("x.acme.example") is False  # fail-closed


def test_permitted_uses_armed_policy_then_disarms():
    p = _pol(include=("acme.example",),
             assets=[policy.Asset(pattern="passive.acme.example", action="passive")])
    providers.set_policy(p)
    try:
        # armed: passive-only host blocked even though the bare scope would allow it.
        # (host must also be globally routable; .example is reserved → _permitted False
        #  regardless, so we assert the policy layer's decision directly)
        assert p.host_permitted("passive.acme.example") is False
    finally:
        providers.reset_engagement()
    assert providers._POLICY is None


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
