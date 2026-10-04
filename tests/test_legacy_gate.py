"""The universal active gate on the legacy (non-orchestrated) provider path.

Before this, the CLI pivot/probe providers gated only on host-level `_permitted`
— so a program that forbade a technique ("no automated scanning") could not stop
`argus pivot --probe` from running a port scan or path probe: the host was in
scope, and that was the only question asked. Now every active provider routes its
one capability through `providers._gate` -> `policy.can_test`, the same decision
source the orchestrator uses. These tests pin the failure modes.
"""
import pytest

from argus import policy as policy_mod, providers, scope as scope_mod


def _pol(include=("acme.example",), exclude=(), **kw):
    return policy_mod.EngagementPolicy(
        scope=scope_mod.Scope(include=list(include), exclude=list(exclude)), **kw)


@pytest.fixture(autouse=True)
def _clean():
    providers.reset_engagement()
    yield
    providers.reset_engagement()


def test_gate_blocks_forbidden_technique_but_not_others():
    # "No automated scanning" forbids port_scan / path_probe / injection_probe (see
    # policy._FORBIDDEN_MAP) — but not a plain http_probe.
    providers.set_policy(_pol(forbidden=["No automated scanning of any kind"]))
    assert providers._gate("api.acme.example", "path_probe") is False
    assert providers._gate("api.acme.example", "port_scan") is False
    assert providers._gate("api.acme.example", "injection_probe") is False
    # http_probe is not forbidden; it is in scope and low-risk -> gate allows the
    # can_test half (host-backstop resolvability is a separate, always-on check).
    pol = providers._active().policy
    assert pol.can_test("api.acme.example", "http_probe").allowed is True


def test_gate_parks_high_risk_technique_instead_of_auto_running():
    # A high-risk technique returns HUMAN_APPROVAL from can_test. On the legacy path
    # there is no task to park, so the gate must refuse to auto-execute it.
    providers.set_policy(_pol())
    assert providers._gate("api.acme.example", "state_change") is False
    assert providers._gate("api.acme.example", "mass_enumeration") is False


def test_gate_denies_unknown_technique_fail_closed():
    providers.set_policy(_pol())
    assert providers._gate("api.acme.example", "totally_made_up") is False


def test_gate_falls_back_to_host_backstop_when_no_policy_armed():
    # Pre-policy behaviour: with only a scope (or nothing) armed, the gate is exactly
    # the host-level _permitted backstop — no technique decision, no regression.
    providers.set_scope(scope_mod.Scope(include=["acme.example"], exclude=[]))
    assert providers._gate("evil.invalid", "path_probe") is False       # out of scope
    assert providers._gate("evil.invalid", "path_probe") == providers._permitted("evil.invalid")


def test_forbidden_technique_is_impossible_through_a_real_provider(monkeypatch):
    # End-to-end: a forbidden path_probe must never reach the wire, even though the
    # host is in scope. admin_probe is a path_probe provider; _fetch is the only way it
    # can touch the target, so proving _fetch is never called proves it was blocked.
    calls = []
    monkeypatch.setattr(providers, "_fetch", lambda *a, **k: calls.append(a) or (0, {}, ""))
    providers.set_policy(_pol(forbidden=["Automated scanning is not allowed"]))
    result = providers.admin_probe("api.acme.example")
    assert calls == []                      # gate short-circuited before any request
    assert result == {}                     # {} == established nothing
