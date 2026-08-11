"""The `program` queue: which assets become concrete seeds, in what order.

Isolated from the policy compiler on purpose — `_concrete_hosts` only consumes
`pol.assets` + `pol.scope`, so it is tested against constructed assets. The rules
it must never break: a wildcard does not authorize the apex, a CIDR range is not a
host, `action == "none"` never runs, dups collapse, tier1 leads."""
from argus import scope as scope_mod
from argus.policy import Asset, EngagementPolicy
from argus.cli import _concrete_hosts


def _pol(assets):
    sc = scope_mod.Scope(include=["example.com", "203.0.113.7"], exclude=["old.example.com"])
    return EngagementPolicy(scope=sc, assets=assets)


def test_queue_shape():
    pol = _pol([
        Asset("zed.example.com", tier=3),
        Asset("alpha.example.com", tier=1),
        Asset("*.example.com"),                  # wildcard -> not the apex, skip
        Asset("alpha.example.com", tier=1),      # duplicate collapses
        Asset("203.0.113.0/24"),                 # range -> not a host, skip
        Asset("203.0.113.7"),                    # single IP -> keep
        Asset("old.example.com", action="none"), # out of scope -> never runs
        Asset("SDM firmware", network=False),    # non-network -> skip
    ])
    queue, skipped = _concrete_hosts(pol)
    assert [a.pattern for a in queue] == ["alpha.example.com", "zed.example.com", "203.0.113.7"]
    assert skipped == 2   # the wildcard and the CIDR range


def test_untiered_sorts_after_tiered():
    pol = _pol([Asset("a.example.com"), Asset("b.example.com", tier=2)])
    assert [a.pattern for a in _concrete_hosts(pol)[0]] == ["b.example.com", "a.example.com"]
