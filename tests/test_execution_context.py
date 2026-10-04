"""Campaign-bound ExecutionContext — the isolation invariant.

The point of ExecutionContext is that once more than one campaign runs in one
process, campaign A can never inherit campaign B's scope / rate / budget / headers
/ policy through shared process state. These tests pin the failure modes, not the
happy path: a leak here is a safety incident (A probing B's out-of-scope host, or
A sending B's identity header), so each test is a concrete "must NOT leak".
"""
import concurrent.futures

import pytest

from argus import policy as policy_mod, providers, scope as scope_mod

PROG_A = "Assets:\n*.alpha.example\nOut of scope:\nsecret.alpha.example\n"
PROG_B = "Assets:\n*.beta.example\n"

# header/budget/rate come from policy fields the real CLI path sets on the compiled
# object (see test_policy_engagement), not from the scope DSL — so set them directly.
CTX_A = dict(headers={"X-Program": "alpha-handle"}, max_requests=10)
CTX_B = dict(headers={"X-Program": "beta-handle"}, max_requests=100)


@pytest.fixture(autouse=True)
def _clean_globals():
    """No test here may leak the legacy default globals into another test."""
    providers.reset_engagement()
    yield
    providers.reset_engagement()


def _ctx(program, headers=None, max_requests=None, rate=None, cid="cid"):
    p = policy_mod.compile(program)
    if headers is not None:
        p.request_headers = headers
    if max_requests is not None:
        p.max_requests = max_requests
    if rate is not None:
        p.rate_per_sec = rate
    return p.execution_context(campaign_id=cid)


def test_headers_do_not_leak_between_campaigns():
    a, b = _ctx(PROG_A, **CTX_A), _ctx(PROG_B, **CTX_B)
    assert a.id_headers == {"X-Program": "alpha-handle"}
    with providers.bound_context(a):
        assert providers._active().id_headers == {"X-Program": "alpha-handle"}
    with providers.bound_context(b):
        assert providers._active().id_headers == {"X-Program": "beta-handle"}
    # a was never mutated by b being bound
    assert a.id_headers == {"X-Program": "alpha-handle"}


def test_scope_does_not_leak_between_campaigns():
    a, b = _ctx(PROG_A, **CTX_A), _ctx(PROG_B, **CTX_B)
    # Under A, beta's host is out of scope and denied; under B it is in scope.
    # (host_permitted is the policy's scope decision; SSRF resolve is separate.)
    with providers.bound_context(a):
        assert providers._active().policy.host_permitted("api.beta.example") is False
        assert providers._active().policy.host_permitted("api.alpha.example") is True
    with providers.bound_context(b):
        assert providers._active().policy.host_permitted("api.beta.example") is True
        assert providers._active().policy.host_permitted("api.alpha.example") is False


def test_budget_exhaustion_is_per_campaign():
    a, b = _ctx(PROG_A, **CTX_A), _ctx(PROG_B, **CTX_B)   # A budget 10, B budget 100
    for _ in range(10):
        assert a.throttle.acquire() is True
    assert a.throttle.acquire() is False            # A spent
    with providers.bound_context(a):
        assert providers.budget_exhausted() is True
    with providers.bound_context(b):
        assert providers.budget_exhausted() is False  # B untouched by A's spend


def test_unbound_falls_back_to_legacy_globals():
    # The single-run CLI path: no context bound => the legacy setters are authoritative.
    providers.set_headers({"X-Legacy": "yes"})
    providers.set_rate(max_requests=2)
    assert providers._active().id_headers == {"X-Legacy": "yes"}
    assert providers.budget_exhausted() is False
    assert providers._active().throttle.acquire() is True
    assert providers._active().throttle.acquire() is True
    assert providers._active().throttle.acquire() is False  # legacy budget of 2 spent


def test_ctxpool_propagates_bound_context_to_worker_threads():
    # The thread-propagation guarantee: a provider's fan-out must not drop the campaign
    # context (plain ThreadPoolExecutor would — _CtxPool is why this holds).
    a = _ctx(PROG_A, **CTX_A)
    plain_seen, ctx_seen = [], []

    def grab(sink):
        sink.append(providers._active().id_headers.get("X-Program"))

    with providers.bound_context(a):
        with providers._CtxPool(max_workers=4) as ex:
            list(ex.map(lambda _: grab(ctx_seen), range(4)))
        # a *plain* pool would lose the context (control, proving the subclass matters)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            list(ex.map(lambda _: grab(plain_seen), range(4)))

    assert ctx_seen == ["alpha-handle"] * 4     # _CtxPool carried it in
    assert plain_seen == [None] * 4             # plain pool saw the unbound default


def test_apply_still_arms_legacy_default_only():
    # apply() remains the migration shim: it mutates the legacy default, and a bound
    # campaign context is NOT disturbed by it.
    b = _ctx(PROG_B, **CTX_B)
    pa = policy_mod.compile(PROG_A); pa.request_headers = {"X-Program": "alpha-handle"}; pa.apply()
    assert providers._active().id_headers == {"X-Program": "alpha-handle"}  # default = A
    with providers.bound_context(b):
        assert providers._active().id_headers == {"X-Program": "beta-handle"}  # bound = B
    assert providers._active().id_headers == {"X-Program": "alpha-handle"}  # back to default A
