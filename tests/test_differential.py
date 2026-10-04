"""Differential runner — the safety invariants first, then the comparison logic.

The runner sends real active requests as two identities, so the tests that matter most
are the ones proving it NEVER sends one the policy didn't clear — especially that a
non-researcher-owned (real) victim's object is never touched automatically.
"""
import os

import pytest

from argus import campaign, differential, identity, orchestrator
from argus.differential import Variant, normalize, compare, run
from argus.identity import Identity
from argus.orchestrator import Orchestrator, Task
from argus.policy import Verdict


@pytest.fixture
def camp(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_HOME", str(tmp_path))
    monkeypatch.setenv("A_TOK", "tok-a")
    monkeypatch.setenv("B_TOK", "tok-b")
    c = campaign.create("Assets:\napi.acme.example\nRate: 5 requests/sec\n", name="Acme")
    identity.register(c, Identity(name="user_a", researcher_owned=True, credential_ref="A_TOK"))
    identity.register(c, Identity(name="user_b", researcher_owned=True, credential_ref="B_TOK"))
    return c


USER_A = Identity(name="user_a", researcher_owned=True, credential_ref="A_TOK")
USER_B = Identity(name="user_b", researcher_owned=True, credential_ref="B_TOK")
VICTIM = Identity(name="victim", researcher_owned=False)   # a REAL user, not the researcher's


def _cross(owner):
    """A cross-account pair: A and B both hit the SAME object owned by `owner`."""
    base = Variant(USER_A, method="POST", path="/api/orders/1/cancel", resource="o1", owner=owner)
    mut = Variant(USER_B, method="POST", path="/api/orders/1/cancel", resource="o1", owner=owner)
    return base, mut


def test_demo():
    differential.demo()


# --- SAFETY INVARIANTS ----------------------------------------------------

def test_real_victims_object_is_never_executed(camp):
    """THE invariant: a cross-account test against a non-researcher-owned object parks for
    approval and sends ZERO requests. This is the line between authorized research and
    attacking a real user."""
    base, mut = _cross(owner=VICTIM)
    fired = []
    r = run(camp, "differential_cross_account", "api.acme.example", base, mut,
            fetch=lambda *a: (fired.append(a) or (200, {}, "")))
    assert fired == [], "a real user's object was touched"
    assert not r.executed
    assert r.decision == Verdict.HUMAN_APPROVAL.value


def test_each_request_is_gated_independently(camp):
    """An out-of-scope host denies BOTH requests — the gate is per-request, so nothing
    is sent even though a (hypothetical) parent approval existed."""
    base, mut = _cross(owner=USER_A)
    hits = []
    r = run(camp, "differential_cross_account", "evil.other.example", base, mut,
            fetch=lambda *a: (hits.append(a) or (200, {}, "")))
    assert hits == [] and not r.executed
    assert "out of scope" in r.decision_reason


def test_secret_never_persisted(camp):
    base, mut = _cross(owner=USER_A)
    r = run(camp, "differential_cross_account", "api.acme.example", base, mut,
            fetch=lambda *a: (200, {}, "{}"))
    disk = (camp.dir / "observations" / f"{r.mutation_obs}.json").read_text()
    assert "tok-b" not in disk and "tok-a" not in disk
    obs = {o["id"]: o for o in camp.observations()}
    assert obs[r.mutation_obs]["request"]["headers"] == {"Authorization": "<redacted>"}


# --- CLASSIFICATION -------------------------------------------------------

def test_bypass_is_suspicious(camp):
    """B reaches A's object (both 200) => authorization boundary => suspicious candidate."""
    base, mut = _cross(owner=USER_A)
    r = run(camp, "differential_cross_account", "api.acme.example", base, mut,
            fetch=lambda *a: (200, {"content-type": "application/json"}, '{"ok":true}'))
    assert r.executed and r.classification == "suspicious"


def test_enforced_ownership_is_secure(camp):
    """B is denied (403) => ownership enforced => secure, NOT a false positive, even though
    the access outcome differs between the two identities."""
    base, mut = _cross(owner=USER_A)

    def enforced(method, url, headers, body):
        granted = headers.get("Authorization") == "Bearer tok-a"
        return (200 if granted else 403), {}, "{}"

    r = run(camp, "differential_cross_account", "api.acme.example", base, mut, fetch=enforced)
    assert r.executed and r.classification == "secure"
    assert r.comparison["access"] == ["granted", "denied"]


def test_unreachable_is_inconclusive(camp):
    base, mut = _cross(owner=USER_A)
    r = run(camp, "differential_cross_account", "api.acme.example", base, mut,
            fetch=lambda *a: (0, {}, ""))        # never connected
    assert r.classification == "inconclusive"


# --- COMPARISON / CONTROLLED-MUTATION RULES -------------------------------

def test_single_mutation_enforced(camp):
    """Two changed axes (identity AND path) is uncontrolled fuzzing — refused."""
    base = Variant(USER_A, path="/a", resource="r", owner=USER_A)
    two = Variant(USER_B, path="/b", resource="r", owner=USER_A)     # identity + path differ
    with pytest.raises(ValueError, match="exactly ONE"):
        run(camp, "differential_cross_account", "api.acme.example", base, two)


def test_zero_mutation_refused(camp):
    base = Variant(USER_A, path="/a", resource="r", owner=USER_A)
    with pytest.raises(ValueError, match="exactly ONE"):
        run(camp, "differential_cross_account", "api.acme.example", base, base)


def test_volatile_noise_is_normalized():
    a = normalize(200, {"date": "d1", "x-request-id": "1"},
                  '{"id":"550e8400-e29b-41d4-a716-446655440000","at":"2026-01-01T00:00:00Z"}')
    b = normalize(200, {"date": "d2", "x-request-id": "2"},
                  '{"id":"550e8400-e29b-41d4-a716-446655449999","at":"2026-09-09T09:09:09Z"}')
    assert not compare(a, b)["body_changed"]
    assert not compare(a, b)["status_changed"]


def test_security_header_change_detected():
    a = normalize(200, {"x-frame-options": "DENY"}, "x")
    b = normalize(200, {}, "x")
    assert compare(a, b)["security_headers_changed"]


# --- END TO END THROUGH THE ORCHESTRATOR ----------------------------------

def test_through_orchestrator_nyx_proposes_argus_executes(camp, monkeypatch):
    """NYX proposes a differential task -> gate QUEUES it (owner researcher-owned) ->
    the default differential worker runs -> the orchestrator adopts the runner's single
    Experiment (no duplicate)."""
    monkeypatch.setattr(differential, "_default_fetch",
                        lambda method, url, headers, body: (200, {"content-type": "application/json"}, "{}"))
    orch = Orchestrator(camp)
    t = orch.propose(Task(
        campaign_id=camp.id, technique="differential_cross_account", host="api.acme.example",
        hypothesis="does cancel enforce ownership?", identity="user_a",
        account=USER_A,                          # owner is researcher-owned => QUEUED, not parked
        spec={"baseline": {"identity": "user_a", "method": "POST",
                           "path": "/api/orders/1/cancel", "resource": "o1", "owner": "user_a"},
              "mutation": {"identity": "user_b", "method": "POST",
                           "path": "/api/orders/1/cancel", "resource": "o1", "owner": "user_a"}}))
    assert t.state == "QUEUED"
    orch.run()
    assert t.state == "EVALUATED"
    exps = camp.experiments()
    assert len(exps) == 1                          # exactly one Experiment — adoption, no duplicate
    exp = exps[0]
    assert exp["technique"] == "differential_cross_account"
    assert exp["classification"] == "suspicious"
    assert exp["mutation"]["axis"] == "identity"
    assert exp["id"] == t.experiment_id
    assert len(camp.observations()) == 2          # baseline + mutation, both recorded


def test_orchestrator_parks_real_victim_for_approval(camp):
    """The same task against a non-owned account is parked, never queued — the worker
    never even runs."""
    orch = Orchestrator(camp)
    t = orch.propose(Task(
        campaign_id=camp.id, technique="differential_cross_account", host="api.acme.example",
        account=VICTIM,                           # not researcher-owned
        spec={"baseline": {"identity": "user_a", "owner": "victim"},
              "mutation": {"identity": "user_b", "owner": "victim"}}))
    assert t.state == "APPROVAL_REQUIRED"
    assert orch.run() == 0                         # nothing executes


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
