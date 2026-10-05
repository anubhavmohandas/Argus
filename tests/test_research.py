"""Pivot / program active execution is orchestrator-gated — the 'two-worlds' close.

Passive discovery stays direct and lightweight. Every target-touching capability
becomes a durable Task that passes `can_test` BEFORE any provider runs. These tests
exercise the BYPASS paths the spec named, not only the happy path:

  * in-scope active probe        -> proposed -> policy_decision -> worker executed
  * program-forbidden technique  -> DENIED, provider NEVER reached
  * out-of-scope host            -> DENIED, nothing touched
  * active work                  -> durable Task on disk
  * passive run                  -> NO fake active Tasks
  * `argus run`                  -> exposes only passive modules (no orchestrator bypass)
"""
import pytest

from argus import campaign as cmod, research
from argus.core import MODULES
from argus.orchestrator import Orchestrator
from argus.pivot import Entity, Graph


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_HOME", str(tmp_path))
    return tmp_path


@pytest.fixture
def calls(monkeypatch):
    """Replace every per-host enricher with a recorder: no network, and we can assert
    exactly which (enricher, host) pairs actually reached a provider."""
    log: list[tuple[str, str]] = []

    def rec(name):
        def enr(g, **kw):
            for e in g.nodes.values():
                log.append((name, e.value))
                e.evidence[name] = True
            return len(g.nodes)
        return enr

    from argus import providers
    for n, _, _ in research._UNITS:
        monkeypatch.setattr(providers, n, rec(n))
    for n, _ in research._ANALYSIS:            # silence real passive-analysis network
        monkeypatch.setattr(providers, n, lambda g, **kw: 0)
    return log


def _one(seed="api.acme.example", extra=""):
    return cmod.create(f"In scope:\n{seed}\n{extra}", name="acme")


def test_active_probe_is_proposed_gated_and_executed(home, calls):
    c = _one()
    g = Graph()
    g.add(Entity("domain", "api.acme.example", 0))
    orch = research.run_active(c, g, tiers={"probe"})

    http = next(t for t in orch.tasks.values() if t.technique == "http_probe")
    assert http.state == "EVALUATED" and http.verdict in ("ALLOW", "ALLOW_WITH_LIMITS")
    assert ("enrich", "api.acme.example") in calls          # the worker reached the provider
    events = [a["event"] for a in c.audit_trail()]
    for e in ("task_proposed", "policy_decision", "experiment_recorded"):
        assert e in events
    assert c.observations(), "the Observation is the durable evidence of record"
    # adapter projected evidence back into the live graph node (the index)
    assert g.nodes["domain:api.acme.example"].evidence.get("enrich") is True


def test_forbidden_technique_is_denied_and_provider_never_runs(home, calls):
    c = _one(extra="Forbidden:\nNo automated scanning\n")
    g = Graph()
    g.add(Entity("domain", "api.acme.example", 0))
    orch = research.run_active(c, g, tiers={"probe", "paths", "scan"})

    denied = {t.technique: t for t in orch.tasks.values() if t.state == "DENIED"}
    assert "port_scan" in denied and "path_probe" in denied and "injection_probe" in denied
    assert not any(n == "enrich_scan" for n, _ in calls)
    assert not any(n in ("enrich_admin", "enrich_exposure", "enrich_traversal") for n, _ in calls)
    # the ban is per-class: the low-risk HTTP probe is still allowed and ran
    assert any(n == "enrich" for n, _ in calls)


def test_out_of_scope_host_is_denied_and_untouched(home, calls):
    c = _one()                                              # scopes to api.acme.example only
    g = Graph()
    g.add(Entity("ip", "198.51.100.9", 1))                 # a resolved IP, NOT in scope
    orch = research.run_active(c, g, tiers={"probe"})
    assert orch.tasks and all(t.state == "DENIED" for t in orch.tasks.values())
    assert not calls


def test_active_tasks_are_durable(home, calls):
    c = _one()
    g = Graph()
    g.add(Entity("domain", "api.acme.example", 0))
    research.run_active(c, g, tiers={"probe"})
    reloaded = cmod.load(c.id)                              # a fresh process-equivalent load
    assert reloaded.tasks(), "active work must persist as durable Task records"


def test_passive_run_creates_no_active_tasks(home, calls):
    c = _one()
    g = Graph()
    g.add(Entity("domain", "api.acme.example", 0))
    orch = research.run_active(c, g, tiers=set())           # no active tiers
    assert not orch.tasks, "passive discovery must not fabricate active Tasks"
    assert not calls


def test_orchestrator_reuses_one_execution_context(home):
    # the cached context is what makes rate + budget SHARED across tasks (program's
    # one-cap-for-the-whole-run); a per-step rebuild would reset the budget each task.
    o = Orchestrator(_one())
    assert o._exec_context() is o._exec_context()


def test_ephemeral_campaign_fails_closed_outside_the_seed(home):
    c = research.ephemeral_campaign("api.example.com")
    assert c.policy.can_test("api.example.com", "http_probe").allowed
    assert c.policy.can_test("sub.api.example.com", "http_probe").allowed   # subdomain in scope
    d = c.policy.can_test("evil.other.example", "http_probe")
    assert not d.allowed and "out of scope" in d.reason


# `argus run <module>` must never become the active-execution bypass. Active
# target-probes live in providers.enrich_* (orchestrated), never as runnable modules.
# If a new module appears here, confirm it is passive (add it) or route it through the
# orchestrator — do not let `run` reach a target without can_test.
_PASSIVE_MODULES = {
    "dns", "github_dork", "github_org", "ip", "jsmap", "phone", "postman_dork",
    "rdap", "secrets", "subdomains", "urlscan", "username", "wayback",
}


def test_run_exposes_only_passive_modules():
    assert set(MODULES) == _PASSIVE_MODULES, (
        "a new `run` module appeared — if it touches a bug-bounty target, route it "
        "through research.run_active; `argus run` must not bypass the orchestrator")
