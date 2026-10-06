"""Durable surface projection — the background pivot's graph must outlive its run thread.

The bug this guards against: the discovery graph (entities + edges + the evidence active
probes project into each node) living ONLY inside the planner closure, so it vanished the
moment the coordinator loop ended. A researcher who looked away for ten seconds, or whose
browser dropped the SSE stream, came back to nothing.

Locked here: a background pivot persists the graph the instant discovery finishes, grows
it durably as active work runs, writes the final dossier (with investigation conclusions)
at completion, and all of it survives the run thread ending AND a fresh campaign reload —
so the API serves a real surface, not an in-memory ghost.

Offline: pivot discovery and every per-host enricher are stubbed; no target is touched.
"""
import os
import time

import pytest

from argus import campaign as cmod, providers, research
from argus.pivot import Entity, Graph
from argus.run import _reset_registry, coordinator_for

PROGRAM = "In scope:\napi.acme.example\nRate: 50 requests/sec\n"


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_HOME", str(tmp_path))
    _reset_registry()
    try:
        yield tmp_path
    finally:
        _reset_registry()


@pytest.fixture
def offline(monkeypatch):
    """A two-node, one-edge discovery graph, and enrichers that only stamp evidence —
    no network, deterministic structure to assert the projection against."""
    def fake_pivot(seed, budget=None):
        g = Graph()
        root = Entity("domain", "api.acme.example", 0)
        child = Entity("ip", "198.51.100.7", 1)
        g.add(root)
        g.add(child, parent=root, rel="resolves_to")
        return g

    monkeypatch.setattr(research.pivot_mod, "pivot", fake_pivot)

    def rec(name):
        def enr(g, **kw):
            for e in g.nodes.values():
                e.evidence[name] = True
            return len(g.nodes)
        return enr

    for n, _, _ in research._UNITS:
        monkeypatch.setattr(providers, n, rec(n))
    for n, _ in research._ANALYSIS:
        monkeypatch.setattr(providers, n, lambda g, **kw: 0)


def _run_to_completion(c):
    planner, on_complete = research.background_pivot(
        "api.acme.example", tiers=research.tiers_for(True, False, False))
    co = coordinator_for(c)
    co.start(planner=planner, on_complete=on_complete)
    end = time.time() + 5
    while time.time() < end and co.snapshot()["run_state"] not in ("COMPLETE", "STOPPED", "FAILED"):
        time.sleep(0.01)
    return co


def test_entities_and_edges_survive_run_completion(home, offline):
    c = cmod.create(PROGRAM, name="acme")
    co = _run_to_completion(c)
    assert co.snapshot()["run_state"] == "COMPLETE"

    surface = c.surface()
    nodes = {n["value"]: n for n in surface["graph"]["nodes"]}
    assert "api.acme.example" in nodes and "198.51.100.7" in nodes
    # the passive-discovery edge survived — it only ever existed in the closure graph
    assert {"src": "domain:api.acme.example", "rel": "resolves_to",
            "dst": "ip:198.51.100.7"} in surface["graph"]["edges"]
    # active evidence was projected onto the node (observation -> projection)
    assert nodes["api.acme.example"]["evidence"].get("enrich") is True
    # completion ran the rule engine: investigation is present, not the mid-run {}
    assert "conclusions" in surface["investigation"]


def test_surface_survives_a_fresh_reload(home, offline):
    c = cmod.create(PROGRAM, name="acme")
    _run_to_completion(c)
    _reset_registry()                       # drop every in-memory coordinator/graph
    reloaded = cmod.load(c.id)              # a brand-new Campaign object, nothing cached
    assert reloaded.surface()["graph"]["nodes"], "surface must be read from disk, not memory"


def test_base_graph_is_durable_before_any_active_work(home, offline):
    """The planner persists the base graph the instant discovery finishes — a disconnect
    right after discovery still leaves nodes/edges, never an empty surface."""
    c = cmod.create(PROGRAM, name="acme")
    planner, _ = research.background_pivot("api.acme.example", tiers=set())  # no active tiers
    co = coordinator_for(c)
    co.start(planner=planner)
    end = time.time() + 5
    while time.time() < end and co.snapshot()["run_state"] not in ("COMPLETE", "STOPPED"):
        time.sleep(0.01)
    assert len(c.surface()["graph"]["nodes"]) == 2


def test_empty_surface_when_never_pivoted(home):
    c = cmod.create(PROGRAM, name="acme")
    s = c.surface()
    assert s["graph"]["nodes"] == [] and s["graph"]["edges"] == []


def test_cli_run_active_still_persists_no_surface_per_step(home, offline):
    """The synchronous CLI path passes no on_step — it must not change behaviour or error.
    (Its graph is serialized by the caller at the end, not per step.)"""
    c = cmod.create(PROGRAM, name="acme")
    g = Graph()
    g.add(Entity("domain", "api.acme.example", 0))
    research.run_active(c, g, tiers={"probe"})
    assert g.nodes["domain:api.acme.example"].evidence.get("enrich") is True


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
