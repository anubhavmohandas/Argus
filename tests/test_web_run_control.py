"""Background pivot + run-control endpoints route through the coordinator, never a provider.

These drive the real server over loopback and prove the HTTP layer stays a thin remote
control: POST /pivot translates bounded UI intent into the research planner and returns a
run snapshot immediately (SSE carries the rest); pause/resume/stop operate on real run
state; and input validation rejects an unknown level or out-of-range budget at the boundary.

The planner is stubbed so no target is touched — the point under test is the WIRING
(endpoint -> coordinator -> orchestrator), not live discovery.
"""
import importlib.util
import json
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "argus_web_server2", Path(__file__).resolve().parent.parent / "web" / "server.py")
server = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(server)


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_HOME", str(tmp_path))
    from argus.run import _reset_registry
    _reset_registry()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        yield base
    finally:
        httpd.shutdown()
        _reset_registry()


def _req(base, path, method="GET", body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(base + path, data=data, method=method,
                               headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def _campaign(base, program="In scope:\napi.acme.example\n"):
    code, body = _req(base, "/api/campaigns", "POST", {"program_text": program, "name": "acme"})
    assert code == 201, body
    return body["id"]


def _coordinator(cid):
    from argus import campaign as cmod, run as run_mod
    return run_mod.coordinator_for(cmod.load(cid))


def _wait(pred, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.01)
    return False


def _stub_planner(monkeypatch, worker):
    """Patch research.background_pivot to propose ONE in-scope task with `worker`, so a
    pivot run exercises the coordinator loop without any network."""
    from argus import research
    from argus.orchestrator import Task

    def fake(seed, *, budget, tiers, ports, cve):
        def planner(co):
            co.orch.register_worker("http_probe", worker)
            co.orch.propose(Task(campaign_id=co.c.id, technique="http_probe",
                                 host="api.acme.example", hypothesis="stub"))
        return planner, (lambda co: None)
    monkeypatch.setattr(research, "background_pivot", fake)


# --- validation (trust boundary) -----------------------------------------
def test_pivot_rejects_unknown_level(api):
    cid = _campaign(api)
    code, body = _req(api, f"/api/campaign/{cid}/pivot", "POST", {"level": "nuke"})
    assert code == 400 and "level" in body["error"]


def test_pivot_rejects_out_of_range_budget(api):
    cid = _campaign(api)
    code, body = _req(api, f"/api/campaign/{cid}/pivot", "POST", {"level": "passive", "depth": 99})
    assert code == 400 and "depth" in body["error"]


# --- background pivot wiring ---------------------------------------------
def test_pivot_starts_background_run_and_completes(api, monkeypatch):
    calls = []
    _stub_planner(monkeypatch, lambda t, c: (calls.append(t.host) or (
        {"request": {"method": "GET", "url": f"https://{t.host}/", "headers": {}, "body": ""},
         "response": {"status": 200}}, "")))
    cid = _campaign(api)
    code, body = _req(api, f"/api/campaign/{cid}/pivot", "POST", {"level": "active"})
    assert code == 202, body
    assert body["run"]["run_id"] and body["run"]["campaign_id"] == cid
    assert body["seed"] == "api.acme.example"
    co = _coordinator(cid)
    assert _wait(lambda: co.snapshot()["run_state"] == "COMPLETE")
    assert calls == ["api.acme.example"]           # the orchestrated worker ran, once


def test_pause_resume_stop_over_http(api, monkeypatch):
    entered = {"api.acme.example": threading.Event()}
    release = {"api.acme.example": threading.Event()}

    def worker(t, c):
        entered[t.host].set()
        release[t.host].wait(5)
        return ({"request": {"method": "GET", "url": f"https://{t.host}/", "headers": {}, "body": ""},
                 "response": {"status": 200}}, "")
    _stub_planner(monkeypatch, worker)
    cid = _campaign(api)
    _req(api, f"/api/campaign/{cid}/pivot", "POST", {"level": "active"})
    co = _coordinator(cid)
    assert _wait(lambda: entered["api.acme.example"].is_set())

    code, body = _req(api, f"/api/campaign/{cid}/pause", "POST", {})
    assert code == 200 and body["run"]["run_state"] in ("RUNNING", "PAUSING", "PAUSED")
    release["api.acme.example"].set()
    assert _wait(lambda: co.snapshot()["run_state"] == "PAUSED")

    code, body = _req(api, f"/api/campaign/{cid}/stop", "POST", {})
    assert code == 200
    assert _wait(lambda: co.snapshot()["run_state"] == "STOPPED")


def test_run_control_on_idle_campaign_is_safe(api):
    cid = _campaign(api)
    code, body = _req(api, f"/api/campaign/{cid}/stop", "POST", {})
    assert code == 200 and body["run"]["campaign_id"] == cid


def _offline_pivot(monkeypatch):
    """Stub discovery + every per-host enricher so the REAL research.background_pivot runs
    with no network: a two-node, one-edge graph and evidence-stamping probes."""
    from argus import providers, research
    from argus.pivot import Entity, Graph

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


def test_active_quick_pivot_serves_a_durable_surface_over_http(api, monkeypatch):
    """The full active Quick Pivot vertical through the real planner: start a background
    run (no SSE client attached — a 'disconnected browser'), and once it completes the
    durable surface is served over the API with entities, the passive-discovery edge, and
    the evidence active probes projected onto the node. No subprocess /api/stream path."""
    _offline_pivot(monkeypatch)
    cid = _campaign(api)
    code, body = _req(api, f"/api/campaign/{cid}/pivot", "POST", {"level": "active"})
    assert code == 202, body                         # returns immediately
    co = _coordinator(cid)
    assert _wait(lambda: co.snapshot()["run_state"] == "COMPLETE")   # continued with no browser

    code, surface = _req(api, f"/api/campaign/{cid}/surface")
    assert code == 200
    nodes = {n["value"]: n for n in surface["graph"]["nodes"]}
    assert "api.acme.example" in nodes and "198.51.100.7" in nodes
    assert {"src": "domain:api.acme.example", "rel": "resolves_to",
            "dst": "ip:198.51.100.7"} in surface["graph"]["edges"]
    assert nodes["api.acme.example"]["evidence"].get("enrich") is True
    assert "conclusions" in surface["investigation"]  # completion ran the rule engine


def test_two_active_quick_pivots_are_independent_campaigns(api):
    """Each active Quick Pivot creates its own ephemeral campaign — distinct ids, distinct
    coordinators — so two investigations never share one run's state."""
    a = _campaign(api, "In scope:\na.acme.example\n")
    b = _campaign(api, "In scope:\nb.acme.example\n")
    assert a != b
    assert _coordinator(a) is not _coordinator(b)


# --- reproduce endpoint validation ---------------------------------------
def test_reproduce_unknown_finding_409(api):
    cid = _campaign(api)
    code, body = _req(api, f"/api/campaign/{cid}/findings/nope/reproduce", "POST", {})
    assert code == 409 and "finding" in body["error"]


def test_reproduce_rejects_out_of_range_trials(api):
    cid = _campaign(api)
    code, body = _req(api, f"/api/campaign/{cid}/findings/x/reproduce", "POST", {"trials": 99})
    assert code == 400 and "trials" in body["error"]


def test_reproduce_refused_while_a_run_is_active(api, monkeypatch):
    # hold a pivot run open with a latching worker, then a reproduce request must 409
    entered = {"api.acme.example": threading.Event()}
    release = {"api.acme.example": threading.Event()}

    def worker(t, c):
        entered[t.host].set()
        release[t.host].wait(5)
        return ({"request": {"method": "GET", "url": f"https://{t.host}/", "headers": {}, "body": ""},
                 "response": {"status": 200}}, "")
    _stub_planner(monkeypatch, worker)
    cid = _campaign(api)
    _req(api, f"/api/campaign/{cid}/pivot", "POST", {"level": "active"})
    co = _coordinator(cid)
    assert _wait(lambda: entered["api.acme.example"].is_set())
    code, body = _req(api, f"/api/campaign/{cid}/findings/x/reproduce", "POST", {})
    assert code == 409 and "already active" in body["error"]
    release["api.acme.example"].set()
    _wait(lambda: not co.is_active())
