"""Web operator golden path — the PRODUCT flow, proven over the public HTTP API.

The backend goldens (test_golden_e2e) drive domain internals directly. This drives the SAME
research loop entirely over the public API a browser uses, end to end:

    create campaign  ->  register identities + session  ->  ingest traffic + assert ownership
    ->  application / endpoint / resource knowledge appears  ->  a coverage gap appears
    ->  GET /plan returns the next safe action  ->  POST /autonomous starts execution
    ->  SSE carries the planner's decisions  ->  the coordinator runs the experiment
    ->  a finding candidate is promoted  ->  reproduce  ->  validate to REPORT_READY
    ->  the Reports queue shows READY + the markdown export is correct
    ->  a program response is recorded  ->  GET /plan again: the planner has moved on

No internal JSON is mutated, no lifecycle is shortcut, and no worker is called around the
Orchestrator. The ONLY thing swapped for the local fixture is differential._default_fetch (the
leaf transport), exactly as the backend goldens swap it — every per-request policy gate still
runs inside the orchestrator, which stays the sole executor. A real bearer token rides over the
wire to the fixture, so the secret-integrity assertions are meaningful.
"""
import importlib.util
import json
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import pytest

import fixture_app
from argus import differential
from argus.run import _reset_registry

_SPEC = importlib.util.spec_from_file_location(
    "argus_web_server_golden", Path(__file__).resolve().parent.parent / "web" / "server.py")
server = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(server)

HOST = "fixture.local"
PROGRAM = f"Assets:\n{HOST}\nRate: 20 requests/sec\n"


def _req(base, path, method="GET", body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(base + path, data=data, method=method,
                               headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def _fixture_fetch(port):
    """The injected leaf transport: route by path to the local fixture, ignore the host."""
    def fetch(method, url, headers, body):
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}{urlsplit(url).path}",
            data=(body.encode() if body else None), method=method, headers=dict(headers))
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, dict(r.headers), r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read().decode()
    return fetch


def _wait(pred, timeout=25.0):
    end = time.time() + timeout
    while time.time() < end:
        v = pred()
        if v:
            return v
        time.sleep(0.02)
    return None


def _detail(base, cid):
    code, d = _req(base, f"/api/campaign?id={cid}")
    return d if code == 200 else {}


def _run_terminal(base, cid):
    """The last run_transition in the audit, if it is terminal (COMPLETE/STOPPED/FAILED)."""
    states = [a.get("state") for a in _detail(base, cid).get("audit", [])
              if a.get("event") == "run_transition"]
    return states[-1] if states and states[-1] in ("COMPLETE", "STOPPED", "FAILED") else None


def _finding_state(base, cid, fid):
    for f in _detail(base, cid).get("findings", []):
        if f.get("id") == fid:
            return f.get("state")
    return None


def _sse_event_names(base, cid):
    """?once=1 replays the durable backlog and CLOSES (no live tail) — a deterministic read of
    exactly what the SSE endpoint serves a reconnecting browser."""
    names = []
    req = urllib.request.Request(base + f"/api/campaign/{cid}/events?once=1&since=0")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            for raw in r:
                line = raw.decode(errors="ignore").strip()
                if line.startswith("event:"):
                    names.append(line[len("event:"):].strip())
    except (urllib.error.URLError, OSError):
        pass
    return names


@pytest.fixture
def web(tmp_path, monkeypatch):
    """The real server over loopback, the fixture app behind the differential's leaf transport,
    and matching credential env vars — the whole stack, offline."""
    monkeypatch.setenv("ARGUS_HOME", str(tmp_path))
    monkeypatch.setenv("FIX_A_TOK", "tok-a")
    monkeypatch.setenv("FIX_B_TOK", "tok-b")
    _reset_registry()
    with fixture_app.running_app() as port:
        monkeypatch.setattr(differential, "_default_fetch", _fixture_fetch(port))
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{httpd.server_address[1]}"
        try:
            yield base
        finally:
            httpd.shutdown()
            _reset_registry()


def test_web_operator_golden_path(web):
    base = web

    # 1) create the campaign — the frozen policy is compiled from the pasted program
    code, body = _req(base, "/api/campaigns", "POST", {"program_text": PROGRAM, "name": "fix"})
    assert code == 201, body
    cid = body["id"]
    code, detail = _req(base, f"/api/campaign?id={cid}")
    assert code == 200 and detail["policy"]["in_scope"], detail

    # 2) register two researcher-controlled identities + a session (credential_ref is an ENV
    #    VAR NAME; a pasted secret is rejected at the boundary)
    for name, cred in (("user_a", "FIX_A_TOK"), ("user_b", "FIX_B_TOK")):
        code, _ = _req(base, f"/api/campaign/{cid}/identities", "POST", {
            "name": name, "role": "customer", "tenant": "t1",
            "researcher_owned": True, "credential_ref": cred})
        assert code in (200, 201), (name, code)
    code, s = _req(base, f"/api/campaign/{cid}/sessions", "POST", {
        "identity": "user_a", "base_origin": f"https://{HOST}",
        "auth_mechanism": "bearer", "credential_ref": "FIX_A_TOK"})
    assert code in (200, 201) and s["has_credential"] is True, s

    # 3) ingest the OWNER's authenticated traffic + assert researcher-controlled ownership
    code, ing = _req(base, f"/api/campaign/{cid}/traffic", "POST", {
        "identity": "user_a",
        "request": {"method": "GET", "url": f"https://{HOST}/api/orders/1",
                    "headers": {"Authorization": "Bearer tok-a"},
                    "response": {"status": 200}}})
    assert code in (200, 201) and ing["ingested"] >= 1, ing
    code, own = _req(base, f"/api/campaign/{cid}/resources/ownership", "POST", {
        "resource_type": "order", "resource_value": "1", "owner_identity": "user_a",
        "tenant": "t1", "researcher_controlled": True, "ownership_status": "CONFIRMED"})
    assert code in (200, 201) and own["researcher_controlled"] is True, own

    # 4) application knowledge appears over the public API: endpoint + owned resource candidate
    code, eps = _req(base, f"/api/campaign/{cid}/endpoints")
    assert code == 200 and any("/api/orders" in e["path_template"] for e in eps["endpoints"]), eps
    code, res = _req(base, f"/api/campaign/{cid}/resources")
    assert code == 200 and any(r["value"] == "1" for r in res["resources"]), res

    # 5) a coverage gap appears, and the planner names a safe next action (not stopped)
    code, pri = _req(base, f"/api/campaign/{cid}/priority")
    assert code == 200 and pri["ranked"], pri
    code, plan = _req(base, f"/api/campaign/{cid}/plan")
    assert code == 200 and plan["assessment"]["next_action"] is not None, plan
    assert plan["assessment"]["stopped"] is False
    assert plan["completion"]["status"] == "RESEARCH_ACTIVE"

    # 6) start AUTONOMOUS execution — returns immediately, the coordinator owns the loop
    code, started = _req(base, f"/api/campaign/{cid}/autonomous", "POST", {})
    assert code == 202 and started["mode"] == "autonomous", started

    # 7) the coordinator runs the experiments and converges (terminal run state in the audit)
    assert _wait(lambda: _run_terminal(base, cid) == "COMPLETE"), _detail(base, cid).get("audit")

    # 8) SSE served the planner's decisions as structured events (deterministic ?once replay)
    names = set(_sse_event_names(base, cid))
    assert "planner.selected" in names, names
    assert "planner.exhausted" in names and "campaign.run.complete" in names, names

    # 9) a finding candidate was promoted — exactly the vulnerable cross-account boundary
    findings = _detail(base, cid)["findings"]
    xacct = [f for f in findings if f["technique"] == "differential_cross_account"]
    assert len(xacct) == 1, findings
    fid = xacct[0]["id"]

    # 10) reproduce it through the coordinator (same leaf transport), then it is REPRODUCIBLE
    code, rep = _req(base, f"/api/campaign/{cid}/findings/{fid}/reproduce", "POST", {"trials": 2})
    assert code == 202, rep
    assert _wait(lambda: _finding_state(base, cid, fid) == "REPRODUCIBLE"), \
        _finding_state(base, cid, fid)

    # 11) validate the earned ladder to REPORT_READY (deterministic, no new requests)
    code, val = _req(base, f"/api/campaign/{cid}/findings/{fid}/validate", "POST", {})
    assert code == 200 and val["reached"] == "REPORT_READY", val

    # 12) the Reports queue shows it READY, and the markdown export is correct + secret-free
    code, reports = _req(base, f"/api/campaign/{cid}/reports")
    assert code == 200
    row = next(r for r in reports["reports"] if r["finding_id"] == fid)
    assert row["queue_status"] == "READY", row
    code, report = _req(base, f"/api/campaign/{cid}/findings/{fid}/report")
    assert code == 200
    md = report["markdown"]
    assert "/api/orders/1" in md and "127.0.0.1" not in md
    for secret in ("tok-a", "tok-b", "Bearer tok"):
        assert secret not in md, f"secret leaked into markdown: {secret!r}"

    # 13) record the program's response (research memory only — no submission/scraping)
    code, tr = _req(base, f"/api/campaign/{cid}/findings/{fid}/triage", "POST",
                    {"outcome": "ACCEPTED", "notes": "nice find"})
    assert code in (200, 201) and tr["triage"]["outcome"] == "ACCEPTED", tr

    # 14) the planner has moved on: every safe gap is consumed, so it stops HONESTLY
    code, plan2 = _req(base, f"/api/campaign/{cid}/plan")
    assert code == 200
    assert plan2["completion"]["status"] == "RESEARCH_EXHAUSTED"
    assert plan2["assessment"]["stop_reason"] != ""        # a real reason, never "secure"

    # 15) whole-journey secret integrity over the public surfaces a browser actually reads
    blob = "\n".join([json.dumps(_detail(base, cid)), json.dumps(plan2),
                      json.dumps(reports), json.dumps(_sse_event_names(base, cid))])
    for secret in ("tok-a", "tok-b", "Bearer tok", "FIX_A_TOK=tok"):
        assert secret not in blob, f"secret leaked: {secret!r}"
