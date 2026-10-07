"""The write API is a REMOTE CONTROL for the orchestrator, not a new execution engine.

Every write endpoint ends at an in-process domain / orchestrator method. These tests
drive the real server over a loopback socket and prove: campaigns/identities are
created in-process; a parked high-risk task can be approved/denied via HTTP; an API
approval can NEVER override a scope/forbidden DENY (can_test is re-run); and the trust
boundary validates its input (bad JSON, missing fields, pasted secret, unknown ids).
"""
import importlib.util
import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "argus_web_server", __import__("pathlib").Path(__file__).resolve().parent.parent / "web" / "server.py")
server = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(server)


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_HOME", str(tmp_path))
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        yield base
    finally:
        httpd.shutdown()


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


def test_create_campaign_and_read_back(api):
    cid = _campaign(api)
    code, detail = _req(api, f"/api/campaign?id={cid}")
    assert code == 200
    assert detail["id"] == cid
    for key in ("tasks", "approvals", "identities", "policy", "progress"):
        assert key in detail


def test_register_identity_in_process(api):
    cid = _campaign(api)
    code, body = _req(api, f"/api/campaign/{cid}/identities", "POST",
                      {"name": "user_a", "role": "customer", "researcher_owned": True,
                       "credential_ref": "ACME_TOKEN"})
    assert code == 201, body
    assert body["name"] == "user_a" and body["has_credential"] is True
    _, detail = _req(api, f"/api/campaign?id={cid}")
    names = [i["name"] for i in detail["identities"]]
    assert "user_a" in names
    # the secret-ref VALUE is never echoed back in the read model
    assert "ACME_TOKEN" not in json.dumps(detail)


def test_pasted_secret_as_credential_is_rejected(api):
    cid = _campaign(api)
    code, body = _req(api, f"/api/campaign/{cid}/identities", "POST",
                      {"name": "bad", "credential_ref": "eyJ0 a.real.token"})
    assert code == 400 and "ENV VAR NAME" in body["error"]


def _park_high_risk(cid):
    """Propose a high-risk task directly so it parks APPROVAL_REQUIRED — the state the
    API's approve/deny endpoints act on."""
    from argus import campaign as cmod
    from argus.orchestrator import Orchestrator, Task
    c = cmod.load(cid)
    orch = Orchestrator(c)
    t = orch.propose(Task(campaign_id=c.id, technique="state_change",
                          host="api.acme.example", hypothesis="can we write?"))
    assert t.state == "APPROVAL_REQUIRED"
    return t.id


def test_approve_parked_task_over_http(api):
    cid = _campaign(api)
    tid = _park_high_risk(cid)
    code, body = _req(api, f"/api/campaign/{cid}/tasks/{tid}/approve", "POST", {"by": "alice"})
    assert code == 200, body
    assert body["task"]["state"] == "QUEUED"


def test_deny_parked_task_over_http(api):
    cid = _campaign(api)
    tid = _park_high_risk(cid)
    code, body = _req(api, f"/api/campaign/{cid}/tasks/{tid}/deny", "POST", {"by": "alice"})
    assert code == 200 and body["task"]["state"] == "DENIED"


def test_api_approval_cannot_override_scope_deny(api):
    """The critical safety property: a task DENIED by scope is terminal and has no edge
    back to APPROVAL_REQUIRED, so the approve endpoint cannot resurrect it."""
    cid = _campaign(api)
    from argus import campaign as cmod
    from argus.orchestrator import Orchestrator, Task
    c = cmod.load(cid)
    orch = Orchestrator(c)
    t = orch.propose(Task(campaign_id=c.id, technique="http_probe",
                          host="evil.out-of-scope.example", hypothesis="oob"))
    assert t.state == "DENIED"
    code, body = _req(api, f"/api/campaign/{cid}/tasks/{t.id}/approve", "POST", {"by": "mallory"})
    assert code == 409 and "not awaiting approval" in body["error"]
    # still denied after the attempt
    _, detail = _req(api, f"/api/campaign?id={cid}")
    assert next(x for x in detail["tasks"] if x["id"] == t.id)["state"] == "DENIED"


def _sse_once(base, path):
    """Fetch an SSE endpoint that closes itself (?once=1) and parse (event, data) pairs."""
    with urllib.request.urlopen(base + path, timeout=10) as resp:
        raw = resp.read().decode()
    out = []
    for block in raw.split("\n\n"):
        ev = dat = None
        for line in block.splitlines():
            if line.startswith("event: "):
                ev = line[7:]
            elif line.startswith("data: "):
                dat = json.loads(line[6:])
        if ev is not None:
            out.append((ev, dat))
    return out


def test_sse_replays_structured_events_from_the_audit_log(api):
    cid = _campaign(api)
    # generate durable audit events through the orchestrator (not stderr)
    from argus import campaign as cmod
    from argus.orchestrator import Orchestrator, Task
    c = cmod.load(cid)
    orch = Orchestrator(c)
    orch.propose(Task(campaign_id=c.id, technique="http_probe",
                      host="api.acme.example", hypothesis="in scope"))        # -> ALLOW
    orch.propose(Task(campaign_id=c.id, technique="http_probe",
                      host="evil.out.example", hypothesis="oob"))             # -> DENY
    orch.propose(Task(campaign_id=c.id, technique="state_change",
                      host="api.acme.example", hypothesis="write?"))          # -> HUMAN_APPROVAL

    events = _sse_once(api, f"/api/campaign/{cid}/events?once=1")
    names = [e for e, _ in events]
    assert "campaign.created" in names
    assert "task.proposed" in names
    assert "policy.allow" in names and "task.queued" in names
    assert "policy.deny" in names
    assert "policy.approval_required" in names and "approval.requested" in names
    assert names[-1] == "campaign.progress"          # stream ends on a progress snapshot
    # every event carries a monotonic seq for ?since= resume
    seqs = [d["seq"] for e, d in events if e != "campaign.progress"]
    assert seqs == sorted(seqs)


def test_sse_since_resumes_without_replaying_the_backlog(api):
    cid = _campaign(api)
    from argus import campaign as cmod
    from argus.orchestrator import Orchestrator, Task
    c = cmod.load(cid)
    orch = Orchestrator(c)
    orch.propose(Task(campaign_id=c.id, technique="http_probe", host="api.acme.example"))
    full = _sse_once(api, f"/api/campaign/{cid}/events?once=1")
    last_seq = max(d["seq"] for e, d in full if e != "campaign.progress")
    # resume strictly after the last seen record: no old events, only the progress tail
    resumed = _sse_once(api, f"/api/campaign/{cid}/events?once=1&since={last_seq + 1}")
    assert [e for e, _ in resumed] == ["campaign.progress"]


def test_sse_unknown_campaign_404(api):
    try:
        urllib.request.urlopen(api + "/api/campaign/nope-000/events?once=1", timeout=5)
        assert False, "expected 404"
    except urllib.error.HTTPError as e:
        assert e.code == 404


def test_surface_route_serves_the_durable_projection(api):
    from argus import campaign as cmod
    cid = _campaign(api)
    # a fresh campaign has an honest empty surface, not a fabricated one
    code, body = _req(api, f"/api/campaign/{cid}/surface")
    assert code == 200
    assert body["graph"]["nodes"] == [] and body["graph"]["edges"] == []
    # once a surface is persisted (as the background pivot does), the route serves it in
    # the engine's {graph, investigation} shape the UI's normalize() already consumes
    cmod.load(cid).save_surface({
        "graph": {"nodes": [{"type": "domain", "value": "api.acme.example", "depth": 0,
                             "via": "seed", "evidence": {"enrich": True}, "observed": {}}],
                  "edges": [], "findings": []},
        "investigation": {"conclusions": []}})
    code, body = _req(api, f"/api/campaign/{cid}/surface")
    assert code == 200
    assert body["graph"]["nodes"][0]["value"] == "api.acme.example"
    assert body["graph"]["nodes"][0]["evidence"]["enrich"] is True


def test_surface_route_unknown_campaign_404(api):
    assert _req(api, "/api/campaign/nope-000/surface")[0] == 404


def test_stream_refuses_active_engagement(api):
    """The legacy /api/stream path is passive-only now — active engagement must go through
    the coordinator-owned campaign, so there is no hidden second web-active engine."""
    for level in ("active", "active-plus", "full"):
        code, body = _req(api, f"/api/stream?seed=api.acme.example&level={level}")
        assert code == 400, (level, body)
        assert "campaign" in body["error"]
    # passive remains a legitimate path — the argv builder still accepts it (asserted
    # offline, so the test touches nothing), active is refused at the same chokepoint.
    assert server._build_argv("api.acme.example", "passive", {})[3:5] == ["pivot", "api.acme.example"]
    with pytest.raises(ValueError, match="campaign"):
        server._build_argv("api.acme.example", "active", {})


def test_traffic_ingest_and_endpoint_catalog_over_http(api):
    cid = _campaign(api)
    # a session referenced by env-var name; the credential value is never echoed back
    code, s = _req(api, f"/api/campaign/{cid}/sessions", "POST",
                   {"identity": "user_a", "base_origin": "https://api.acme.example",
                    "credential_ref": "ACME_USER_A_TOKEN"})
    assert code == 201 and s["has_credential"] is True and "credential_ref" not in s
    sid = s["id"]

    # ingest a single captured request carrying secrets — they must not come back
    code, body = _req(api, f"/api/campaign/{cid}/traffic", "POST", {
        "identity": "user_a", "session_id": sid,
        "request": {"method": "GET",
                    "url": "https://api.acme.example/api/orders/123?token=LEAKME&page=1",
                    "headers": {"Authorization": "Bearer LEAKME"},
                    "response": {"status": 200}}})
    assert code == 201, body
    assert "LEAKME" not in json.dumps(body)        # the catalog carries names, never secrets
    ep = body["endpoints"][0]
    assert ep["path_template"] == "/api/orders/{id}" and "page" in ep["query_params"]

    # the catalog + sessions read model
    code, cat = _req(api, f"/api/campaign/{cid}/endpoints")
    assert code == 200 and len(cat["endpoints"]) == 1
    assert cat["sessions"][0]["id"] == sid and "credential_ref" not in cat["sessions"][0]

    # the inspector: one endpoint + its captures (evidence), still secret-free
    code, ins = _req(api, f"/api/campaign/{cid}/endpoints?ep={ep['id']}")
    assert code == 200 and ins["endpoint"]["id"] == ep["id"]
    assert len(ins["captures"]) == 1
    assert "LEAKME" not in json.dumps(ins) and "<redacted>" in json.dumps(ins)


def test_traffic_ingest_rejects_bad_bodies(api):
    cid = _campaign(api)
    assert _req(api, f"/api/campaign/{cid}/traffic", "POST", {})[0] == 400          # no har/request
    assert _req(api, f"/api/campaign/{cid}/traffic", "POST",
                {"request": {"method": "GET"}})[0] == 400                            # missing url
    assert _req(api, f"/api/campaign/{cid}/traffic", "POST",
                {"session_id": "sess-nope", "request": {"url": "https://api.acme.example/x"}}
                )[0] == 400                                                          # unknown session
    assert _req(api, f"/api/campaign/{cid}/sessions", "POST",
                {"credential_ref": "not a var name"})[0] == 400                      # pasted secret


def test_write_api_input_validation(api):
    cid = _campaign(api)
    # malformed JSON
    r = urllib.request.Request(api + "/api/campaigns", data=b"{not json",
                               method="POST", headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(r)
        assert False, "expected 400"
    except urllib.error.HTTPError as e:
        assert e.code == 400
    # missing program_text
    assert _req(api, "/api/campaigns", "POST", {"name": "x"})[0] == 400
    # unknown campaign / task
    assert _req(api, "/api/campaign/nope-000/identities", "POST", {"name": "a"})[0] == 404
    assert _req(api, f"/api/campaign/{cid}/tasks/task-xxx/approve", "POST", {})[0] == 404


def test_matrix_route_projects_traffic_without_secrets(api):
    """GET /api/campaign/{id}/matrix returns the identity x endpoint read model built from
    captured traffic — observed vs unobserved coverage, and NEVER a captured secret."""
    cid = _campaign(api)
    from argus import campaign as cmod, identity as imod, traffic
    c = cmod.load(cid)
    imod.register(c, imod.Identity(name="user_a", role="customer", researcher_owned=True))
    imod.register(c, imod.Identity(name="user_b", role="customer", researcher_owned=True))
    traffic.capture(c, method="GET", url="https://api.acme.example/api/orders/1",
                    headers={"Authorization": "Bearer supersecrettoken"}, identity="user_a",
                    response={"status": 200})
    traffic.capture(c, method="GET", url="https://api.acme.example/api/orders/2",
                    headers={"Cookie": "session=topsecret"}, identity="user_b",
                    response={"status": 403})

    code, body = _req(api, f"/api/campaign/{cid}/matrix")
    assert code == 200, body
    assert body["campaign_id"] == cid
    assert {col["name"] for col in body["identities"]} >= {"user_a", "user_b"}
    ep = next(r for r in body["endpoints"] if r["path_template"] == "/api/orders/{id}")
    assert set(ep["identities_observed"]) == {"user_a", "user_b"}
    # the secret never reaches the projection
    blob = json.dumps(body)
    assert "supersecrettoken" not in blob and "topsecret" not in blob


def test_matrix_route_unknown_campaign_is_404(api):
    code, body = _req(api, "/api/campaign/no-such-campaign-xyz/matrix")
    assert code == 404, body


def test_resources_route_and_ownership_assertion(api):
    """GET /api/campaign/{id}/resources mines candidates; POST .../resources/ownership
    declares explicit ownership. An INFERRED assertion is forced non-controlled; a bad
    assertion is a 400. researcher_controlled is never inferred from traffic."""
    cid = _campaign(api)
    from argus import campaign as cmod, traffic
    c = cmod.load(cid)
    traffic.capture(c, method="GET", url="https://api.acme.example/api/orders/123",
                    headers={"Authorization": "Bearer s"}, identity="customer_a",
                    response={"status": 200})

    code, body = _req(api, f"/api/campaign/{cid}/resources")
    assert code == 200, body
    row = next(r for r in body["resources"] if r["value"] == "123")
    assert row["resource_type"] == "order" and row["researcher_controlled"] is False
    assert row["ownership_status"] == ""                     # unknown is normal

    # explicit confirmed controlled assertion
    code, body = _req(api, f"/api/campaign/{cid}/resources/ownership", "POST",
                      {"resource_type": "order", "resource_value": "123",
                       "owner_identity": "customer_a", "tenant": "tenant_a",
                       "researcher_controlled": True})
    assert code == 201 and body["researcher_controlled"] is True
    _, body = _req(api, f"/api/campaign/{cid}/resources")
    row = next(r for r in body["resources"] if r["value"] == "123")
    assert row["researcher_controlled"] and row["owner_identity"] == "customer_a"

    # an INFERRED assertion can never be researcher-controlled, even if asked
    code, body = _req(api, f"/api/campaign/{cid}/resources/ownership", "POST",
                      {"resource_type": "order", "resource_value": "456",
                       "researcher_controlled": True, "ownership_status": "INFERRED",
                       "confidence": 0.7})
    assert code == 201 and body["researcher_controlled"] is False

    # a bad assertion is rejected at the boundary
    code, body = _req(api, f"/api/campaign/{cid}/resources/ownership", "POST",
                      {"resource_type": "order", "resource_value": "", "ownership_status": "MAYBE"})
    assert code == 400, body


def test_coverage_route_exposes_research_gaps(api):
    """GET /api/campaign/{id}/coverage derives ownership-aware ResearchGaps from an owner's
    observed action on a researcher-controlled object + an untested non-owner identity."""
    cid = _campaign(api, program="In scope:\napi.acme.example\nRate: 2 requests/sec\n")
    from argus import campaign as cmod, identity as imod, resource, traffic
    c = cmod.load(cid)
    imod.register(c, imod.Identity(name="customer_a", role="customer", tenant="t1", researcher_owned=True))
    imod.register(c, imod.Identity(name="customer_b", role="customer", tenant="t1", researcher_owned=True))
    traffic.capture(c, method="POST", url="https://api.acme.example/api/orders/777/cancel",
                    headers={"Authorization": "Bearer s"}, identity="customer_a",
                    response={"status": 204})
    resource.assert_ownership(c, resource.Ownership(
        resource_type="order", resource_value="777", owner_identity="customer_a",
        tenant="t1", researcher_controlled=True))

    code, body = _req(api, f"/api/campaign/{cid}/coverage")
    assert code == 200, body
    live = [g for g in body["gaps"] if not g.get("orphan")]
    assert len(live) == 1
    g = live[0]
    assert g["gap_type"] == "OWNER_NONOWNER_UNTESTED"
    assert g["mutation_identity"] == "customer_b"
    assert g["policy_preview"]["verdict"] == "ALLOW_WITH_LIMITS"
    assert body["summary"]["owner_nonowner_untested"] == 1
