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
