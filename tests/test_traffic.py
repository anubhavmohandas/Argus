"""Session + traffic knowledge — the first research-automation vertical slice.

ARGUS learns what the application looks like from researcher-controlled captures, BEFORE
any vulnerability reasoning. These tests pin the foundation the roadmap depends on:

  * one captured request becomes durable knowledge (evidence + an endpoint)
  * GET /users/123 and /users/456 collapse to /users/{id} — but route names are NOT
    over-generalized
  * parameter NAMES are extracted; identity + session are linked
  * raw capture (evidence) and endpoint template (interpretation) stay SEPARATE records
  * secrets NEVER enter the durable corpus — not captures, not endpoints, not the audit log
  * a HAR import produces the same durable endpoints
  * a Session references a credential by env-var NAME; a pasted secret is rejected
"""
import json
import os

import pytest

from argus import campaign as cmod, session as smod, traffic


@pytest.fixture
def camp(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_HOME", str(tmp_path))
    return cmod.create("In scope:\napi.acme.example\n", name="acme")


# --- normalization --------------------------------------------------------
def test_numeric_and_uuid_segments_become_id():
    assert traffic.normalize_path("/users/123") == "/users/{id}"
    assert traffic.normalize_path("/users/123/orders/4") == "/users/{id}/orders/{id}"
    assert traffic.normalize_path(
        "/o/550e8400-e29b-41d4-a716-446655440000") == "/o/{id}"
    assert traffic.normalize_path("/x/507f1f77bcf86cd799439011") == "/x/{id}"   # mongo id


def test_route_names_are_not_over_generalized():
    # short alphabetic segments are routes, not ids — must survive verbatim
    assert traffic.normalize_path("/api/orders/cancel") == "/api/orders/cancel"
    assert traffic.normalize_path("/v2/users/me") == "/v2/users/me"


# --- one capture -> durable knowledge -------------------------------------
def test_capture_creates_evidence_and_an_endpoint(camp):
    cap, ep = traffic.capture(
        camp, method="get", url="https://api.acme.example/api/orders/123?fields=all",
        headers={"Content-Type": "application/json"}, identity="user_a",
        response={"status": 200})
    assert cap.method == "GET" and cap.host == "api.acme.example"
    assert ep.path_template == "/api/orders/{id}"
    assert "fields" in ep.query_params and ep.identities == ["user_a"]
    assert ep.response_classes == ["2xx"] and ep.obs_count == 1
    # evidence and interpretation are distinct durable records
    assert len(traffic.captures(camp)) == 1 and len(traffic.endpoints(camp)) == 1


def test_two_ids_collapse_to_one_endpoint_with_both_identities(camp):
    traffic.capture(camp, method="GET", url="https://api.acme.example/api/orders/123",
                    headers={"Authorization": "Bearer t"}, identity="user_a",
                    response={"status": 200})
    traffic.capture(camp, method="GET", url="https://api.acme.example/api/orders/456",
                    headers={"Cookie": "s=x"}, identity="user_b", response={"status": 403})
    eps = traffic.endpoints(camp)
    assert len(eps) == 1
    e = eps[0]
    assert e["path_template"] == "/api/orders/{id}"
    assert set(e["identities"]) == {"user_a", "user_b"}
    assert e["auth"] == "required" and set(e["response_classes"]) == {"2xx", "4xx"}
    assert e["obs_count"] == 2
    # the endpoint points back at its evidence
    assert len(traffic.captures_for(camp, e["id"])) == 2


def test_different_methods_are_distinct_endpoints(camp):
    traffic.capture(camp, method="GET", url="https://api.acme.example/api/orders/1")
    traffic.capture(camp, method="POST", url="https://api.acme.example/api/orders/1/cancel",
                    body='{"reason":"x"}')
    eps = {(e["method"], e["path_template"]) for e in traffic.endpoints(camp)}
    assert ("GET", "/api/orders/{id}") in eps
    assert ("POST", "/api/orders/{id}/cancel") in eps


def test_anon_only_route_is_auth_none(camp):
    traffic.capture(camp, method="GET", url="https://api.acme.example/health",
                    response={"status": 200})
    assert traffic.endpoints(camp)[0]["auth"] == "none"


# --- the security boundary: secrets never reach the corpus ----------------
def test_secrets_are_redacted_everywhere_durable(camp):
    traffic.capture(
        camp, method="GET",
        url="https://api.acme.example/api/orders/1?token=SUPERSECRET&page=2",
        headers={"Authorization": "Bearer SUPERSECRET", "Cookie": "session=SECRETCOOKIE",
                 "X-Api-Key": "SECRETKEY", "Accept": "application/json"},
        body='{"password":"hunter2","note":"ok"}', identity="user_a",
        response={"status": 200})

    # every durable artifact in the campaign dir, concatenated
    corpus = []
    for root, _dirs, files in os.walk(camp.dir):
        for f in files:
            corpus.append((os.path.join(root, f),
                           open(os.path.join(root, f)).read()))
    blob = "".join(text for _, text in corpus)
    for secret in ("SUPERSECRET", "SECRETCOOKIE", "SECRETKEY", "hunter2"):
        assert secret not in blob, f"{secret!r} leaked into {[(p) for p, t in corpus if secret in t]}"
    assert "<redacted>" in blob
    # the non-secret header value and param NAMES are still kept (they are interpretation)
    e = traffic.endpoints(camp)[0]
    assert "page" in e["query_params"] and "token" in e["query_params"]
    assert "note" in e["body_params"] and "password" in e["body_params"]  # names, not values


def test_audit_trail_carries_no_secret(camp):
    traffic.capture(camp, method="GET", url="https://api.acme.example/a/1?token=LEAK",
                    headers={"Authorization": "Bearer LEAK"}, identity="user_a")
    trail = json.dumps(camp.audit_trail())
    assert "LEAK" not in trail
    assert any(a["event"] == "traffic_captured" for a in camp.audit_trail())


# --- HAR import -----------------------------------------------------------
def test_har_import_builds_the_same_catalog(camp):
    har = {"log": {"entries": [
        {"request": {"method": "GET", "url": "https://api.acme.example/api/users/7",
                     "headers": [{"name": "Authorization", "value": "Bearer z"}]},
         "response": {"status": 200, "content": {"mimeType": "application/json"}}},
        {"request": {"method": "GET", "url": "https://api.acme.example/api/users/8",
                     "headers": [{"name": "Authorization", "value": "Bearer z"}]},
         "response": {"status": 200}},
        {"request": {"url": ""}},                     # junk entry — skipped, not fatal
    ]}}
    eps = traffic.import_har(camp, har, identity="user_a", session_id="")
    assert any(e.path_template == "/api/users/{id}" for e in eps)
    cat = traffic.endpoints(camp)
    users = next(e for e in cat if e["path_template"] == "/api/users/{id}")
    assert users["obs_count"] == 2 and users["auth"] == "required"


# --- session linking ------------------------------------------------------
def test_capture_links_and_touches_a_session(camp):
    s = smod.register(camp, smod.Session(identity="user_a",
                                         base_origin="https://api.acme.example",
                                         credential_ref="ACME_USER_A_TOKEN", source="har"))
    before = smod.get(camp, s.id).last_seen
    traffic.capture(camp, method="GET", url="https://api.acme.example/api/orders/1",
                    identity="user_a", session_id=s.id, response={"status": 200})
    e = traffic.endpoints(camp)[0]
    assert s.id in e["session_ids"] and e["auth"] == "required"   # a session implies auth
    assert smod.get(camp, s.id).last_seen >= before


def test_session_rejects_a_pasted_secret():
    with pytest.raises(ValueError, match="ENV VAR NAME"):
        smod.Session(credential_ref="eyJ0 real token value")


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
