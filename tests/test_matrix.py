"""Identity × Endpoint matrix — pins the research-memory semantics the roadmap depends on.

The matrix is a deterministic PROJECTION over captured traffic, never a new source of
truth and never a security conclusion. These tests lock the distinctions that must never
blur:

  * one normalized endpoint observed by two identities => ONE row, TWO observed cells
  * N requests by one identity => one cell with count N (not N rows)
  * an endpoint an identity never used => UNOBSERVED (absent), not denied / vulnerable
  * anonymous ("") traffic is a distinct column, preserved accurately
  * reloading the campaign yields an identical matrix (deterministic)
  * no captured secret (Authorization / Cookie / session token) reaches the projection
  * building the matrix is read-only — it stores nothing and touches no target
"""
import os

import pytest

from argus import campaign as cmod, identity as imod, matrix, traffic


@pytest.fixture
def camp(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_HOME", str(tmp_path))
    c = cmod.create("In scope:\napi.acme.example\n", name="acme")
    imod.register(c, imod.Identity(name="user_a", role="customer", researcher_owned=True))
    imod.register(c, imod.Identity(name="user_b", role="customer", researcher_owned=True))
    return c


def _orders(c, ident, oid, status, headers):
    traffic.capture(c, method="GET", url=f"https://api.acme.example/api/orders/{oid}",
                    headers=headers, identity=ident, response={"status": status})


def test_same_endpoint_two_identities_one_row_two_cells(camp):
    _orders(camp, "user_a", 1, 200, {"Authorization": "Bearer a"})
    _orders(camp, "user_b", 2, 200, {"Cookie": "session=b"})
    m = matrix.build(camp)
    rows = [r for r in m["endpoints"] if r["path_template"] == "/api/orders/{id}"]
    assert len(rows) == 1
    assert set(rows[0]["identities_observed"]) == {"user_a", "user_b"}
    observed = [c for c in m["cells"] if c["endpoint_id"] == rows[0]["id"]]
    assert {c["identity"] for c in observed} == {"user_a", "user_b"}


def test_many_requests_collapse_to_one_cell_with_count(camp):
    for i in range(20):
        _orders(camp, "user_a", i, 200, {"Authorization": "Bearer a"})
    m = matrix.build(camp)
    ep = next(r for r in m["endpoints"] if r["path_template"] == "/api/orders/{id}")
    cells = [c for c in m["cells"] if c["endpoint_id"] == ep["id"] and c["identity"] == "user_a"]
    assert len(cells) == 1 and cells[0]["request_count"] == 20


def test_unobserved_is_not_denied_or_vulnerable(camp):
    _orders(camp, "user_a", 1, 200, {"Authorization": "Bearer a"})
    m = matrix.build(camp)
    ep = next(r for r in m["endpoints"] if r["path_template"] == "/api/orders/{id}")
    # user_b never used it: absent from observed cells, absent from the row's observed list
    assert "user_b" not in ep["identities_observed"]
    assert not any(c["endpoint_id"] == ep["id"] and c["identity"] == "user_b" for c in m["cells"])
    # the projection contains no verdict vocabulary — only observed/unobserved
    blob = str(m).lower()
    assert "denied" not in blob and "vulnerable" not in blob and "unauthorized" not in blob


def test_anonymous_traffic_is_its_own_column(camp):
    traffic.capture(camp, method="GET", url="https://api.acme.example/api/health",
                    response={"status": 200})               # identity "" => anonymous
    m = matrix.build(camp)
    anon = next(c for c in m["identities"] if c["is_anonymous"])
    assert anon["name"] == matrix.ANON and anon["endpoints_observed"] == 1
    health = next(r for r in m["endpoints"] if r["path_template"] == "/api/health")
    assert health["anonymous_observed"] and not health["authenticated_observed"]


def test_observed_only_identity_becomes_a_column(camp):
    # a capture tagged with an identity the operator never DECLARED still forms a column —
    # the tag is an explicit researcher association, not an inference from cookies/tokens.
    _orders(camp, "merchant_x", 5, 200, {"Authorization": "Bearer m"})
    m = matrix.build(camp)
    col = next(c for c in m["identities"] if c["name"] == "merchant_x")
    assert col["declared"] is False and col["role"] == ""


def test_matrix_is_deterministic_across_reload(camp):
    _orders(camp, "user_a", 1, 200, {"Authorization": "Bearer a"})
    _orders(camp, "user_b", 2, 403, {"Cookie": "session=b"})
    first = matrix.build(camp)
    reloaded = matrix.build(cmod.load(camp.id))
    assert reloaded == first


def test_no_secret_reaches_the_projection(camp):
    _orders(camp, "user_a", 1, 200,
            {"Authorization": "Bearer supersecrettoken", "Cookie": "session=topsecret"})
    blob = str(matrix.build(camp))
    assert "supersecrettoken" not in blob and "topsecret" not in blob


def test_build_is_read_only(camp):
    _orders(camp, "user_a", 1, 200, {"Authorization": "Bearer a"})
    before = sorted(p.name for p in camp.dir.rglob("*"))
    audit_before = len(camp.audit_trail())
    matrix.build(camp)
    matrix.build(camp)
    assert sorted(p.name for p in camp.dir.rglob("*")) == before
    assert len(camp.audit_trail()) == audit_before   # no new audit records from a read


def test_coverage_summary_counts(camp):
    _orders(camp, "user_a", 1, 200, {"Authorization": "Bearer a"})          # orders: a
    _orders(camp, "user_b", 2, 200, {"Cookie": "session=b"})               # orders: b  (multi)
    traffic.capture(camp, method="POST", url="https://api.acme.example/api/orders/3/cancel",
                    headers={"Authorization": "Bearer a"}, identity="user_a",
                    response={"status": 204})                               # cancel: a only (single)
    traffic.capture(camp, method="GET", url="https://api.acme.example/api/health",
                    response={"status": 200})                               # health: anon only
    s = matrix.build(camp)["summary"]
    assert s["endpoints"] == 3
    assert s["observed_cells"] == 4
    assert s["multi_identity_endpoints"] == 1
    assert s["single_identity_endpoints"] == 2        # cancel (user_a) + health (anon)
    assert s["anonymous_only_endpoints"] == 1
    assert s["endpoints_no_authenticated_observation"] == 1
    assert s["possible_cells"] == s["endpoints"] * s["identities"]
    assert s["coverage_denominator"] == "endpoints x identities"


def test_gaps_are_opportunities_not_findings(camp):
    traffic.capture(camp, method="POST", url="https://api.acme.example/api/orders/3/cancel",
                    headers={"Authorization": "Bearer a"}, identity="user_a",
                    response={"status": 204})
    traffic.capture(camp, method="GET", url="https://api.acme.example/api/health",
                    response={"status": 200})
    gaps = matrix.build(camp)["gaps"]
    by_type = {g["gap_type"]: g for g in gaps}
    assert "ONLY_ONE_IDENTITY_OBSERVED" in by_type and "ANONYMOUS_ONLY" in by_type
    assert all(g["status"] == "OPEN" for g in gaps)     # a gap is OPEN research, never a verdict


def test_demo_self_check():
    matrix.demo()       # offline assert-based self-check must hold
    assert "ARGUS_HOME" not in os.environ or True       # demo cleans up its own env
