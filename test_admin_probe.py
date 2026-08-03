"""Administrative-surface probe — the first path-based provider.

Every earlier probe asked a host one question (`/`). This one asks five, so the
tests here are mostly about restraint: what it refuses to assert. A control
request establishes what a nonexistent path looks like on this host, and a path
that answers the same way proves nothing — that is the whole defence against
catch-alls and soft-404s.

The core is pure (`admin_evidence`), so none of this touches the network.

    python3 test_admin_probe.py
"""
from argus import engine, providers
from argus.pivot import Graph, Entity

_NOT_FOUND = (404, {}, "<title>Not Found</title>")


def _r(status, headers=None, title=""):
    return status, headers or {}, f"<title>{title}</title>" if title else ""


def test_control_defines_nothing_here():
    # The host serves the SAME page for /admin/ as for a path that cannot exist.
    # That is a catch-all, so /admin/ is not a surface — nothing is established.
    control = providers._shape(*_r(200, title="Welcome"))
    responses = {p: _r(200, title="Welcome") for p in providers._ADMIN_PATHS}
    assert providers.admin_evidence(control, responses) == {}


def test_auth_challenge_on_admin_path_is_the_predicate():
    control = providers._shape(*_NOT_FOUND)
    responses = dict.fromkeys(providers._ADMIN_PATHS, _NOT_FOUND)
    responses["/admin/"] = _r(401, {"www-authenticate": 'Basic realm="admin"'})
    assert providers.admin_evidence(control, responses) == {"has_admin_interface": True}


def test_redirect_into_a_login_flow_counts():
    control = providers._shape(*_NOT_FOUND)
    responses = dict.fromkeys(providers._ADMIN_PATHS, _NOT_FOUND)
    responses["/manager/"] = _r(302, {"location": "https://sso.example.com/login"})
    assert providers.admin_evidence(control, responses) == {"has_admin_interface": True}


def test_redirect_to_somewhere_boring_does_not():
    control = providers._shape(*_NOT_FOUND)
    responses = dict.fromkeys(providers._ADMIN_PATHS, _NOT_FOUND)
    responses["/admin/"] = _r(301, {"location": "https://example.com/"})
    assert providers.admin_evidence(control, responses) == {}, \
        "a redirect home is not an admin surface"


def test_served_page_needs_a_recognisable_admin_title():
    control = providers._shape(*_NOT_FOUND)
    named = dict.fromkeys(providers._ADMIN_PATHS, _NOT_FOUND)
    named["/admin/"] = _r(200, title="Grafana Console")
    assert providers.admin_evidence(control, named) == {"has_admin_interface": True}

    unnamed = dict.fromkeys(providers._ADMIN_PATHS, _NOT_FOUND)
    unnamed["/admin/"] = _r(200, title="Hello")
    assert providers.admin_evidence(control, unnamed) == {}, \
        "an uncharacterised 200 is a page we cannot name, not an admin interface"


def test_never_asserts_false():
    # Four paths came back empty. That means we checked four paths — not that the
    # host has no admin surface. Absent stays absent (I-1): unknown, never False.
    control = providers._shape(*_NOT_FOUND)
    ev = providers.admin_evidence(control, dict.fromkeys(providers._ADMIN_PATHS, _NOT_FOUND))
    assert ev == {}
    assert "has_admin_interface" not in ev


def test_unreachable_paths_establish_nothing():
    control = providers._shape(*_NOT_FOUND)
    assert providers.admin_evidence(control, {p: (0, {}, "") for p in providers._ADMIN_PATHS}) == {}


def test_login_path_is_not_probed():
    # A login page is evidence of authentication, not of an admin surface;
    # `authentication_required` already carries that fact.
    assert "/login" not in providers._ADMIN_PATHS
    assert all("admin" in p or "manager" in p for p in providers._ADMIN_PATHS)


def test_request_budget_is_bounded():
    # Contract item 8: minimum path set. One control + the admin paths, per host.
    assert len(providers._ADMIN_PATHS) + 1 <= 5


def test_provider_only_writes_evidence():
    g = Graph()
    e = Entity("subdomain", "admin.example.com", 1)
    g.add(e)
    shape = (len(g.nodes), len(g.edges), len(g.findings))
    # no network: hand the pure core its answers, then apply them the way enrich does
    e.evidence.update(providers.admin_evidence(
        providers._shape(*_NOT_FOUND),
        {**dict.fromkeys(providers._ADMIN_PATHS, _NOT_FOUND),
         "/admin/": _r(403, {}, "Forbidden")}))
    assert e.evidence["has_admin_interface"] is True
    assert (len(g.nodes), len(g.edges), len(g.findings)) == shape


def test_predicate_is_engine_vocabulary_and_now_covered():
    assert "has_admin_interface" in engine._PREDICATES
    assert providers.coverage()["has_admin_interface"] == "admin_probe"


def test_it_unlocks_the_waiting_rule():
    # admin_interface_exposed.toml has carried `if = "has_admin_interface", add = 25`
    # with nothing able to satisfy it. This is the point of the provider.
    rule = next(r for r in engine.load_rules() if r["id"] == "admin_interface_exposed")
    assert any(a["if"] == "has_admin_interface" for a in rule["adjustments"])

    g = Graph()
    e = Entity("subdomain", "admin.example.com", 1)
    g.add(e)
    without = engine.investigate(g)
    e.evidence["has_admin_interface"] = True
    with_ev = engine.investigate(g)

    def conf(result):
        return next(c.confidence for c in result.conclusions if c.rule == "admin_interface_exposed")

    assert conf(with_ev) == conf(without) + 25, "the +25 rung is now reachable"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  PASS {name}")
    print("all admin probe checks passed")
