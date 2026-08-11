"""Path-traversal probe: control-gated, signature-verified, honest.

Same discipline as the exposed-file probe. A payload only counts if the response
BOTH differs from the host's "nothing here" shape (else it's a catch-all/soft-404)
AND the body is a real /etc/passwd. It never asserts a negative — payloads coming
back empty means we tried them, not that traversal is impossible (I-1).

    python3 test_traversal.py
"""
from argus import engine, providers
from argus.pivot import Graph, Entity

_PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
_CTRL = (404, {}, "<title>Not Found</title>")   # what this host says for something absent


def test_real_passwd_body_confirms_traversal():
    ctrl = providers._shape(*_CTRL)
    ev = providers.traversal_evidence(ctrl, {"/p": (200, {}, _PASSWD)})
    assert ev == {"path_traversal": True}


def test_soft_404_branded_200_is_not_traversal():
    # a host that answers 200 for everything (SPA/catch-all): the payload's shape
    # equals the control shape, so it proves nothing even at status 200.
    ctrl = providers._shape(200, {}, "<title>App</title>")
    responses = {"/p": (200, {}, "<title>App</title>")}
    assert providers.traversal_evidence(ctrl, responses) == {}


def test_200_without_the_signature_is_not_traversal():
    # differs from control, but the body isn't /etc/passwd — not a file read.
    ctrl = providers._shape(*_CTRL)
    assert providers.traversal_evidence(ctrl, {"/p": (200, {}, "hello world")}) == {}


def test_unreachable_payloads_establish_nothing():
    ctrl = providers._shape(*_CTRL)
    assert providers.traversal_evidence(ctrl, {"/a": (0, {}, ""), "/b": (0, {}, "")}) == {}


def test_probe_never_touches_a_non_global_target():
    for inward in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "localhost"):
        assert providers.traversal_probe(inward) == {}, inward


def test_only_owns_its_one_predicate():
    assert providers.PROVIDES["traversal_probe"] == ("path_traversal",)
    assert set(providers.PROVIDES["traversal_probe"]) <= set(engine._PREDICATES)


def test_traversal_fires_the_rule_through_the_unchanged_engine():
    g = Graph()
    e = Entity("subdomain", "vuln.example.com", 1, evidence={"path_traversal": True})
    g.add(e)
    conf = {c.rule: c for c in engine.investigate(g).conclusions}
    assert "path_traversal" in conf, "path_traversal evidence must fire the rule"
    c = conf["path_traversal"]
    assert c.severity == "critical" and c.confidence == 80
    assert any(chk.get("predicate") == "path_traversal" and chk.get("met")
               for chk in c.ledger["evidence"])


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  PASS {name}")
    print("all path-traversal checks passed")
