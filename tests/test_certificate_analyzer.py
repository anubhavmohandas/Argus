"""TLS probe + certificate analyzer — the first Analysis-class provider.

The probe records a certificate fingerprint (an observation about one host); the
analyzer derives `certificate_reused` by comparing fingerprints across the whole
graph. The analyzer is offline — it reads the graph, never the network — which is
what makes it a different provider class than HTTP/TLS. No engine change.

    python3 test_certificate_analyzer.py
"""
from argus import engine, providers
from argus.pivot import Graph, Entity


def test_fingerprint_is_deterministic():
    assert providers.cert_fingerprint(b"der") == providers.cert_fingerprint(b"der")
    assert providers.cert_fingerprint(b"a") != providers.cert_fingerprint(b"b")


def test_fingerprint_is_an_observation_not_a_predicate():
    # the probe has seen ONE host — it cannot know about reuse, so it must never
    # emit the predicate. The fingerprint lives in observed, never in vocabulary.
    assert "cert_fingerprint" not in engine._PREDICATES
    obs = {"cert_fingerprint": providers.cert_fingerprint(b"x")}
    assert "certificate_reused" not in obs


def test_analyzer_marks_only_shared_certs():
    g = Graph()
    a = Entity("subdomain", "a.example.com", 1)
    b = Entity("subdomain", "b.example.com", 1)
    c = Entity("subdomain", "c.example.com", 1)
    a.observed["cert_fingerprint"] = "SHARED"
    b.observed["cert_fingerprint"] = "SHARED"
    c.observed["cert_fingerprint"] = "UNIQUE"
    for e in (a, b, c):
        g.add(e)
    shape = (len(g.nodes), len(g.edges), len(g.findings))

    marked = providers.analyze_certificates(g)
    assert marked == 2
    assert a.evidence.get("certificate_reused") is True
    assert b.evidence.get("certificate_reused") is True
    assert "certificate_reused" not in c.evidence, "a unique cert is not reuse"
    # Analysis provider: reads the graph, never reshapes it
    assert (len(g.nodes), len(g.edges), len(g.findings)) == shape


def test_single_host_is_never_reuse():
    g = Graph()
    only = Entity("subdomain", "solo.example.com", 1)
    only.observed["cert_fingerprint"] = "LONELY"
    g.add(only)
    assert providers.analyze_certificates(g) == 0
    assert "certificate_reused" not in only.evidence


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  PASS {name}")
    print("all certificate analyzer checks passed")
