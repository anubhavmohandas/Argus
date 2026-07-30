"""Offline self-checks for the Argus engine. No network — runs anywhere.

    python3 test_argus.py    # asserts, exits 0 on pass
"""
from argus import core
from argus.core import Finding, check_target, sort_by_severity
from argus.modules import scan_text
from argus.pivot import classify, pivot, Budget, Graph, Entity, _extract, _normalize_child


def test_validation():
    assert core.validate_ip("8.8.8.8") == "8.8.8.8"
    assert core.validate_domain("HTTPS://Example.com/path") == "example.com"
    for bad in ("not a domain", "10.0.0.999", "a..b", "with space"):
        try:
            core.validate_domain(bad); assert False, f"accepted bad domain {bad!r}"
        except ValueError:
            pass
    # control chars rejected at the boundary
    try:
        check_target("username", "bob\x00evil"); assert False
    except ValueError:
        pass


def test_classify():
    assert classify("8.8.8.8") == "ip"
    assert classify("example.com") == "domain"
    assert classify("alice@example.com") == "email"
    assert classify("+14155552671") == "phone"
    assert classify("neo") == "username"


def test_secret_scanner():
    hits = list(scan_text('AKIAIOSFODNN7EXAMPLE\nghp_' + "a" * 36 + '\nnothing here'))
    names = {f.title.split()[0] for f in hits}
    assert "AWS_ACCESS_KEY" in names, names
    assert "GH_PAT_CLASSIC" in names, names
    assert all(f.severity == core.CRITICAL for f in hits), "AWS+GH PAT are critical"
    # no false positive on a plain line
    assert not list(scan_text("just some normal text with words"))


def test_severity_sort():
    fs = [Finding("m", "t", "a", core.LOW), Finding("m", "t", "b", core.CRITICAL),
          Finding("m", "t", "c", core.MEDIUM)]
    assert [f.severity for f in sort_by_severity(fs)] == [core.CRITICAL, core.MEDIUM, core.LOW]


def test_extract_and_graph():
    # dns A record -> ip entity ; MX -> mail domain
    f = Finding("dns", "x.com", "A", core.INFO, data={"type": "A", "records": ["1.2.3.4"]})
    assert ("ip", "1.2.3.4", "resolves_to") in _extract(f, "x.com")
    mx = Finding("dns", "x.com", "MX", core.INFO, data={"type": "MX", "records": ["10 mail.x.com"]})
    assert ("domain", "mail.x.com", "mail_server") in _extract(mx, "x.com")
    # graph dedupes nodes, records edges
    g = Graph()
    a = Entity("domain", "x.com", 0); b = Entity("ip", "1.2.3.4", 1)
    assert g.add(a) is True
    assert g.add(a) is False          # dedupe
    g.add(b, a, "resolves_to")
    assert (a.key, "resolves_to", b.key) in g.edges


def test_normalize_child_drops_junk():
    # null-MX "0 ." parses to host "0" in _extract — must be dropped, not a node
    assert _normalize_child("domain", "0") is None
    assert _normalize_child("domain", "MAIL.Example.COM") == "mail.example.com"  # lowercased
    assert _normalize_child("ip", "not.an.ip") is None
    assert _normalize_child("ip", "1.2.3.4") == "1.2.3.4"


def test_pivot_offline_fanout():
    # max_depth=-1 forbids running any (network) module, so this stays offline.
    # An email seed still fans out into domain + username nodes before the loop.
    g = pivot("alice@example.com", Budget(max_depth=-1, max_entities=5))
    assert isinstance(g, Graph)
    kinds = {e.type for e in g.nodes.values()}
    assert {"email", "domain", "username"} <= kinds, kinds
    assert any(rel == "email_domain" for (_, rel, _) in g.edges)
    assert not g.findings  # nothing ran, so no findings — proves no network path taken


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  PASS {name}")
    print("all self-checks passed")
