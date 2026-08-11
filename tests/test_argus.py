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
    assert ("ip", "1.2.3.4", "resolves_to") in _extract(f)
    mx = Finding("dns", "x.com", "MX", core.INFO, data={"type": "MX", "records": ["10 mail.x.com"]})
    assert ("domain", "mail.x.com", "mail_server") in _extract(mx)
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


def test_priority():
    # priority is a conclusion kind, not a second output type: same Conclusion,
    # same ledger, ranked by score instead of confidence.
    from argus import engine
    g = Graph()
    for v in ("admin.example.com", "cdn-static.example.com", "shop.example.com"):
        g.add(Entity("subdomain", v, 1))
    r = engine.investigate(g)
    score = {p.target: p.score for p in r.priority}
    assert score["admin.example.com"] > score["shop.example.com"] > score["cdn-static.example.com"], score
    assert r.interesting[0].target == "admin.example.com"         # look here first
    assert "admin surface" in r.interesting[0].name
    assert [p.target for p in r.noise] == ["cdn-static.example.com"]
    # the score is traceable, exactly like a confidence — no opaque number (I-2)
    top = r.interesting[0]
    assert top.kind == "priority" and top.confidence == 100
    assert {"predicate": "name:admin", "applied": True, "delta": 5} in top.ledger["evidence"]
    assert top.ledger["final"] == top.score
    # read-only: scoring must not mutate the evidence graph
    before = g.to_dict()
    engine.investigate(g)
    assert g.to_dict() == before
    # a critical finding on an otherwise-boring host lifts it above the bare name
    g.findings.append(Finding("secrets", "shop.example.com", "AWS_ACCESS_KEY", core.CRITICAL))
    score2 = {p.target: p.score for p in engine.investigate(g).priority}
    assert score2["shop.example.com"] > score2["admin.example.com"]


def test_rules():
    # Investigator Rule Engine: deterministic conclusions + traceable ledger.
    from argus import engine
    g = Graph()
    g.add(Entity("subdomain", "jenkins.example.com", 1, evidence={"public_exploit": True}))
    rules = engine.load_rules()  # the shipped TOML rule files parse + validate

    c1 = engine.evaluate(g, rules)
    jc = [c for c in c1 if c.rule == "jenkins_suspected"]
    assert jc, [c.rule for c in c1]
    # name-only lead (40) + public exploit (10). Reaching 65 needs probe facts —
    # the name alone must never score like a verified finding.
    assert jc[0].confidence == 50 and jc[0].severity == "high", jc[0]
    calc = jc[0].ledger["calculation"]                    # 40 base, +10 public_exploit -> traceable
    assert calc[0] == {"step": "base", "delta": 40}
    assert {"step": "public_exploit", "delta": 10} in calc
    assert jc[0].rule_version == 2, jc[0]                 # provenance: which rule version concluded this

    # Principle 8 — reproducible: same graph + same rules => identical output + hash
    c2 = engine.evaluate(g, rules)
    assert [c.to_dict() for c in c1] == [c.to_dict() for c in c2]
    fp = engine.fingerprint(g, rules)
    assert fp == engine.fingerprint(g, rules)

    # read-only: evaluation must not mutate the evidence graph
    before = g.to_dict()["nodes"]
    engine.evaluate(g, rules)
    assert g.to_dict()["nodes"] == before

    # changing the graph changes the fingerprint (and therefore the conclusions)
    g.add(Entity("subdomain", "admin.example.com", 1))
    assert engine.fingerprint(g, rules) != fp

    # confidence is clamped to 0..100 — never exceeds what evidence justifies
    hi = engine.evaluate(g, [{"id": "hi", "base_confidence": 95, "requires": {"publicly_discoverable": True},
                              "adjustments": [{"if": "public_exploit", "add": 50}], "outputs": {}}])
    assert all(c.confidence <= 100 for c in hi) and any(c.confidence == 100 for c in hi)
    g.nodes["subdomain:admin.example.com"].evidence["authentication_required"] = True
    lo = engine.evaluate(g, [{"id": "lo", "base_confidence": 10, "requires": {"name_suggests_admin": True},
                              "adjustments": [{"if": "authentication_required", "subtract": 50}], "outputs": {}}])
    assert all(c.confidence >= 0 for c in lo) and any(c.confidence == 0 for c in lo)

    # closed vocabulary: an unknown predicate is rejected, not silently ignored
    try:
        engine.evaluate(g, [{"id": "x", "requires": {"made_up_predicate": True}}]); assert False
    except engine.RuleError:
        pass
    # security invariant: a rule carrying an executable key is rejected at load
    try:
        engine.evaluate(g, [{"id": "x", "python": "import os"}]); assert False
    except engine.RuleError:
        pass
    # allowlist, not denylist: a typo'd key is rejected too, rather than silently
    # ignored (a rule that quietly never fires is the bug you never find)
    try:
        engine.evaluate(g, [{"id": "x", "adjustment": [{"if": "public_exploit"}]}]); assert False
    except engine.RuleError:
        pass

    # two-tier vocabulary: a name is a lead, a probe is a fact. A probe fact is
    # never inferred from a hostname, and verifying it must raise confidence.
    g4 = Graph()
    g4.add(Entity("subdomain", "admin.example.com", 1))
    bare = g4.nodes["subdomain:admin.example.com"]
    assert engine._PREDICATES["name_suggests_admin"](bare, g4) is True
    assert engine._PREDICATES["has_admin_interface"](bare, g4) is None, \
        "a probe fact must stay unknown until something actually probed"
    lead = engine.evaluate(g4, rules)
    bare.evidence["has_admin_interface"] = True
    assert engine.evaluate(g4, rules)[0].confidence > lead[0].confidence, "verified must outrank suspected"

    # I-1 — unknown is not false. Nobody probed this host for authentication.
    g3 = Graph()
    g3.add(Entity("subdomain", "unchecked.example.com", 1))
    silent = [{"id": "assumes_no_auth", "base_confidence": 50,
               "requires": {"authentication_required": False}, "outputs": {}}]
    assert engine.evaluate(g3, silent) == [], \
        "silence must never satisfy a requirement — that is inventing negative evidence"
    # and an unchecked adjustment reads as '?', never as a negative
    g3.nodes["subdomain:unchecked.example.com"].evidence["has_admin_interface"] = True
    partial = engine.evaluate(g3, [{"id": "p", "base_confidence": 50,
                                    "requires": {"has_admin_interface": True},
                                    "adjustments": [{"if": "authentication_required", "subtract": 20}],
                                    "outputs": {}}])
    assert partial[0].confidence == 50, partial[0]        # unchecked => no adjustment
    lines = engine.ledger_lines(partial[0])
    assert "? authentication_required" in lines[0], lines
    assert "not established" in lines[-1], lines


def test_memory():
    import os, tempfile
    from argus import store
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["ARGUS_HOME"] = tmp
        try:
            g1 = Graph()
            g1.add(Entity("domain", "x.com", 0)); g1.add(Entity("subdomain", "a.x.com", 1))
            store.save("x.com", g1)
            hist = store.history("x.com")
            assert len(hist) == 1 and hist[0]["seed"] == "x.com"
            # next run finds a new subdomain — diff must catch it
            g2 = Graph()
            for v in ("x.com",): g2.add(Entity("domain", v, 0))
            for v in ("a.x.com", "b.x.com"): g2.add(Entity("subdomain", v, 1))
            new, gone = store.diff_keys(hist[-1], g2)
            assert "subdomain:b.x.com" in new and gone == set()
            assert "+1 new subdomain(s)" in store.compare_line(hist[-1], g2)
            # A case file maps someone else's infrastructure. Nothing outside the
            # owner may read it, and it is never world-readable for even an
            # instant — created 0600, not chmod'd after the data lands.
            if os.name == "posix":
                import stat
                p = store.save("x.com", g2)
                assert stat.S_IMODE(p.stat().st_mode) & 0o077 == 0, oct(p.stat().st_mode)
                assert stat.S_IMODE(store._home().stat().st_mode) & 0o077 == 0
        finally:
            os.environ.pop("ARGUS_HOME", None)


def test_color_gating_cross_platform():
    # colors must never leak into piped/redirected output on any OS
    import os
    from argus.cli import _color_enabled
    os.environ["NO_COLOR"] = "1"
    try:
        assert _color_enabled() is False
    finally:
        os.environ.pop("NO_COLOR", None)
    # under the test runner stdout is captured (not a tty), so it's off there too
    assert _color_enabled() is False


def test_evidence_provider():
    # The architectural test: a provider feeds evidence in, and existing rules
    # get more certain — with zero changes to engine.py, the rules, or the
    # result object. Pure parsing only; nothing here touches the network.
    from argus import engine, providers

    # 1. establishes only what it observed
    ev = providers.evidence_from(200, {"x-jenkins": "2.4"}, "<title>Dashboard [Jenkins]</title>")
    assert ev["technology"] == "jenkins" and ev["internet_facing"] is True
    assert ev["authentication_required"] is False        # probed, got the page: real negative
    assert providers.evidence_from(401, {"www-authenticate": "Basic"}, "")["authentication_required"]
    assert providers.evidence_from(403, {}, "")["authentication_required"]
    assert providers.evidence_from(302, {"location": "/login"}, "")["authentication_required"]
    # fingerprinting reads the <title>, never loose body text: a page that links
    # to gitlab is not gitlab. And unreachable establishes NOTHING.
    assert "technology" not in providers.evidence_from(
        200, {}, "<title>Home</title><a href='/x'>our gitlab and jenkins</a>")
    assert providers.evidence_from(0, {}, "") == {}, "no answer must not mean 'not internet-facing'"

    # 2. it never draws conclusions — those words belong to the rule engine
    assert set(ev) <= set(engine._PREDICATES), "a provider may only assert engine vocabulary"
    assert not {"priority", "confidence", "risk"} & set(ev)

    # 3. SSRF guard: a discovered name pointing inward is never probed.
    # IP literals + /etc/hosts only — getaddrinfo does no DNS for these.
    for inward in ("127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254", "localhost"):
        assert providers._resolvable_and_global(inward) is False, inward
    assert providers._resolvable_and_global("8.8.8.8") is True

    # 4. the payoff — same graph, same rules, better evidence
    g = Graph()
    g.add(Entity("subdomain", "jenkins.example.com", 1))
    rules = engine.load_rules()
    before = {c.rule: c.confidence for c in engine.evaluate(g, rules)}
    assert "jenkins_suspected" in before and "jenkins_confirmed" not in before

    g.nodes["subdomain:jenkins.example.com"].evidence.update(ev)   # provider speaks
    after = {c.rule: c.confidence for c in engine.evaluate(g, rules)}
    assert "jenkins_confirmed" in after, "probe evidence must fire the confirmed rule"
    assert after["jenkins_suspected"] > before["jenkins_suspected"], "verified outranks suspected"

    # 5. enrich() writes evidence and nothing else — discovery shape is untouched.
    # probe() is stubbed so this stays offline and deterministic.
    g.add(Entity("username", "someone", 1))     # not probeable — must be skipped
    shape = (len(g.nodes), len(g.edges), len(g.findings))
    real_probe = providers.probe
    providers.probe = lambda host, timeout=8.0: ({"internet_facing": True}, {})  # (evidence, observed)
    try:
        assert providers.enrich(g) == 1, "only the subdomain is probeable"
    finally:
        providers.probe = real_probe
    assert (len(g.nodes), len(g.edges), len(g.findings)) == shape
    assert g.nodes["username:someone"].evidence == {}


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
