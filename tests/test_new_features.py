"""Self-checks for the roadmap features added this pass: engagement scope, the
politeness throttle, security.txt discovery, exposed-secret escalation, the CORS
`Origin: null` variant, and Markdown report export. Pure logic only — no network.

Run: `python test_new_features.py` (same standalone pattern as the other suites).
"""
from argus import providers, scope, engine
from argus.pivot import Entity, Graph, report_markdown, _repro_for
from argus.engine import investigate


# --- scope ----------------------------------------------------------------
def test_scope_matching():
    s = scope.Scope(include=["example.com", "*.dev.example.org", "10.0.0.0/8"],
                    exclude=["corp.example.com"])
    assert s.allows("example.com") and s.allows("api.example.com")
    assert not s.allows("corp.example.com")            # exclusion wins
    assert not s.allows("api.corp.example.com")        # under an excluded host
    assert s.allows("a.dev.example.org") and not s.allows("dev.example.org")  # *. is subdomains only
    assert s.allows("10.9.9.9") and not s.allows("11.0.0.1")
    assert not s.allows("unrelated.net")               # inclusions present => must match one


def test_scope_only_exclusions_allows_rest():
    s = scope.Scope(include=[], exclude=["bad.com"])
    assert s.allows("good.com") and not s.allows("bad.com")


def test_scope_rejects_garbage_entry(tmp=None):
    import tempfile, os
    fd, path = tempfile.mkstemp(suffix=".scope")
    os.write(fd, b"example.com\nnot a host!!\n")
    os.close(fd)
    try:
        scope.load(path)
    except ValueError as e:
        assert "line 2" in str(e)
    else:
        raise AssertionError("a malformed scope entry must fail loudly")
    finally:
        os.unlink(path)


def test_permitted_blocks_out_of_scope_without_network():
    # scope check runs BEFORE the SSRF/DNS resolve, so an out-of-scope host is
    # rejected without a lookup — no network in this test.
    providers.set_scope(scope.Scope(include=["example.com"], exclude=[]))
    try:
        assert providers._permitted("evil.invalid") is False
    finally:
        providers.set_scope(None)   # never leak scope into other tests


# --- throttle -------------------------------------------------------------
def test_throttle_budget_exhausts():
    providers.set_rate(max_requests=3)
    try:
        got = [providers._throttle.acquire() for _ in range(4)]
        assert got == [True, True, True, False], got
    finally:
        providers.set_rate()    # back to unlimited


def test_throttle_rate_sets_interval():
    providers.set_rate(rate=10)
    try:
        assert abs(providers._throttle.min_interval - 0.1) < 1e-9
    finally:
        providers.set_rate()


def test_fetch_returns_nothing_when_budget_exhausted():
    # a 0-request budget means _fetch never sends: it returns the "unreachable"
    # tuple, which every provider reads as "established nothing" (I-1). No network.
    providers.set_rate(max_requests=0)
    try:
        assert providers._fetch("https://example.com/", 1.0) == (0, {}, "")
    finally:
        providers.set_rate()


def test_retry_after_parse():
    assert providers._retry_after({"retry-after": "12"}) == 12.0
    assert providers._retry_after({}) == 5.0            # default when absent
    assert providers._retry_after({"retry-after": "Wed, 21 Oct 2099 07:28:00 GMT"}) == 5.0


# --- security.txt ---------------------------------------------------------
def test_security_txt_needs_contact():
    good = "Contact: mailto:security@example.com\nPolicy: https://example.com/policy\n"
    parsed = providers.parse_security_txt(good)
    assert parsed["contact"] == ["mailto:security@example.com"]
    assert parsed["policy"] == ["https://example.com/policy"]
    # an HTML soft-404 has no Contact line => not a security.txt
    assert providers.parse_security_txt("<html><body>not found</body></html>") == {}


# --- exposed secret -------------------------------------------------------
def test_secrets_in_redacts():
    body = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nDEBUG=true\n"
    hits = providers.secrets_in(body)
    assert hits, "a live-format AWS key must be detected"
    raw = "AKIAIOSFODNN7EXAMPLE"
    for h in hits:
        assert raw not in h["preview"], "the raw secret must never appear in output"
        assert "…" in h["preview"] or h["preview"] == "*" * len(h["preview"])
    assert providers.secrets_in("just some ordinary page text") == []


def test_exposed_secret_rule_fires():
    g = Graph()
    g.add(Entity("subdomain", "leak.example.com", 1,
                 evidence={"internet_facing": True, "exposed_secret": True}))
    result = investigate(g)
    fired = [c.rule for c in result.risks]
    assert "exposed_secret" in fired, fired
    c = next(c for c in result.risks if c.rule == "exposed_secret")
    assert c.severity == "critical"


def test_exposed_secret_predicate_in_vocab():
    assert "exposed_secret" in engine._PREDICATES


# --- CORS null variant ----------------------------------------------------
def test_cors_reflected_and_null():
    reflected = {"access-control-allow-origin": providers._CORS_PROBE_ORIGIN,
                 "access-control-allow-credentials": "true"}
    assert providers.cors_evidence(reflected) == {"cors_misconfig": True}
    null_ok = {"access-control-allow-origin": "null",
               "access-control-allow-credentials": "true"}
    assert providers.cors_null_evidence(null_ok) == {"cors_misconfig": True}
    # null without credentials is not the exploitable case
    assert providers.cors_null_evidence({"access-control-allow-origin": "null"}) == {}
    # a specific-but-different origin echoed is not our probe origin
    assert providers.cors_evidence({"access-control-allow-origin": "https://real.example",
                                    "access-control-allow-credentials": "true"}) == {}


# --- report export --------------------------------------------------------
def test_report_markdown_renders_findings():
    g = Graph()
    e = Entity("subdomain", "vuln.example.com", 1,
               evidence={"internet_facing": True, "exposed_sensitive_file": True})
    g.add(e)
    e.observed["security_txt"] = {"url": "https://example.com/.well-known/security.txt",
                                  "contact": ["mailto:security@example.com"], "policy": []}
    result = investigate(g)
    md = report_markdown("example.com", g, result)
    assert md.startswith("# ARGUS report")
    assert "vuln.example.com" in md
    assert "security@example.com" in md            # disclosure contact surfaced
    assert "Evidence ledger" in md and "```" in md
    assert "Remediation" in md
    # the "how determined" line is the provider method, keyed off the fired predicate
    c = next(c for c in result.risks if "noise" not in c.tags)
    assert _repro_for(c) != "See the evidence ledger below for the predicates that fired."


def test_report_markdown_no_findings_is_honest():
    g = Graph()
    g.add(Entity("domain", "quiet.example.com", 0))
    md = report_markdown("quiet.example.com", g, investigate(g))
    assert "No deterministic conclusion" in md


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  PASS {name}")
    print("all new-feature checks passed")
