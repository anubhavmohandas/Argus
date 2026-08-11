"""Web-class probes (clickjacking, CORS, GraphQL introspection, subdomain
takeover, open redirect, reflected XSS, SSTI, email spoofing) — same discipline
as the traversal probe: pure evidence functions, honest about the unchecked
(I-1), self-gating signatures, and each firing its rule through the unchanged
engine.

    python3 test_web_vulns.py
"""
from argus import engine, providers
from argus.pivot import Graph, Entity


# --- clickjacking (framability from headers, zero extra requests) ---------
def test_no_framing_headers_is_framable():
    assert providers.is_framable({}) is True


def test_xframe_or_csp_frame_ancestors_is_protected():
    assert providers.is_framable({"x-frame-options": "DENY"}) is False
    assert providers.is_framable({"x-frame-options": "SameOrigin"}) is False
    assert providers.is_framable(
        {"content-security-policy": "default-src 'self'; frame-ancestors 'none'"}) is False


def test_200_sets_clickjacking_both_ways():
    # framable page -> True; protected page -> established False (checked, I-1), not silence
    assert providers.evidence_from(200, {}, "").get("clickjacking") is True
    assert providers.evidence_from(200, {"x-frame-options": "DENY"}, "").get("clickjacking") is False


# --- CORS (reflected arbitrary origin + credentials) ----------------------
def test_reflected_origin_with_credentials_is_misconfig():
    h = {"access-control-allow-origin": providers._CORS_PROBE_ORIGIN,
         "access-control-allow-credentials": "true"}
    assert providers.cors_evidence(h) == {"cors_misconfig": True}


def test_reflection_without_credentials_is_not_claimed():
    h = {"access-control-allow-origin": providers._CORS_PROBE_ORIGIN}
    assert providers.cors_evidence(h) == {}


def test_no_acao_header_establishes_nothing():
    assert providers.cors_evidence({}) == {}                 # unknown, never a false negative
    assert providers.cors_evidence({"access-control-allow-origin": "*",
                                    "access-control-allow-credentials": "true"}) == {}


# --- GraphQL (introspection signature is self-gating) ---------------------
def test_live_schema_confirms_introspection():
    body = '{"data":{"__schema":{"queryType":{"name":"Query"}}}}'
    assert providers.introspection_confirmed(body) is True


def test_error_or_soft404_is_not_introspection():
    assert providers.introspection_confirmed('{"errors":[{"message":"nope"}]}') is False
    assert providers.introspection_confirmed("<title>Not Found</title>") is False
    assert providers.introspection_confirmed('{"data":{"__schema":null}}') is False


# --- subdomain takeover (vendor unclaimed-page fingerprint, free from base body) -
def test_vendor_unclaimed_page_fingerprints_takeover():
    assert providers.takeover_service("...There isn't a GitHub Pages site here.") == "github-pages"
    assert providers.takeover_service("<Code>NoSuchBucket</Code>") == "aws-s3"


def test_generic_404_is_not_takeover():
    assert providers.takeover_service("<h1>404 Not Found</h1>") is None
    # a 404 vendor page still fingerprints (status doesn't matter, the string does)
    assert providers.evidence_from(404, {}, "there isn't a github pages site here").get(
        "subdomain_takeover") is True


# --- email spoofing (DMARC enforcement, DNS-only) -------------------------
def test_missing_or_none_dmarc_is_spoofable():
    assert providers.email_spoofable([]) is True                       # no DMARC at all
    assert providers.email_spoofable(["v=DMARC1; p=none; rua=mailto:x"]) is True


def test_enforced_dmarc_is_not_spoofable():
    assert providers.email_spoofable(["v=DMARC1; p=reject"]) is False
    assert providers.email_spoofable(["v=DMARC1; p=quarantine; pct=100"]) is False


# --- open redirect (unique external canary in the Location header) --------
def test_redirect_to_injected_host_is_open_redirect():
    resp = {"next": (302, "https://argus-openredirect-canary.example/")}
    assert providers.redirect_evidence(resp) == {"open_redirect": True}


def test_redirect_to_other_host_is_not_flagged():
    # a 302 to the app's own login, not to our canary — not an open redirect
    assert providers.redirect_evidence({"next": (302, "https://vuln.example.com/login")}) == {}
    assert providers.redirect_evidence({"next": (200, "")}) == {}


# --- reflected XSS + SSTI (unescaped reflection / rendered template) -------
def test_unescaped_reflection_is_xss_only():
    body = "hi " + providers._XSS_PAYLOAD + " there"      # raw <svg…> came back intact
    assert providers.injection_evidence([body]) == {"reflected_xss": True}


def test_encoded_reflection_is_not_xss():
    # angle brackets HTML-encoded on the way out — reflected, but not executable
    body = "hi argusx55&lt;svg/onload=confirm(1)&gt;argussti{{7*7}} there"
    assert providers.injection_evidence([body]) == {}


def test_rendered_template_is_ssti():
    assert providers.injection_evidence(["out: " + providers._SSTI_EVAL]) == {"ssti": True}
    # literal echo of {{7*7}} is reflection, not evaluation
    assert "ssti" not in providers.injection_evidence(["out: argussti{{7*7}}"])


# --- SSRF guard: no probe ever touches a non-global target ----------------
def test_probes_never_touch_non_global_targets():
    for inward in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "localhost"):
        assert providers.cors_probe(inward) == {}, inward
        assert providers.graphql_probe(inward) == {}, inward
        assert providers.redirect_probe(inward) == {}, inward
        assert providers.injection_probe(inward) == {}, inward


# --- manifest: each provider owns exactly its predicate(s) ----------------
def test_providers_own_their_predicates():
    assert {"clickjacking", "subdomain_takeover"} <= set(providers.PROVIDES["http_probe"])
    assert providers.PROVIDES["cors_probe"] == ("cors_misconfig",)
    assert providers.PROVIDES["graphql_probe"] == ("graphql_introspection",)
    assert providers.PROVIDES["redirect_probe"] == ("open_redirect",)
    assert providers.PROVIDES["injection_probe"] == ("reflected_xss", "ssti")
    assert providers.PROVIDES["email_spoof"] == ("email_spoofable",)
    for preds in providers.PROVIDES.values():
        assert set(preds) <= set(engine._PREDICATES)


# --- each fact fires its rule through the unchanged engine -----------------
def _fire(evidence):
    g = Graph()
    g.add(Entity("subdomain", "vuln.example.com", 1, evidence=evidence))
    return {c.rule: c for c in engine.investigate(g).conclusions}


def test_each_web_vuln_fires_its_rule():
    # (rule id, predicate that triggers it, expected severity) — the rule id and
    # its predicate differ for email (email_spoofing / email_spoofable).
    cases = [
        ("clickjacking", "clickjacking", "medium"),
        ("cors_misconfig", "cors_misconfig", "high"),
        ("graphql_introspection", "graphql_introspection", "low"),
        ("subdomain_takeover", "subdomain_takeover", "high"),
        ("open_redirect", "open_redirect", "medium"),
        ("reflected_xss", "reflected_xss", "high"),
        ("ssti", "ssti", "critical"),
        ("email_spoofing", "email_spoofable", "low"),
    ]
    for rule, predicate, severity in cases:
        conf = _fire({predicate: True})
        assert rule in conf, f"{predicate} evidence must fire rule {rule}"
        assert conf[rule].severity == severity, f"{rule} severity"
        assert any(chk.get("predicate") == predicate and chk.get("met")
                   for chk in conf[rule].ledger["evidence"])


def test_protected_page_does_not_fire_clickjacking():
    # clickjacking=False is an established negative — the rule must NOT fire on it
    assert "clickjacking" not in _fire({"clickjacking": False})


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  PASS {name}")
    print("all web-vuln checks passed")
