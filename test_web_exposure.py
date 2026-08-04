"""Web-exposure providers (owasp_scanner patterns as evidence).

Everything here is pure — the header/cookie parsing and the sensitive-file
signature matching run with no network and no engine, per Provider Contract
item 4. The one architectural test at the end proves the whole point: new
evidence, existing engine, a conclusion falls out with zero engine changes.

    python3 test_web_exposure.py
"""
from argus import engine, providers
from argus.pivot import Entity, Graph


# --- security headers (free, from the base `/` response) ------------------
def test_missing_security_headers_is_pure_and_specific():
    assert providers.missing_security_headers({}) == list(providers._SECURITY_HEADERS)
    full = {h: "x" for h in providers._SECURITY_HEADERS}
    assert providers.missing_security_headers(full) == []
    partial = {"content-security-policy": "default-src 'self'"}
    assert "content-security-policy" not in providers.missing_security_headers(partial)


def test_evidence_from_flags_missing_headers_only_on_a_served_page():
    # 200 with nothing set: checked, and they're missing -> established True
    assert providers.evidence_from(200, {}, "")["security_headers_missing"] is True
    # 200 with all present: checked, fine -> established False (not silence)
    full = {h: "x" for h in providers._SECURITY_HEADERS}
    assert providers.evidence_from(200, full, "")["security_headers_missing"] is False
    # a 401/redirect is not a served page: we make no hardening claim (unknown)
    assert "security_headers_missing" not in providers.evidence_from(401, {}, "")
    assert "security_headers_missing" not in providers.evidence_from(302, {"location": "/login"}, "")


# --- insecure cookie ------------------------------------------------------
def test_cookie_flags():
    # no cookie set -> unknown, never "secure"
    assert providers.cookie_is_insecure({}) is None
    # https, both flags -> fine
    assert providers.cookie_is_insecure({"set-cookie": "id=1; HttpOnly; Secure"}, "https") is False
    # https, missing Secure -> insecure
    assert providers.cookie_is_insecure({"set-cookie": "id=1; HttpOnly"}, "https") is True
    # missing HttpOnly -> insecure regardless of scheme
    assert providers.cookie_is_insecure({"set-cookie": "id=1; Secure"}, "https") is True
    # over plain http, Secure absence alone is not the finding (only HttpOnly counts)
    assert providers.cookie_is_insecure({"set-cookie": "id=1; HttpOnly"}, "http") is False


def test_evidence_from_only_asserts_engine_vocabulary():
    ev = providers.evidence_from(200, {"set-cookie": "id=1"}, "")
    assert ev["insecure_cookie"] is True
    assert set(ev) <= set(engine._PREDICATES), "a provider may only assert engine vocabulary"


# --- exposed sensitive file (control-gated, signature-checked) ------------
_NOT_FOUND = (404, {}, "not found")
_CATCHALL = (200, {}, "<title>App</title>")   # a host that 200s for everything


def _resp(body, status=200):
    return (status, {}, body)


def test_real_git_head_is_evidence():
    control = providers._shape(*_NOT_FOUND)
    responses = {"/.git/HEAD": _resp("ref: refs/heads/main\n"),
                 "/.env": _NOT_FOUND, "/.DS_Store": _NOT_FOUND}
    assert providers.sensitive_evidence(control, responses) == {"exposed_sensitive_file": True}


def test_real_dotenv_is_evidence():
    control = providers._shape(*_NOT_FOUND)
    responses = {"/.git/HEAD": _NOT_FOUND,
                 "/.env": _resp("DB_PASSWORD=hunter2\nAPI_KEY=abc\n"), "/.DS_Store": _NOT_FOUND}
    assert providers.sensitive_evidence(control, responses) == {"exposed_sensitive_file": True}


def test_catchall_host_proves_nothing():
    # host answers 200 for the control path too -> every 200 has the control shape
    control = providers._shape(*_CATCHALL)
    responses = {p: _CATCHALL for p in providers._SENSITIVE_PATHS}
    assert providers.sensitive_evidence(control, responses) == {}, \
        "a host that 200s for everything must not read as an exposed file"


def test_soft_404_body_is_not_a_git_repo():
    # different shape from control, but the body isn't a real HEAD -> no claim
    control = providers._shape(*_NOT_FOUND)
    responses = {"/.git/HEAD": _resp("<html>page not found</html>"),
                 "/.env": _NOT_FOUND, "/.DS_Store": _NOT_FOUND}
    assert providers.sensitive_evidence(control, responses) == {}


def test_unreachable_paths_never_assert_false():
    control = providers._shape(*_NOT_FOUND)
    responses = {p: (0, {}, "") for p in providers._SENSITIVE_PATHS}
    assert providers.sensitive_evidence(control, responses) == {}, \
        "never reached is unknown, not 'no file exposed' (I-1)"


# --- the payoff: new evidence, existing engine, a conclusion --------------
def test_exposed_file_produces_a_conclusion_with_no_engine_change():
    g = Graph()
    e = Entity("subdomain", "assets.example.com", 1)
    g.add(e)
    e.evidence.update({"internet_facing": True, "exposed_sensitive_file": True})
    concl = engine.evaluate(g, engine.load_rules())
    fired = [c for c in concl if c.rule == "exposed_sensitive_file"]
    assert fired, "the exposed-file rule must fire on the provider's evidence"
    assert fired[0].confidence == 70 and fired[0].priority == "high"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  PASS {name}")
    print("all web-exposure checks passed")
