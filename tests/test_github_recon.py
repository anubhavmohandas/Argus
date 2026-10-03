"""Offline self-checks for the github_dork module. No network — injected fetchers.

    pytest tests/test_github_recon.py
"""
from argus import core
from argus.github_recon import (
    shannon_entropy, is_false_positive, redact, github_dork_scan, _raw_url,
)


def test_entropy_orders_sensibly():
    assert shannon_entropy("aaaaaaaa") < shannon_entropy("Lf9mNoEXifdcFNXU0eB4xcDxxqd")
    assert shannon_entropy("") == 0.0


def test_false_positive_filter():
    # placeholders / test / dummy → dropped
    for fp in ("password", "your_api_key", "example", "changeme", "xxxxxxxx",
               "1234", "aaaaaaaa", "token_here", "test"):
        assert is_false_positive(fp), fp
    # AWS's own doc key contains "EXAMPLE" — correctly treated as a false positive
    assert is_false_positive("AKIAIOSFODNN7EXAMPLE")
    # real provider-format secrets (no placeholder markers) → kept
    assert not is_false_positive("AKIAZ3XB7EXKJQ4NPFLW")
    assert not is_false_positive("ghp_" + "a1B2c3" * 6)  # 36 chars, ghp_ prefix
    assert not is_false_positive("Lf9mNoEXifdcFNXU0eB4xcDxxqdfGXkXpa0WwQszu")


def test_redact_never_leaks_full_value():
    v = "Lf9mNoEXifdcFNXU0eB4xcDxxqdfGXkXpa0WwQszu"
    r = redact(v)
    assert v not in r          # full secret never present
    assert r.startswith("Lf9m") and "Qszu" in r  # first/last 4 kept for identification


def test_raw_url_mapping():
    html = "https://github.com/owner/repo/blob/abc123/path/to/file.env"
    assert _raw_url(html) == "https://raw.githubusercontent.com/owner/repo/abc123/path/to/file.env"


def test_dork_scan_self_gates_and_triages():
    # one search hit; the RAW file carries a real GH PAT + a placeholder.
    real_pat = "ghp_" + "b2C4d6" * 6  # 36 chars
    fake = "your_api_key"

    def fake_gh(url, token, timeout=15.0):
        if "search/code" in url:
            return {"items": [{
                "html_url": "https://github.com/acme/leak/blob/deadbeef/config.env",
                "repository": {"full_name": "acme/leak"},
                "path": "config.env",
            }]}
        return None

    def fake_raw(url, timeout=15.0):
        return 200, f"GITHUB_TOKEN={real_pat}\nAPI_KEY={fake}\n"

    hits = list(github_dork_scan("acme.com", "tok", gh_get=fake_gh, raw_get=fake_raw))
    # the real PAT is kept; the placeholder is filtered
    assert len(hits) == 1, [h.title for h in hits]
    f = hits[0]
    assert f.severity == core.CRITICAL
    assert "acme/leak" in f.data["repository"]
    assert real_pat not in f.data["match_redacted"]  # redacted
    assert f.data["verify_cmd"].startswith("curl -sS 'https://raw.githubusercontent.com/")


def test_dork_scan_skips_when_file_gone():
    # RAW returns 404 (force-pushed) → cannot self-gate → no finding
    def fake_gh(url, token, timeout=15.0):
        if "search/code" in url:
            return {"items": [{
                "html_url": "https://github.com/acme/leak/blob/dead/x.env",
                "repository": {"full_name": "acme/leak"}, "path": "x.env",
            }]}
        return None

    def fake_raw(url, timeout=15.0):
        return 404, ""

    assert list(github_dork_scan("acme.com", "tok", gh_get=fake_gh, raw_get=fake_raw)) == []


def test_module_registered():
    assert "github_dork" in core.MODULES
    assert core.MODULES["github_dork"].kind == "domain"
