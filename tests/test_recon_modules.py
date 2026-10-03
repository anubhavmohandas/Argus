"""Offline self-checks for the Kongsec-derived recon modules (postman_dork,
jsmap, github_org) and the shared triage helpers. No network — fetchers injected.
"""
from argus import core
from argus.triage import shannon_entropy, is_false_positive, redact
from argus.postman_recon import postman_scan
from argus.js_recon import jsmap_scan
from argus.github_org import github_org_scan

REAL_PAT = "ghp_" + "b2C4d6" * 6          # 36 chars, structured prefix
REAL_AWS = "AKIAZ3XB7EXKJQ4NPFLW"
FAKE = "your_api_key"


def test_shared_triage():
    assert is_false_positive("password") and is_false_positive("your_api_key")
    assert not is_false_positive(REAL_PAT) and not is_false_positive(REAL_AWS)
    assert REAL_PAT not in redact(REAL_PAT)
    assert shannon_entropy("aaaa") < shannon_entropy(REAL_PAT)


def test_postman_scan_triages_and_redacts():
    def search(brand):
        return [{"id": "ws1", "name": "acme-public", "slug": "acme/x", "publicHandle": "https://postman.com/acme/x"}]

    def fetch(ws_id):
        return '{"values":[{"key":"bearer","value":"%s"},{"key":"demo","value":"%s"}]}' % (REAL_PAT, FAKE)

    hits = list(postman_scan("acme", search=search, fetch=fetch))
    assert len(hits) == 1, [h.title for h in hits]
    assert hits[0].severity == core.CRITICAL
    assert REAL_PAT not in hits[0].data["match_redacted"]
    assert hits[0].data["workspace_id"] == "ws1"


def test_postman_scan_empty_when_no_workspaces():
    assert list(postman_scan("acme", search=lambda b: [], fetch=lambda w: "")) == []


def test_jsmap_scan_from_archived_bundle():
    def list_js(domain):
        return ["https://web.archive.org/web/20250101id_/https://acme.com/static/app.min.js"]

    def fetch(u):
        return f'var cfg={{token:"{REAL_AWS}",demo:"{FAKE}"}};'

    hits = list(jsmap_scan("acme.com", list_js=list_js, fetch=fetch))
    assert len(hits) == 1, [h.title for h in hits]
    assert "app.min.js" in hits[0].title
    assert hits[0].data["js_url"] == "https://acme.com/static/app.min.js"
    assert REAL_AWS not in hits[0].data["match_redacted"]


def test_jsmap_empty_when_no_js():
    assert list(jsmap_scan("acme.com", list_js=lambda d: [], fetch=lambda u: "")) == []


def test_github_org_scans_added_history_lines():
    def list_repos(org, token):
        return ["https://github.com/acme/infra.git"]

    def history(clone_url):
        # a git log -p style diff: the secret is on an ADDED line
        return (
            "commit abc\n"
            "diff --git a/config.py b/config.py\n"
            "--- a/config.py\n"
            "+++ b/config.py\n"
            f"+GITHUB_TOKEN = '{REAL_PAT}'\n"
            f"-OLD = '{FAKE}'\n"
        )

    hits = list(github_org_scan("acme", "tok", list_repos=list_repos, history=history))
    assert len(hits) == 1, [h.title for h in hits]
    assert "acme/infra" in hits[0].data["repository"]
    assert REAL_PAT not in hits[0].data["match_redacted"]


def test_github_org_ignores_removed_lines_only():
    # secret appears ONLY on a removed line (-) → not an added secret → skip
    def history(clone_url):
        return "--- a/x\n+++ b/x\n-TOKEN='%s'\n" % REAL_PAT
    hits = list(github_org_scan("acme", "tok",
                                list_repos=lambda o, t: ["https://github.com/acme/x.git"],
                                history=history))
    assert hits == []


def test_all_modules_registered():
    for name in ("postman_dork", "jsmap", "github_org", "github_dork"):
        assert name in core.MODULES, name
        assert core.MODULES[name].kind == "domain"
