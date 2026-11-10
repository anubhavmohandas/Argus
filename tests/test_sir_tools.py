"""Offline self-checks for the sir's-tools/notes integration:
  - new provider-token patterns in the shared secret catalog (modules.scan_text)
  - expanded GitHub dork catalog (github_recon._DORKS)
  - JS-asset prioritisation harvested from JSHarvester (js_recon._score_js/_prioritize)
  - the aegisdroid-derived `apk` static-analysis module

No network — APK is synthesised in-process; dork scan uses injected fetchers.
"""
import struct
import zipfile

from argus import core
from argus.core import run_module, MODULES
from argus.modules import scan_text
from argus.github_recon import _DORKS, github_dork_scan
from argus.js_recon import _score_js, _prioritize

# realistic, non-placeholder provider tokens (structured prefixes; pass triage).
# Split so the source never holds a contiguous token — GitHub push protection.
SHOPIFY = "shpat_" + "a1b2c3d4e5f60718293a4b5c6d7e8f90"
NEWRELIC = "NRAK-" + "9F3KP2RM7WN4BV8LC3JH6TY1PDG"
GITLAB = "glpat-" + "aB3dEfGh1jKlMn0pQrSt"


# ── new secret patterns ─────────────────────────────────────────────────────
def test_new_provider_tokens_detected():
    def caught(blob):
        return {f.title.split(" (")[0] for f in scan_text(blob)}
    assert "SHOPIFY_TOKEN" in caught(f'token="{SHOPIFY}"')
    assert "NEW_RELIC" in caught(f"x-api-key: {NEWRELIC}")
    assert "GITLAB_PAT" in caught(f"GITLAB_TOKEN={GITLAB}")


def test_secret_catalog_still_catches_originals():
    # no regression: the pre-existing typed tokens still fire
    names = {f.title.split(" (")[0] for f in scan_text('k="ghp_' + "a1B2c3" * 6 + '"\naws=AKIAZ3XB7EXKJQ4NPFLW')}
    assert "GH_PAT_CLASSIC" in names and "AWS_ACCESS_KEY" in names


# ── GitHub dork catalog ─────────────────────────────────────────────────────
def test_dork_catalog_expanded():
    assert len(_DORKS) >= 40                       # was 8
    joined = " ".join(_DORKS)
    assert "shpat_ in:file" in _DORKS              # provider-key dork from sir's notes
    assert any("swagger" in d for d in _DORKS)     # api-surface dork
    assert "extension:env" in joined               # file-type dork (API-syntax translated)


def test_dork_scan_self_gates_and_redacts():
    def gh_get(url, token, timeout=15.0):
        return {"items": [{"html_url": "https://github.com/acme/repo/blob/main/.env",
                           "repository": {"full_name": "acme/repo"}, "path": ".env"}]}
    def raw_get(url, timeout=15.0):
        return 200, f"SHOPIFY_TOKEN={SHOPIFY}\n"
    hits = list(github_dork_scan("acme.io", "tok", gh_get=gh_get, raw_get=raw_get))
    assert len(hits) >= 1
    assert SHOPIFY not in hits[0].data["match_redacted"]   # proven, never re-leaked


def test_code_search_is_paced_to_rate_limit(monkeypatch):
    # 41 dorks vs GitHub's 10 req/min: un-paced, ~30 would 403 and be silently skipped
    import urllib.request
    from argus import github_recon
    slept = []
    monkeypatch.setattr(github_recon, "_last_search", 0.0)
    monkeypatch.setattr(github_recon.time, "sleep", slept.append)
    monkeypatch.setattr(urllib.request, "urlopen",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("offline")))
    github_recon._gh_get("https://api.github.com/search/code?q=x", "tok")
    github_recon._gh_get("https://api.github.com/search/code?q=y", "tok")
    assert slept and slept[-1] > 6.0               # second call waited out the interval


# ── JS asset prioritisation ─────────────────────────────────────────────────
def test_js_scoring_ranks_sourcemaps_and_secret_bundles_first():
    arch = "https://web.archive.org/web/1id_/https://cdn.x.io/"
    urls = [arch + "vendor.js", arch + "app.config.js", arch + "main.js.map", arch + "auth-token.js"]
    ranked = [u.split("id_/")[-1].rsplit("/", 1)[-1] for u in _prioritize(urls)]
    assert ranked[0] == "main.js.map"                      # sourcemap pinned highest
    assert ranked.index("app.config.js") < ranked.index("vendor.js")
    assert _score_js(arch + "x.js.map") == 1000


# ── apk module (aegisdroid static analysis) ─────────────────────────────────
def _axml(strings):
    """Minimal binary-XML (RES_STRING_POOL) blob carrying `strings`, UTF-8."""
    blobs, offsets = b"", []
    for s in strings:
        offsets.append(len(blobs))
        b = s.encode("utf-8")
        blobs += bytes([len(s)]) + bytes([len(b)]) + b + b"\x00"
    header_size = 28
    offarr = b"".join(struct.pack("<I", o) for o in offsets)
    strings_start = header_size + len(offarr)
    body = offarr + blobs
    return (struct.pack("<HHI", 0x0001, header_size, header_size + len(body))
            + struct.pack("<IIIII", len(strings), 0, 0x100, strings_start, 0) + body)


def _synthetic_apk(path):
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", _axml(["android.permission.SEND_SMS", "com.evil.app"]))
        zf.writestr("classes.dex", b"not-a-real-dex")
        zf.writestr("classes2.dex", b"filler")
        zf.writestr("classes3.dex", b"filler")
        zf.writestr("lib/armeabi-v7a/libnative.so", b"\x7fELF native blob")
        zf.writestr("assets/config.json",
                    '{"aws_access_key_id":"AKIAZ3XB7EXKJQ4NPFLW",'
                    '"api":"https://api.evil.app/api/v1/admin/users",'
                    '"gql":"https://api.evil.app/graphql",'
                    '"fb":"https://evil-default-rtdb.firebaseio.com/.json",'
                    '"loader":"DexClassLoader","packer":"bangcle"}')
    return str(path)


def test_apk_module_registered_and_passive():
    assert "apk" in MODULES and MODULES["apk"].kind == "path"


def test_apk_static_analysis(tmp_path):
    apk = _synthetic_apk(tmp_path / "evil.apk")
    findings = run_module("apk", apk)
    titles = " || ".join(f.title.lower() for f in findings)
    assert all(f.module == "apk" for f in findings)
    assert "send_sms" in titles                    # permission parsed from binary-XML manifest
    assert "dynamic dex loading" in titles         # DexClassLoader suspicious string (ATT&CK)
    assert "packer" in titles                       # bangcle protector marker
    assert "multiple dex" in titles                 # 3 .dex -> multidex
    assert "native code" in titles                  # lib/*.so
    assert "graphql" in titles and "firebase" in titles   # recon indicators
    assert any("aws_access_key" in str(f.data).lower() for f in findings)  # secret via shared catalog
    assert "apk recon complete" in titles           # summary


def test_apk_rejects_non_apk(tmp_path):
    p = tmp_path / "notes.txt"
    p.write_text("just text")
    findings = run_module("apk", str(p))
    assert len(findings) == 1 and findings[0].severity == core.INFO
