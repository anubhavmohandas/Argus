"""Provider manifest + coverage map: self-documenting, and it can't drift.

Providers declare the predicates they establish next to their own code; the
coverage map is derived from that manifest and the engine's live vocabulary.
So "which predicates still have no evidence source" is answered by the code,
not a hand-maintained table.

    python3 test_coverage.py
"""
from argus import engine, providers


def test_manifest_declares_http_probe():
    assert providers.PROVIDES["http_probe"] == (
        "internet_facing", "technology", "authentication_required",
        "security_headers_missing", "insecure_cookie")


def test_coverage_maps_every_predicate_once():
    cov = providers.coverage()
    assert set(cov) == set(engine._PREDICATES), "coverage must span exactly the vocabulary"
    # what the HTTP probe fills
    assert cov["technology"] == "http_probe"
    assert cov["internet_facing"] == "http_probe"
    assert cov["authentication_required"] == "http_probe"
    # what discovery establishes from the name/graph
    assert cov["publicly_discoverable"] == "discovery"
    assert cov["name_suggests_admin"] == "discovery"
    # the version-gated KEV provider fills these
    assert cov["public_exploit"] == "kev"
    assert cov["known_exploited"] == "kev"
    # the certificate analyzer (Analysis-class provider) fills this
    assert cov["certificate_reused"] == "cert_analysis"
    # the path-based probe fills the last gap
    assert cov["has_admin_interface"] == "admin_probe"
    # the TCP port scan establishes the service-version CVE predicate
    assert cov["known_vulnerable_service"] == "port_scan"
    # web-exposure predicates: two come free from the base HTTP probe, one from
    # the path-based exposure probe (owasp_scanner patterns as evidence)
    assert cov["security_headers_missing"] == "http_probe"
    assert cov["insecure_cookie"] == "http_probe"
    assert cov["exposed_sensitive_file"] == "exposure_probe"
    # the path-traversal probe (another active path probe on the --probe-paths tier)
    assert cov["path_traversal"] == "traversal_probe"
    assert all(cov.values()), f"uncovered: {[p for p, v in cov.items() if not v]}"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  PASS {name}")
    print("all coverage checks passed")
