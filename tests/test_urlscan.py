"""Offline self-checks for the urlscan module's parser. No network.

    python3 tests/test_urlscan.py    # asserts, exits 0 on pass
"""
from argus.modules import _parse_urlscan
from argus.pivot import _extract
from argus.core import Finding, LOW

# Synthetic urlscan.io /search response — example.* only, never a real target.
_SAMPLE = {
    "total": 3,
    "results": [
        {"_id": "aaaa", "page": {"domain": "www.example.com", "ip": "93.184.216.34",
                                 "url": "https://www.example.com/", "server": "ECS",
                                 "asnname": "EXAMPLE-AS"}},
        {"_id": "bbbb", "page": {"domain": "shop.example.com", "ip": "93.184.216.35",
                                 "url": "https://shop.example.com/"},
         "screenshot": "https://urlscan.io/screenshots/bbbb.png"},
        # unrelated host must be dropped from the subdomain set but its IP kept
        {"_id": "cccc", "page": {"domain": "evil.notexample.org", "ip": "10.0.0.1",
                                 "url": "http://evil.notexample.org/"}},
    ],
}


def test_parse_extracts_hosts_ips_screenshots():
    p = _parse_urlscan(_SAMPLE, "example.com")
    assert p["total"] == 3
    # only hosts under the seed domain are kept as subdomains
    assert p["subdomains"] == ["shop.example.com", "www.example.com"]
    # every IP seen is kept (including the off-domain one — it is still intel)
    assert p["ips"] == ["10.0.0.1", "93.184.216.34", "93.184.216.35"]
    # screenshot URL is taken as-given, or synthesized from the result id
    shots = {pg["domain"]: pg["screenshot"] for pg in p["pages"]}
    assert shots["www.example.com"] == "https://urlscan.io/screenshots/aaaa.png"
    assert shots["shop.example.com"] == "https://urlscan.io/screenshots/bbbb.png"


def test_parse_empty_is_safe():
    for empty in (None, {}, {"results": None}):
        p = _parse_urlscan(empty, "example.com")
        assert p == {"subdomains": [], "ips": [], "pages": [], "total": 0}


def test_graph_extraction_feeds_subdomains():
    # a urlscan Finding must yield new subdomain entities into the pivot graph
    p = _parse_urlscan(_SAMPLE, "example.com")
    f = Finding("urlscan", "example.com", "x", LOW, data=p)
    children = _extract(f)
    assert ("subdomain", "www.example.com", "subdomain_of") in children
    assert ("subdomain", "shop.example.com", "subdomain_of") in children


if __name__ == "__main__":
    test_parse_extracts_hosts_ips_screenshots()
    test_parse_empty_is_safe()
    test_graph_extraction_feeds_subdomains()
    print("ok")
