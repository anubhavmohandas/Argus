"""Live NVD provider: parse a real NVD response into observed['cves'] entries,
version-gated and reference-carrying, without ever touching the network.

The pure seam is parse_nvd(payload, product, version, port). The network wrapper
(_nvd_get) is deliberately thin and untested here — every honesty property lives
in the parser and in nvd_cves' guards, which is what this exercises.

    python3 test_nvd_provider.py
"""
from argus import providers
from argus.pivot import Graph, Entity

# A trimmed but real-shaped NVD cves/2.0 response: one CVE, CVSS v3.1, a
# CISA-KEV date, and an Exploit-tagged reference.
_PAYLOAD = {
    "vulnerabilities": [
        {"cve": {
            "id": "CVE-2019-10149",
            "cisaExploitAdd": "2021-11-03",
            "descriptions": [
                {"lang": "es", "value": "ignorado"},
                {"lang": "en", "value": "Exim 'Return of the WIZard' RCE."},
            ],
            "metrics": {"cvssMetricV31": [
                {"cvssData": {"baseSeverity": "CRITICAL", "baseScore": 9.8}}]},
            "references": [
                {"url": "https://vendor.example/advisory", "tags": ["Vendor Advisory"]},
                {"url": "https://www.exploit-db.com/exploits/46996", "tags": ["Exploit"]},
            ],
        }},
        {"cve": {"id": None}},  # malformed record -> skipped, never crashes
    ]
}


def test_parse_nvd_shape_severity_kev_and_refs():
    out = providers.parse_nvd(_PAYLOAD, "exim", "4.91", port=25)
    assert len(out) == 1, "the id-less record must be dropped, not counted"
    c = out[0]
    assert c["cve"] == "CVE-2019-10149"
    assert (c["product"], c["version"], c["port"]) == ("exim", "4.91", 25)
    assert c["severity"] == "critical" and c["cvss"] == 9.8
    assert c["known_exploited"] is True, "cisaExploitAdd -> KEV"
    assert c["public_exploit"] is True, "an Exploit-tagged ref -> public exploit"
    assert c["summary"] == "Exim 'Return of the WIZard' RCE."  # English, never Spanish
    # references present, and the Exploit-tagged one ranks ahead of the advisory
    assert c["references"][0] == "https://www.exploit-db.com/exploits/46996"


def test_parse_nvd_empty_is_silence():
    assert providers.parse_nvd({}, "exim", "4.91") == []
    assert providers.parse_nvd({"vulnerabilities": []}, "exim", "4.91") == []


def test_nvd_lookup_is_gated_before_it_ever_hits_the_network():
    # unknown product / unparseable version must short-circuit to [] — the guard
    # is what stops a bad (product, version) from becoming a live query or a guess.
    assert providers.nvd_cves("not-a-product", "1.0") == []
    assert providers.nvd_cves("exim", "") == []
    assert providers.nvd_cves("exim", None) == []


def test_version_pairs_reads_both_scan_and_http_sources():
    e = Entity("subdomain", "host.example.com", 1,
               evidence={"technology": "jenkins"})
    e.observed["version"] = "2.401.3"
    e.observed["services"] = [
        {"port": 22, "product": "openssh", "version": "7.4"},
        {"port": 8080, "product": None, "version": None},  # no product -> skipped
    ]
    pairs = providers._version_pairs(e)
    assert ("openssh", "7.4", 22) in pairs
    assert ("jenkins", "2.401.3", None) in pairs
    assert len(pairs) == 2


def test_enrich_nvd_merges_without_dropping_catalog_hits(monkeypatch=None):
    # enrich_nvd must ADD live CVEs to whatever's already in observed['cves']
    # (e.g. a static-catalog hit from the port scan), not overwrite them.
    g = Graph()
    e = Entity("subdomain", "host.example.com", 1,
               evidence={"technology": "exim"})
    e.observed["version"] = "4.91"
    e.observed["cves"] = [{"cve": "CVE-OLD-0001", "port": None, "product": "exim",
                           "version": "4.91"}]
    g.add(e)
    # stub the network: parse the canned payload instead of calling NVD, then
    # restore so the stub can't leak into another test (order-independent).
    real = providers.nvd_cves
    providers.nvd_cves = lambda p, v, port=None, timeout=20.0: (
        providers.parse_nvd(_PAYLOAD, p, v, port))
    try:
        hosts = providers.enrich_nvd(g)
    finally:
        providers.nvd_cves = real
    assert hosts == 1
    ids = {c["cve"] for c in e.observed["cves"]}
    assert ids == {"CVE-OLD-0001", "CVE-2019-10149"}, "live hit added, old one kept"
    assert e.evidence["known_vulnerable_service"] is True


if __name__ == "__main__":
    import sys
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
    sys.exit(0)
