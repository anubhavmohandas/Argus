"""Port-scan + service-version CVE provider: honest observation, no engine change.

The scan RECORDS open ports and the (product, version) a banner volunteers, and
matches those versions against a local CVE catalog — version-gated, never a
guess. It owns exactly one predicate, `known_vulnerable_service`; the specific
CVEs ride in observed['cves'] for the report. The pure pieces (port/banner
parsing, version-gated matching, the SSRF guard) run with no network.

    python3 test_port_scan.py
"""
from argus import engine, providers
from argus.pivot import Graph, Entity


def test_parse_ports_is_a_validating_trust_boundary():
    assert providers.parse_ports("22,80,443") == [22, 80, 443]
    assert providers.parse_ports("80,80,79-81") == [79, 80, 81]        # dedup + range
    assert providers.parse_ports("1-3") == [1, 2, 3]
    for bad in ("0", "70000", "100-50", "80-99999", "abc", "22,x"):
        try:
            providers.parse_ports(bad)
            assert False, f"{bad!r} should have been rejected"
        except ValueError:
            pass


def test_parse_banner_pulls_product_and_version():
    assert providers.parse_banner("SSH-2.0-OpenSSH_7.4") == ("openssh", "7.4")
    assert providers.parse_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu") == ("openssh", "8.9")  # 'p1' dropped for compare
    assert providers.parse_banner("220 (vsFTPd 2.3.4)") == ("vsftpd", "2.3.4")
    assert providers.parse_banner("220 ProFTPD 1.3.5 Server") == ("proftpd", "1.3.5")
    # unknown product, or no version, or empty -> no claim
    assert providers.parse_banner("220 mystery service ready") == (None, None)
    assert providers.parse_banner("SSH-2.0-OpenSSH") == ("openssh", None)
    assert providers.parse_banner("") == (None, None)


def test_cve_match_is_version_gated_and_deterministic():
    # a vulnerable version -> the catalog entry, with its CVE id + report metadata
    hits = providers.cve_matches("vsftpd", "2.3.4")
    assert [h["cve"] for h in hits] == ["CVE-2011-2523"]
    assert hits[0]["severity"] == "critical" and hits[0]["known_exploited"] is True
    # patched / unknown / absent version -> nothing (the whole point: not a guess)
    assert providers.cve_matches("vsftpd", "3.0.5") == []
    assert providers.cve_matches("vsftpd", None) == []
    assert providers.cve_matches("openssh", "") == []
    # a product not in the catalog -> nothing
    assert providers.cve_matches("nginx", "1.0.0") == []
    # OpenSSH below the gate matches; comparison survives the dropped 'p1'
    assert providers.cve_matches("openssh", "7.4")[0]["cve"] == "CVE-2018-15473"
    assert providers.cve_matches("openssh", "9.6") == []


def test_probe_port_distinguishes_open_from_closed():
    # the state mapping is real socket logic — one runnable check, localhost only
    # (no external egress), deterministic on macOS/Linux.
    import socket as _s
    srv = _s.socket()
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.listen(1)
    try:
        state, banner = providers._probe_port("127.0.0.1", port, 0.5)
        assert state == "open" and banner == "", (state, banner)  # accepted, said nothing
    finally:
        srv.close()
    # nothing listening now -> the OS refuses the connection -> closed (not filtered)
    state, banner = providers._probe_port("127.0.0.1", port, 0.5)
    assert state == "closed" and banner == "", (state, banner)


def test_scan_never_touches_a_non_global_target():
    # the SSRF guard every probe shares: inward names are never connected to,
    # and the function returns offline without a socket.
    for inward in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "localhost"):
        assert providers.scan_host(inward, ports=[22, 80]) == {}, inward
    assert providers.scan_host("8.8.8.8", ports=[]) == {}, "no ports => no scan"


def test_only_owns_its_one_predicate():
    # a provider may only assert engine vocabulary, and the scan claims exactly one
    assert providers.PROVIDES["port_scan"] == ("known_vulnerable_service",)
    assert set(providers.PROVIDES["port_scan"]) <= set(engine._PREDICATES)


def test_cve_evidence_fires_the_rule_through_the_unchanged_engine():
    # mirror the KEV test: inject what a scan would have observed, then prove the
    # shipped rule concludes a risk from it — no engine or rule edit required.
    g = Graph()
    e = Entity("subdomain", "ftp.example.com", 1)
    e.evidence["known_vulnerable_service"] = True          # what enrich_scan sets
    e.observed["cves"] = [{"port": 21, "product": "vsftpd", "version": "2.3.4",
                           "cve": "CVE-2011-2523", "severity": "critical",
                           "known_exploited": True, "public_exploit": True}]
    g.add(e)
    conf = {c.rule: c for c in engine.investigate(g).conclusions}
    assert "vulnerable_service" in conf, "known_vulnerable_service must fire the rule"
    c = conf["vulnerable_service"]
    assert c.severity == "high" and c.confidence == 65
    # traceable: the conclusion attributes itself to the named predicate (I-2)
    assert any(chk.get("predicate") == "known_vulnerable_service" and chk.get("met")
               for chk in c.ledger["evidence"])


def test_enrich_scan_writes_only_observed_and_evidence(monkeypatch=None):
    # a provider fills facts; it never invents graph shape. scan_host is stubbed
    # so this stays offline and deterministic.
    g = Graph()
    g.add(Entity("subdomain", "ftp.example.com", 1))
    g.add(Entity("username", "someone", 1))               # not probeable — skipped
    shape = (len(g.nodes), len(g.edges), len(g.findings))
    real = providers.scan_host
    providers.scan_host = lambda host, ports=None, timeout=4.0: (
        {"open_ports": [21], "services": [{"port": 21, "product": "vsftpd", "version": "2.3.4"}],
         "cves": [{"port": 21, "product": "vsftpd", "version": "2.3.4",
                   "cve": "CVE-2011-2523", "severity": "critical"}]}
        if host == "ftp.example.com" else {})
    try:
        assert providers.enrich_scan(g) == 1, "one host had a catalog CVE"
    finally:
        providers.scan_host = real
    assert (len(g.nodes), len(g.edges), len(g.findings)) == shape, "no nodes/edges/findings added"
    assert g.nodes["subdomain:ftp.example.com"].evidence["known_vulnerable_service"] is True
    assert g.nodes["subdomain:ftp.example.com"].observed["cves"][0]["cve"] == "CVE-2011-2523"
    assert g.nodes["username:someone"].evidence == {}, "non-probeable host left untouched"


def test_tcp_connect_obeys_the_request_budget():
    # A TCP connect is outbound engagement, so it honours the same politeness
    # budget as HTTP. Offline: budget 0 => _probe_port returns before it ever
    # opens a socket, and 'skipped' stays distinct from closed/filtered (I-1).
    try:
        providers.set_rate(max_requests=0)                 # budget exhausted
        state, banner = providers._probe_port("example.com", 80, timeout=0.01)
        assert (state, banner) == ("skipped", ""), (state, banner)
    finally:
        providers.set_rate()                               # clear: unlimited again
    # and unlimited (the default) leaves the gate open — no skip
    assert providers._throttle.acquire() is True


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  PASS {name}")
    print("all port-scan provider checks passed")
