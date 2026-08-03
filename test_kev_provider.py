"""Version-gated KEV provider: honest exploit evidence, no engine change.

The provider asserts `known_exploited` / `public_exploit` ONLY when a running
version is at or below a known-exploited one. A patched or unknown version earns
no claim — the inverse-overclaim guard (a Jenkins host is not "exploitable" just
because the product family appears in KEV). The provider states facts; turning
them into priority stays the rule engine's job.

    python3 test_kev_provider.py
"""
from argus import engine, providers
from argus.pivot import Graph, Entity


def test_version_captured_but_not_as_a_predicate():
    # Jenkins volunteers its version in X-Jenkins. It is an observation, so it
    # must NOT leak into the evidence dict (that stays engine-vocabulary only).
    assert providers.version_from({"x-jenkins": "2.401.3"}) == "2.401.3"
    assert providers.version_from({"server": "nginx"}) is None
    ev = providers.evidence_from(200, {"x-jenkins": "2.401.3"}, "")
    assert "version" not in ev, "version is an observation, never a predicate"
    assert set(ev) <= set(engine._PREDICATES)


def test_kev_is_version_gated():
    # vulnerable version -> the exploit facts are asserted
    assert providers.kev_evidence("jenkins", "2.401.3") == {
        "known_exploited": True, "public_exploit": True}
    # patched version -> nothing (the whole point: not every Jenkins is flagged)
    assert providers.kev_evidence("jenkins", "2.999") == {}
    # unknown/absent version -> nothing (silence, never a guess)
    assert providers.kev_evidence("jenkins", None) == {}
    assert providers.kev_evidence("jenkins", "") == {}
    # a product not in the catalog -> nothing
    assert providers.kev_evidence("nginx", "1.0") == {}


def test_kev_lifts_confidence_through_the_unchanged_engine():
    def confidence(version):
        g = Graph()
        e = Entity("subdomain", "ci.example.com", 1,
                   evidence={"technology": "jenkins", "internet_facing": True})
        e.observed["version"] = version        # what the probe saw, non-predicate
        g.add(e)
        providers.enrich_kev(g)                # intel lands in evidence
        conf = {c.rule: c for c in engine.investigate(g).conclusions}
        return conf["jenkins_confirmed"]

    vuln = confidence("2.401.3")
    patched = confidence("2.999")
    assert vuln.confidence > patched.confidence, (vuln.confidence, patched.confidence)
    # traceable: the boost is attributed to real, named evidence — not magic
    assert any(chk.get("predicate") == "known_exploited" and chk.get("applied")
               for chk in vuln.ledger["evidence"])


def test_enrich_kev_writes_only_evidence():
    # a provider fills facts; it never invents graph shape
    g = Graph()
    e = Entity("subdomain", "ci.example.com", 1, evidence={"technology": "jenkins"})
    e.observed["version"] = "2.401.3"
    g.add(e)
    shape = (len(g.nodes), len(g.edges), len(g.findings))
    providers.enrich_kev(g)
    assert (len(g.nodes), len(g.edges), len(g.findings)) == shape
    assert e.evidence["known_exploited"] is True


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  PASS {name}")
    print("all KEV provider checks passed")
