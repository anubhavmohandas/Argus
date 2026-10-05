"""Research planner — the one path active pivot/program work takes to a target.

The split this file enforces (the spec's "two-worlds" close):

    PASSIVE DISCOVERY   public DNS / CT / RDAP / archives / urlscan
                        -> pivot.pivot(), direct, lightweight, campaign-free

    ACTIVE INTERACTION  HTTP / TLS / CORS / path / injection / port probes
                        -> a bounded Task per (host, technique)
                        -> Orchestrator.propose -> can_test (FIRST lock)
                        -> worker -> provider enricher (_gate, SECOND lock)
                        -> Observation (durable) + graph projection (the index)

The security boundary is one question: does this capability connect to the
target? If yes it is a Task under orchestrator authorization — never a direct
provider call. `providers._gate` stays as defence-in-depth; the orchestrator is
the first lock, so a program that FORBIDS a technique parks/denies the task and
the provider is never reached.

occam: one Task per (host, technique) — a meaningful bounded unit, not one per
internal call. The worker REUSES the existing per-host `providers.enrich_*`
functions (run on a one-node graph) so the probe + merge logic is not
re-implemented; the enricher writes evidence straight into the live graph node
(that IS the projection) and the worker snapshots the delta as the Observation.
"""
from __future__ import annotations

from importlib import import_module

from . import campaign as campaign_mod, providers
from .orchestrator import Orchestrator, Task

# argus/__init__ re-exports a `pivot` function, which shadows the `pivot` SUBMODULE on
# the package — attribute access (and `import ... as`) would hand back the function, so
# fetch the module object straight from the import system for its Graph/Entity classes.
pivot_mod = import_module("argus.pivot")

TIERS = ("probe", "paths", "scan")

# (provider enricher name, authorizing technique, tier). The technique is the one
# `can_test` decides on AND the one the enricher's own internal `_gate` uses, so the
# two locks always agree. Grouping several enrichers under one technique is deliberate:
# they share a risk class, so one authorization covers the bounded bundle.
_UNITS: tuple[tuple[str, str, str], ...] = (
    ("enrich",              "http_probe",      "probe"),   # HTTP map: status/headers/version/takeover
    ("enrich_security_txt", "http_probe",      "probe"),   # disclosure contact (one GET/host)
    ("enrich_tls",          "tls_probe",       "probe"),   # TLS inspection: cert fingerprint
    ("enrich_cors",         "cors_probe",      "probe"),   # one credentialed-origin CORS probe
    ("enrich_admin",        "path_probe",      "paths"),   # admin-surface discovery
    ("enrich_exposure",     "path_probe",      "paths"),   # .git/.env sensitive-file probe
    ("enrich_traversal",    "path_probe",      "paths"),   # directory-traversal probe
    ("enrich_graphql",      "http_probe",      "paths"),   # introspection probe
    ("enrich_redirect",     "http_probe",      "paths"),   # open-redirect canary
    ("enrich_injection",    "injection_probe", "paths"),   # reflected xss / ssti canary
    ("enrich_scan",         "port_scan",       "scan"),    # TCP-connect port + service scan
)

# Passive analysis / public-record enrichers — they interact with NO target (local
# catalog, graph-internal comparison, DMARC over a public resolver, NVD's public API),
# so they run directly on the graph, exactly as passive discovery does. `needs_cve`
# gates the live NVD lookup behind the operator's --cve, matching the legacy flow.
_ANALYSIS: tuple[tuple[str, bool], ...] = (
    ("enrich_kev", False),             # observed version -> known-exploited (no network)
    ("analyze_certificates", False),   # shared cert fingerprint across graph (no network)
    ("enrich_email_spoof", False),     # DMARC over DoH (public resolver)
    ("enrich_nvd", True),              # live NVD CVE lookup (public API)
)


def tiers_for(probe: bool, probe_paths: bool, scan: bool) -> set[str]:
    """CLI flags -> the active tiers to plan. `--probe-paths` implies `--probe`
    (it adds to the base probe tier, exactly as the legacy run did); `--scan` is
    independent (loudest tier, may run alone)."""
    t: set[str] = set()
    if probe or probe_paths:
        t.add("probe")
    if probe_paths:
        t.add("paths")
    if scan:
        t.add("scan")
    return t


def _bundles(tiers: set[str]) -> dict[str, list[str]]:
    """technique -> the enricher names to run for it, across the enabled tiers.
    Deterministic order (source order of _UNITS) so a task's plan is reproducible."""
    out: dict[str, list[str]] = {}
    for name, tech, tier in _UNITS:
        if tier in tiers:
            out.setdefault(tech, []).append(name)
    return out


def _make_worker(graph):
    """A worker closed over the live discovery graph. Looks up the task's host node,
    runs the technique's enrichers on a one-node graph (reusing the providers' probe +
    merge), and returns the evidence/observed DELTA as the durable Observation. The
    enricher mutates the live node in place — that is the graph projection; the
    Observation is the independent evidence of record."""
    def worker(task: Task, campaign):
        spec = task.spec or {}
        names = spec.get("enrichers", [])
        etype = spec.get("etype", "domain")
        key = f"{etype}:{task.host.lower()}"
        node = graph.nodes.get(key)
        if node is None:
            # no live graph node (e.g. a restart recovered this task without the
            # planner's in-memory graph): probe a throwaway node so the Observation
            # — the evidence of record — is still captured; projection is best-effort.
            node = pivot_mod.Entity(etype, task.host, depth=0)
        before_ev, before_obs = dict(node.evidence), dict(node.observed)
        g1 = pivot_mod.Graph()
        g1.nodes[node.key] = node
        for name in names:
            fn = getattr(providers, name)
            fn(g1, ports=spec.get("ports")) if name == "enrich_scan" else fn(g1)
        ev_delta = {k: v for k, v in node.evidence.items() if before_ev.get(k) != v}
        obs_delta = {k: v for k, v in node.observed.items() if before_obs.get(k) != v}
        obs = {"request": {"method": "", "url": f"https://{task.host}/", "headers": {}, "body": ""},
               "response": {"evidence": ev_delta, "observed": obs_delta}}
        return obs, ""    # ARGUS collects; classification (reasoning) is NYX's job
    return worker


def run_active(campaign, graph, *, tiers: set[str], ports=None, cve: bool = False,
               orch: Orchestrator | None = None) -> Orchestrator:
    """Route the graph's active enrichment through the orchestrator. Builds one bounded
    Task per (probeable host, technique), proposes each (can_test parks/denies out-of-
    scope or forbidden ones — their worker never runs), drains the ready queue, then runs
    the passive analysis enrichers directly on the graph. Returns the Orchestrator so the
    caller can read the durable task table / progress.

    Pass `orch` to reuse ONE orchestrator across several graphs (the `program` command,
    so rate + request budget are shared across every host, not reset per host)."""
    orch = orch or Orchestrator(campaign)
    worker = _make_worker(graph)
    bundles = _bundles(tiers)
    for tech in bundles:
        orch.register_worker(tech, worker)
    probeable = [e for e in graph.nodes.values() if e.type in providers._PROBEABLE]
    for ent in probeable:
        for tech, names in bundles.items():
            orch.propose(Task(
                campaign_id=campaign.id, technique=tech, host=ent.value,
                hypothesis=f"active {tech} of {ent.value}",
                spec={"enrichers": names, "etype": ent.type,
                      "ports": ports if tech == "port_scan" else None}))
    orch.run()
    for name, needs_cve in _ANALYSIS:
        if needs_cve and not cve:
            continue
        getattr(providers, name)(graph)
    return orch


def ephemeral_campaign(seed: str, scope=None, *, rate=None, max_requests=None) -> "campaign_mod.Campaign":
    """A seed-scoped engagement context for Quick Pivot — so active work that has no
    program/policy still passes through the orchestrator instead of running fail-OPEN.
    A bare domain/IP seed scopes to itself (apex + subdomains, standard bounty
    semantics); a supplied Scope is rendered into the same program grammar. Active
    execution against anything outside this scope fails closed, as can_test requires."""
    if scope is not None:
        lines = list(scope.include_patterns()) or [seed]
        text = "In scope:\n" + "\n".join(lines)
        ex = scope.exclude_patterns()
        if ex:
            text += "\nOut of scope:\n" + "\n".join(ex)
    else:
        text = f"In scope:\n{seed}\n"
    c = campaign_mod.create(text + "\n", name=seed)
    if rate is not None:
        c.policy.rate_per_sec = rate
    if max_requests is not None:
        c.policy.max_requests = max_requests
    return c


def demo() -> None:
    """Self-check (offline, stubbed providers): active pivot work becomes durable Tasks
    under can_test — an in-scope probe runs its enricher and projects into the graph; an
    out-of-scope host is DENIED and its enricher is NEVER called; a program-forbidden
    technique is DENIED too. Proves the invariant: no target-active capability executes
    without passing orchestrator authorization first."""
    import os
    import tempfile

    calls: list[tuple[str, str]] = []

    def fake_probe(name):
        def enr(g, **kw):
            for e in g.nodes.values():
                calls.append((name, e.value))
                e.evidence["internet_facing"] = True
            return len(g.nodes)
        return enr

    saved = {n: getattr(providers, n) for n, _, _ in _UNITS}
    for n, _, _ in _UNITS:
        setattr(providers, n, fake_probe(n))
    # silence the real passive-analysis network calls for the self-check
    saved_analysis = {n: getattr(providers, n) for n, _ in _ANALYSIS}
    for n, _ in _ANALYSIS:
        setattr(providers, n, lambda g, **kw: 0)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["ARGUS_HOME"] = tmp
            c = campaign_mod.create(
                "In scope:\napi.acme.example\nForbidden:\nNo automated scanning\n", name="acme")
            g = pivot_mod.Graph()
            g.add(pivot_mod.Entity("domain", "api.acme.example", 0))   # in scope
            g.add(pivot_mod.Entity("ip", "198.51.100.9", 1))           # NOT in scope

            orch = run_active(c, g, tiers={"probe", "paths", "scan"})
            tasks = list(orch.tasks.values())

            def by(h, t):
                return next(x for x in tasks if x.host == h and x.technique == t)

            # in-scope low-risk probe ran and projected into the graph node
            assert by("api.acme.example", "http_probe").state == "EVALUATED"
            assert g.nodes["domain:api.acme.example"].evidence.get("internet_facing") is True
            # program forbids automated scanning -> these are DENIED, enricher never called
            assert by("api.acme.example", "port_scan").state == "DENIED"
            assert by("api.acme.example", "path_probe").state == "DENIED"
            assert not any(n == "enrich_scan" for n, _ in calls)
            assert not any(n in ("enrich_admin", "enrich_exposure", "enrich_traversal")
                           for n, _ in calls)
            # out-of-scope host: every technique DENIED, nothing touched it
            assert all(by("198.51.100.9", t).state == "DENIED"
                       for t in ("http_probe", "tls_probe", "cors_probe"))
            assert not any(v == "198.51.100.9" for _, v in calls)
            # durable: the tasks are on disk, not just in memory
            assert len(c.tasks()) == len(tasks)
        del os.environ["ARGUS_HOME"]
    finally:
        for n, fn in saved.items():
            setattr(providers, n, fn)
        for n, fn in saved_analysis.items():
            setattr(providers, n, fn)
    print("research demo passed")


if __name__ == "__main__":
    demo()
