"""The golden end-to-end tests — the directive's acceptance gate.

These drive the WHOLE research loop against the local fixture app (tests/fixture_app.py),
with no lifecycle shortcuts and no direct worker invocation around the Orchestrator:

    program + scope  ->  identities + sessions  ->  captured authenticated traffic
    ->  endpoint + resource candidate  ->  confirmed ownership  ->  coverage gap
    ->  priority  ->  ExperimentProposal  ->  policy gate (queue)
    ->  Orchestrator executes against the fixture  ->  Observation
    ->  finding promotion  ->  reproduction  ->  scope/boundary/impact/dedupe
    ->  report-ready  ->  markdown export

The ONLY thing swapped for the local fixture is the differential's leaf transport: a fetch
that connects to 127.0.0.1:<port> instead of the internet. Everything above it is the real
code path — the policy gate (can_test) still runs on every request, the Orchestrator still
owns execution, and the finding lifecycle is still fully earned.

The application under test is identified as the real domain `fixture.local` (in scope); the
injected fetch resolves that to the local server, exactly as DNS would resolve a program host
to an IP. This keeps the SSRF/global-routable production backstop untouched and unweakened.
"""
from __future__ import annotations

import json
import os
import tempfile
import urllib.error
import urllib.request
from urllib.parse import urlsplit

import fixture_app

from argus import (
    campaign as campaign_mod,
    coverage,
    differential,
    finding,
    identity as identity_mod,
    orchestrator as orchestrator_mod,
    planner,
    priority,
    proposal,
    report,
    reproduce,
    resource as resource_mod,
    session as session_mod,
    traffic,
)

_DIFF_TECHNIQUES = ("differential_cross_account", "differential_anonymous",
                    "differential_same_account")

HOST = "fixture.local"
PROGRAM = f"Assets:\n{HOST}\nRate: 20 requests/sec\n"


def _make_fetch(port: int):
    """The injected leaf transport: send the request to the local fixture. The URL's host
    (`fixture.local`) is ignored for routing — only the path/method/headers/body matter —
    so the real token rides over the wire to the fixture while stored evidence stays redacted."""
    def fetch(method, url, headers, body):
        path = urlsplit(url).path
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}{path}",
            data=(body.encode() if body else None), method=method, headers=dict(headers))
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, dict(r.headers), r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read().decode()
    return fetch


def _diff_worker(fetch):
    """A differential worker identical to the orchestrator's own, except the leaf transport is
    the local-fixture fetch. Registered with the Orchestrator and invoked BY it (not around
    it); each outbound request is still independently re-gated inside differential.run."""
    def worker(task, c):
        spec = task.spec or {}
        base = orchestrator_mod._variant_from_spec(c, spec["baseline"])
        mut = orchestrator_mod._variant_from_spec(c, spec["mutation"])
        r = differential.run(c, task.technique, task.host, base, mut,
                             hypothesis=task.hypothesis, intensity=task.intensity, fetch=fetch)
        return None, r.classification, r.experiment_id
    return worker


def _variants(c, path):
    a, b = identity_mod.get(c, "user_a"), identity_mod.get(c, "user_b")
    base = differential.Variant(a, method="GET", path=path, resource="1", owner=a)
    mut = differential.Variant(b, method="GET", path=path, resource="1", owner=a)
    return base, mut


def _setup_identities_and_traffic(c, route, rtype):
    """Register two researcher-owned identities with sessions, then capture the OWNER's
    authenticated request against `route` so the endpoint + resource candidate + the
    owner->non-owner gap all derive from real observed traffic."""
    os.environ["FIX_A_TOK"], os.environ["FIX_B_TOK"] = "tok-a", "tok-b"
    a = identity_mod.Identity(name="user_a", role="customer", tenant="t1",
                              researcher_owned=True, credential_ref="FIX_A_TOK")
    b = identity_mod.Identity(name="user_b", role="customer", tenant="t1",
                              researcher_owned=True, credential_ref="FIX_B_TOK")
    identity_mod.register(c, a)
    identity_mod.register(c, b)
    sess = session_mod.register(c, session_mod.Session(
        identity="user_a", base_origin=f"https://{HOST}", auth_mechanism="bearer",
        credential_ref="FIX_A_TOK"))
    traffic.capture(c, method="GET", url=f"https://{HOST}{route}/1",
                    headers={"Authorization": "Bearer tok-a"}, identity="user_a",
                    session_id=sess.id, response={"status": 200, "content_type": "application/json"})
    resource_mod.assert_ownership(c, resource_mod.Ownership(
        resource_type=rtype, resource_value="1", owner_identity="user_a", tenant="t1",
        researcher_controlled=True))


def _top_owner_gap(c):
    gaps = [g for g in coverage.build(c)["gaps"]
            if g["gap_type"] == "OWNER_NONOWNER_UNTESTED"]
    assert gaps, "the untested owner->non-owner boundary should have been derived"
    ranked = priority.rank(c)
    top = next(g for g in ranked if g["gap_type"] == "OWNER_NONOWNER_UNTESTED")
    return top


def test_golden_vulnerable_path():
    """PROGRAM -> ... -> REPORT READY -> MARKDOWN, and no secret ever leaks into evidence."""
    with fixture_app.running_app() as port, tempfile.TemporaryDirectory() as tmp:
        os.environ["ARGUS_HOME"] = tmp
        try:
            fetch = _make_fetch(port)
            c = campaign_mod.create(PROGRAM, name="Fixture-Vuln")
            _setup_identities_and_traffic(c, "/api/orders", "order")

            top = _top_owner_gap(c)
            prop = proposal.build(c, top)
            assert prop["technique"] == "differential_cross_account"
            assert prop["path"] == "/api/orders/1"

            # gate + persist through the REAL queue path, then run through a REAL Orchestrator
            q = proposal.queue(c, top["gap_id"])
            assert q["verdict"].startswith("ALLOW"), q
            orch = orchestrator_mod.Orchestrator(c)
            orch.register_worker("differential_cross_account", _diff_worker(fetch))
            orch.run()
            proposal.reconcile(c)

            # the vulnerable route => a suspicious experiment => one promoted finding
            assert any(e["classification"] == "suspicious" for e in c.experiments())
            fs = finding.findings(c)
            assert len(fs) == 1 and fs[0]["state"] == "OBSERVED"
            fid = fs[0]["id"]

            # reproduce for real (localhost), then let the earned ladder run itself
            base, mut = _variants(c, "/api/orders/1")
            rep = reproduce.verify(c, "differential_cross_account", HOST, base, mut,
                                   trials=2, fetch=fetch, finding_id=fid)
            assert rep.reproduced
            assert finding._get(c, fid).state == "REPRODUCIBLE"

            f_final, stopped = finding.validate(c, fid)
            assert f_final.state == "REPORT_READY", f"stopped at: {stopped!r}"
            assert [d["id"] for d in finding.report_ready(c)] == [fid]

            # bounty-ready report + markdown export, critic does not BLOCK
            rep_obj = report.generate(c, fid)
            md = report.render(rep_obj)
            verdict, issues = report.critique(rep_obj)
            assert verdict != "BLOCK", issues
            assert report.queue(c)              # the Reports workspace sees it
            assert "/api/orders/1" in md and "127.0.0.1" not in md

            # SECRET SAFETY: no token/credential anywhere in the durable or exported evidence
            blob = "\n".join([
                md, json.dumps(finding.findings(c)), json.dumps(c.experiments()),
                json.dumps(c.observations()), json.dumps(c.audit_trail()),
            ])
            for secret in ("tok-a", "tok-b", "Bearer tok", "FIX_A_TOK=tok"):
                assert secret not in blob, f"secret leaked: {secret!r}"
        finally:
            for k in ("ARGUS_HOME", "FIX_A_TOK", "FIX_B_TOK"):
                os.environ.pop(k, None)


def test_golden_autonomous_loop():
    """The bounded autonomous loop drives the planner's decisions through ONE orchestrator,
    cycle after cycle, against the fixture: the vulnerable boundary becomes a finding, the
    secure one resolves with no finding, and the loop stops honestly once no safe worthwhile
    gap remains — all gates and ownership rules intact, no worker invocation around the orch."""
    with fixture_app.running_app() as port, tempfile.TemporaryDirectory() as tmp:
        os.environ["ARGUS_HOME"] = tmp
        try:
            fetch = _make_fetch(port)
            c = campaign_mod.create(PROGRAM, name="Fixture-Auto")
            os.environ["FIX_A_TOK"], os.environ["FIX_B_TOK"] = "tok-a", "tok-b"
            for name, cred in (("user_a", "FIX_A_TOK"), ("user_b", "FIX_B_TOK")):
                identity_mod.register(c, identity_mod.Identity(
                    name=name, role="customer", tenant="t1", researcher_owned=True,
                    credential_ref=cred))
            # owner traffic on BOTH routes -> two researcher-controlled objects -> real gaps
            for route, rtype in (("/api/orders", "order"), ("/api/secure-orders", "secure-order")):
                traffic.capture(c, method="GET", url=f"https://{HOST}{route}/1",
                                headers={"Authorization": "Bearer tok-a"}, identity="user_a",
                                response={"status": 200, "content_type": "application/json"})
                resource_mod.assert_ownership(c, resource_mod.Ownership(
                    resource_type=rtype, resource_value="1", owner_identity="user_a",
                    tenant="t1", researcher_controlled=True))

            orch = orchestrator_mod.Orchestrator(c)
            worker = _diff_worker(fetch)
            for tech in _DIFF_TECHNIQUES:
                orch.register_worker(tech, worker)

            result = planner.autonomous_run(c, orch, max_actions=10)

            # the loop ran real experiments and converged: nothing safe remains to run
            assert result["actions"], "the loop should have run at least one safe action"
            assert all(a["verdict"].startswith("ALLOW") for a in result["actions"] if a["ran"])
            final = planner.assess(c)
            assert final["counts"]["safe_runnable"] == 0        # every safe gap consumed
            assert result["completion"]["status"] == "RESEARCH_EXHAUSTED"
            assert result["completion"]["why_stopped"] in (
                "no_open_gaps", "all_remaining_need_approval", "all_remaining_denied")

            # the vulnerable cross-account boundary produced exactly one finding; the secure
            # route (and any anonymous boundary the fixture denies) produced none
            assert any(e["classification"] == "suspicious" for e in c.experiments())
            assert any(e["classification"] == "secure" for e in c.experiments())
            fs = finding.findings(c)
            assert len(fs) == 1 and fs[0]["technique"] == "differential_cross_account"
        finally:
            for k in ("ARGUS_HOME", "FIX_A_TOK", "FIX_B_TOK"):
                os.environ.pop(k, None)


def test_golden_secure_path():
    """GAP -> controlled test -> access CORRECTLY DENIED -> no finding -> negative memory ->
    the planner moves on (the resolved boundary is never re-recommended)."""
    with fixture_app.running_app() as port, tempfile.TemporaryDirectory() as tmp:
        os.environ["ARGUS_HOME"] = tmp
        try:
            fetch = _make_fetch(port)
            c = campaign_mod.create(PROGRAM, name="Fixture-Secure")
            _setup_identities_and_traffic(c, "/api/secure-orders", "secure-order")

            top = _top_owner_gap(c)
            gap_id = top["gap_id"]
            assert proposal.build(c, top)["path"] == "/api/secure-orders/1"

            q = proposal.queue(c, gap_id)
            assert q["verdict"].startswith("ALLOW"), q
            orch = orchestrator_mod.Orchestrator(c)
            orch.register_worker("differential_cross_account", _diff_worker(fetch))
            orch.run()
            proposal.reconcile(c)

            # the secure route denies the non-owner => secure classification, NO finding
            assert any(e["classification"] == "secure" for e in c.experiments())
            assert not any(e["classification"] in ("suspicious", "vulnerable")
                           for e in c.experiments())
            assert finding.findings(c) == []

            # negative memory: the gap is RESOLVED and the planner never re-recommends it
            states = coverage._states(c)
            assert states.get(gap_id, {}).get("status") == "RESOLVED"
            assert gap_id not in [g["gap_id"] for g in priority.rank(c)]
        finally:
            for k in ("ARGUS_HOME", "FIX_A_TOK", "FIX_B_TOK"):
                os.environ.pop(k, None)
