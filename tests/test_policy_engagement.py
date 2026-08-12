"""End-to-end behavioural proof: the SAME raw findings, run under three materially
different engagement policies, produce three different reportable+ranked queues.

This is the claim that separates Argus from a scanner — it does not behave the same
against every target; the program's rules of engagement reshape suppression and
priority. We hold discovery/rules constant (one fixed finding pool) and vary only
the policy, so any difference in the queue is caused by the engagement alone.

The three programs are synthetic (example.* hosts, generic rules) — the parser is
general, never tuned to any real program. No network: touching real hosts is
exactly what the scope layer exists to prevent.
"""
from argus import policy
from argus.engine import Conclusion, InvestigationResult


def _pool(host: str) -> InvestigationResult:
    """One identical set of findings on `host`, in engine order (confidence desc)."""
    mk = lambda rule, conf, tags: Conclusion(
        rule=rule, name=rule, target=host, confidence=conf, ledger={}, kind="risk", tags=tags)
    risks = [
        mk("missing_security_headers", 90, ["hardening"]),
        mk("cors", 80, ["cors"]),
        mk("vulnerable_service", 70, ["cve"]),        # control: no program touches this class
        mk("open_redirect", 60, ["redirect"]),
        mk("exposed_secret", 55, ["secret"]),
        mk("reflected_xss", 50, ["xss"]),
        mk("admin_interface_exposed", 45, ["access-control"]),
    ]
    return InvestigationResult(risks, "fp")


# program A — excludes hardening classes, cares about sensitive-data exposure
PROG_A = """Assets:
*.acme-a.example
Automated tooling: max 2 requests/sec
Interesting: sensitive data exposure, account compromise
Out of scope:
- Missing security headers
- CORS on non-sensitive endpoints
- Version disclosure / banner grabbing
"""

# program B — excludes no vuln class, cares about privilege escalation
PROG_B = """Assets:
app.acme-b.example
Out of scope:
login.acme-b.example
Interesting targets:
horizontal privilege escalation
vertical privilege escalation
Rate: 5 requests/sec
"""

# program C — excludes CORS + user-enum, cares about xss and open redirect
PROG_C = """In scope:
https://test.acme-c.example/
Production URL must not be scanned.
Interesting: reflected xss, open redirect
Rate: 5 requests/sec
Out of scope:
- Username enumeration
- CORS on non-sensitive endpoints
"""


def _queue(program: str, host: str):
    p = policy.compile(program)
    kept, suppressed = p.filter(_pool(host))
    return [c.rule for c in kept.risks], sorted({c.rule for c in suppressed})


def test_engagement_reshapes_the_queue():
    a_q, a_sup = _queue(PROG_A, "api.acme-a.example")
    b_q, b_sup = _queue(PROG_B, "app.acme-b.example")
    c_q, c_sup = _queue(PROG_C, "test.acme-c.example")

    # A: headers + CORS suppressed; "sensitive data" objective floats exposed_secret to #1.
    assert a_sup == ["cors", "missing_security_headers"], a_sup
    assert a_q[0] == "exposed_secret", a_q
    assert "missing_security_headers" not in a_q and "cors" not in a_q

    # B: suppresses no vuln class (only an out-of-scope host); privesc objective floats
    # admin_interface_exposed to #1 — even at 45%, above the 90% headers finding.
    assert b_sup == [], b_sup
    assert b_q[0] == "admin_interface_exposed", b_q
    assert b_q.index("admin_interface_exposed") < b_q.index("missing_security_headers")

    # C: CORS suppressed; xss + redirect objectives float to the top, redirect first
    # (60% > xss 50% — objective match sets the *group*, confidence orders within it).
    assert c_sup == ["cors"], c_sup
    assert c_q[:2] == ["open_redirect", "reflected_xss"], c_q

    # THE POINT: same findings in, three different priority queues out.
    assert a_q != b_q and b_q != c_q and a_q != c_q
    assert a_q[0] != b_q[0] != c_q[0]     # each engagement leads with a different lead

    # And confidence was never touched to achieve it — only rank.
    kept, _ = policy.compile(PROG_B).filter(_pool("app.acme-b.example"))
    top = kept.risks[0]
    assert top.rule == "admin_interface_exposed" and top.confidence == 45


def test_engagement_state_fully_resets_between_runs():
    """The reset discipline the CLI's pivot path relies on: a run WITHOUT a policy
    must inherit NOTHING from a prior --policy run. Headers were the gap — installed
    by apply(), never cleared — so program A's identity header ('X-Program: handle-A')
    could ride onto program B's targets. Guard all three engagement globals together;
    headers are the one this regression is about. No network."""
    from argus import providers

    p = policy.compile("Assets:\n*.acme-a.example\nRate: 2 requests/sec\n")
    p.request_headers = {"X-Program": "handle-A"}
    p.apply()                                    # what a --policy run installs
    assert providers._ID_HEADERS == {"X-Program": "handle-A"}
    assert providers._SCOPE is not None and providers._throttle.min_interval > 0

    # exactly what cli._run's non-policy pivot path now does before the next run
    providers.set_scope(None); providers.set_rate(); providers.set_headers()
    assert providers._ID_HEADERS == {}, "stale ID header would leak onto the next target"
    assert providers._SCOPE is None
    assert providers._throttle.min_interval == 0.0


if __name__ == "__main__":
    test_engagement_reshapes_the_queue()
    test_engagement_state_fully_resets_between_runs()
    print("policy engagement behaviour: 3 programs -> 3 distinct ranked queues — passed")
