"""Evidence providers — the second half of the pipeline seam.

A discovery module yields Findings (new entities to pivot into). A *provider*
does something different: it establishes facts about an entity we already have,
and writes them to `Entity.evidence` where the rule engine's `_ev()` predicates
read them.

The contract, and it is the whole point:

    A provider answers "what evidence can I establish?"
    A provider NEVER answers "what conclusion should I draw?"

So this file asserts `technology`, `internet_facing`, `authentication_required`
— things it directly observed on the wire. It does not assert "high risk",
"exploitable", or even "this is an admin interface". Those are the rule
engine's, exclusively. Adding a provider must never require an engine change:
that property is what makes Argus grow by adding evidence instead of rewriting
intelligence.

Probing is ACTIVE. Discovery reads public sources (DNS, CT, RDAP); this
connects to the target itself. That is a different level of engagement with
someone else's infrastructure, so it is opt-in (`argus pivot --probe`) and
never runs by default.
"""
from __future__ import annotations

import concurrent.futures
import ipaddress
import re
import socket
import urllib.error
import urllib.request

_UA = "Argus-Recon/0.1 (+https://github.com/)"
_BODY_CAP = 65536          # enough for <head>; we only ever read the title
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)

# Technology fingerprints. Only names in the engine's _TECH vocabulary — a
# provider that invents a technology string no rule can match is dead evidence.
_TECH_BY_HEADER = {              # header present => that's what it runs
    "x-jenkins": "jenkins",
    "x-jenkins-session": "jenkins",
    "kbn-name": "kibana",
    "kbn-license-sig": "kibana",
    "x-gitlab-feature-category": "gitlab",
}
_TECH_BY_HEADER_VALUE = [        # (header, substring in its value) => tech
    ("set-cookie", "phpmyadmin", "phpmyadmin"),
    ("set-cookie", "grafana_session", "grafana"),
    ("server", "jenkins", "jenkins"),
    ("x-powered-by", "jira", "jira"),
]
# Matched against <title> only, never the whole body: a page that merely
# mentions "jenkins" in a link is not a Jenkins server.
_TECH_BY_TITLE = ["jenkins", "gitlab", "grafana", "kibana", "phpmyadmin",
                  "jira", "confluence"]

_LOGIN_HINTS = ("sign in", "log in", "login", "authentication required",
                "unauthorized", "sso")


def _resolvable_and_global(host: str) -> bool:
    """True only if every address `host` resolves to is public.

    Discovered hostnames are attacker-influenced input: a subdomain can point
    at 127.0.0.1, at RFC1918 space, or at 169.254.169.254 (cloud metadata).
    Probing those turns a recon tool into an SSRF primitive against the machine
    running it, so a non-global answer means we do not connect at all.
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, ValueError):
        return False
    if not infos:
        return False
    for info in infos:
        try:
            if not ipaddress.ip_address(info[4][0]).is_global:
                return False
        except ValueError:
            return False
    return True


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects: following one re-targets us at a host that never
    passed the guard above. A 3xx is also evidence in its own right (a redirect
    to /login says something), so we keep the response instead of chasing it."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _fetch(url: str, timeout: float) -> tuple[int, dict, str]:
    """GET without redirects. Returns (status, lowercased headers, body).
    Unreachable => (0, {}, "") — a failure to connect establishes nothing."""
    req = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "*/*"})
    try:
        with _OPENER.open(req, timeout=timeout) as r:  # noqa: S310 (probes external targets by design)
            body = r.read(_BODY_CAP).decode("utf-8", "replace")
            return r.status, {k.lower(): v for k, v in r.headers.items()}, body
    except urllib.error.HTTPError as e:      # 3xx/4xx/5xx are answers, not errors
        body = ""
        try:
            body = e.read(_BODY_CAP).decode("utf-8", "replace")
        except Exception:
            pass
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, body
    except Exception:
        return 0, {}, ""


def evidence_from(status: int, headers: dict, body: str) -> dict:
    """Pure: one HTTP response -> the evidence it establishes. No I/O.

    Only facts we actually observed go in. What the response doesn't show stays
    absent from the dict — absent means "unknown" to the engine (invariant I-1),
    and unknown is never the same claim as false.
    """
    if not status:
        return {}          # never reached it: we learned nothing, not "it's down"

    ev: dict = {"internet_facing": True}
    title = (_TITLE_RE.search(body).group(1).strip().lower()
             if body and _TITLE_RE.search(body) else "")

    for header, tech in _TECH_BY_HEADER.items():
        if header in headers:
            ev["technology"] = tech
            break
    else:
        for header, needle, tech in _TECH_BY_HEADER_VALUE:
            if needle in headers.get(header, "").lower():
                ev["technology"] = tech
                break
        else:
            for tech in _TECH_BY_TITLE:
                if tech in title:
                    ev["technology"] = tech
                    break

    if status in (401, 403) or "www-authenticate" in headers:
        ev["authentication_required"] = True
    elif status in (301, 302, 303, 307, 308):
        # a redirect only counts as an auth gate if it points at one
        if any(h in headers.get("location", "").lower() for h in _LOGIN_HINTS):
            ev["authentication_required"] = True
    elif status == 200:
        # We got the page. This is a real observation either way — the probe
        # checked, so False here is established evidence, not invented silence.
        ev["authentication_required"] = any(h in title for h in _LOGIN_HINTS)
    return ev


# occam: no has_admin_interface — asserting it from `technology == "jenkins"`
#        would be the provider drawing a conclusion. That mapping is the rule
#        engine's job (see rules/jenkins_confirmed.toml). Assert it only when a
#        probe actually reaches an admin surface.
# occam: no certificate_reused — it compares entities, so it is reasoning, not
#        observation. It belongs to a predicate over the graph, not here.
def probe(host: str, timeout: float = 8.0) -> dict:
    """Probe one host over HTTPS, then HTTP. Returns the evidence established."""
    if not _resolvable_and_global(host):
        return {}
    for scheme in ("https", "http"):
        status, headers, body = _fetch(f"{scheme}://{host}/", timeout)
        if status:
            return evidence_from(status, headers, body)
    return {}


_PROBEABLE = ("domain", "subdomain", "ip")


def enrich(g, timeout: float = 8.0, workers: int = 8) -> int:
    """Attach probe evidence to every probeable node. Returns hosts reached.

    Writes only to `Entity.evidence`; never adds nodes, edges, or findings.
    Discovery shape is discovery's business — a provider only fills in facts.
    """
    targets = [e for e in g.nodes.values() if e.type in _PROBEABLE]
    if not targets:
        return 0
    reached = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for ent, ev in zip(targets, ex.map(lambda e: probe(e.value, timeout), targets)):
            if ev:
                ent.evidence.update(ev)
                reached += 1
    return reached
