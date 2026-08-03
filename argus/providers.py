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
"exploitable", or "this host matters". Those are the rule engine's, exclusively.
`has_admin_interface` is the line worth studying: a provider may assert it only
by *reaching* an administrative surface and observing how it answers, never by
reasoning from a hostname or from `technology == "jenkins"`. Adding a provider must never require an engine change:
that property is what makes Argus grow by adding evidence instead of rewriting
intelligence.

Probing is ACTIVE. Discovery reads public sources (DNS, CT, RDAP); this
connects to the target itself. That is a different level of engagement with
someone else's infrastructure, so it is opt-in (`argus pivot --probe`) and
never runs by default.
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import ipaddress
import re
import socket
import ssl
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


# Headers whose whole value IS the product version (Jenkins volunteers it).
_VERSION_HEADERS = ("x-jenkins", "x-gitlab-version")
_VERSION_RE = re.compile(r"\d+(?:\.\d+){1,3}")


def version_from(headers: dict) -> str | None:
    """Pure: pull a product version from a header that volunteers it.

    A *version* is not an engine predicate — it's an observation another
    provider (KEV) consumes, so it never goes in the evidence dict. occam:
    header-declared versions only; parsing versions out of banners/bodies is
    per-product guesswork — add it when a provider actually needs it.
    """
    for h in _VERSION_HEADERS:
        if h in headers:
            m = _VERSION_RE.search(headers[h])
            if m:
                return m.group(0)
    return None


# No has_admin_interface here — asserting it from `technology == "jenkins"` would
# be the provider drawing a conclusion. That mapping is the rule engine's job
# (see rules/jenkins_confirmed.toml). The predicate is earned by reaching an
# admin surface and observing it: `admin_probe`, at the bottom of this file.
# occam: no certificate_reused — it compares entities, so it is reasoning, not
#        observation. It belongs to a predicate over the graph, not here.
def probe(host: str, timeout: float = 8.0) -> tuple[dict, dict]:
    """Probe one host over HTTPS, then HTTP. Returns (evidence, observed):
    evidence is engine-vocabulary predicates; observed is non-predicate facts
    (e.g. a product version) that OTHER providers read. Unreachable => ({}, {})."""
    if not _resolvable_and_global(host):
        return {}, {}
    for scheme in ("https", "http"):
        status, headers, body = _fetch(f"{scheme}://{host}/", timeout)
        if status:
            observed = {}
            ver = version_from(headers)
            if ver:
                observed["version"] = ver
            return evidence_from(status, headers, body), observed
    return {}, {}


_PROBEABLE = ("domain", "subdomain", "ip")


# --- provider manifest ----------------------------------------------------
# A provider declares the engine predicates it can establish, right next to its
# code, so the coverage map can never drift from reality. `argus coverage`
# reads this; the predicates with no provider are the roadmap.
PROVIDES: dict[str, tuple[str, ...]] = {}


def declares(name: str, provides):
    """Register a provider's asserted predicates. Returns the fn unchanged."""
    def deco(fn):
        PROVIDES[name] = tuple(provides)
        return fn
    return deco


@declares("http_probe", ("internet_facing", "technology", "authentication_required"))
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
        for ent, (ev, obs) in zip(targets, ex.map(lambda e: probe(e.value, timeout), targets)):
            if ev:
                ent.evidence.update(ev)
                reached += 1
            if obs:
                ent.observed.update(obs)
    return reached


def coverage() -> dict:
    """predicate -> provider name (or None). Reads the engine's live vocabulary
    and the provider manifest, so it can't go stale. The name_suggests_* /
    publicly_discoverable predicates come from discovery itself, not a probe;
    every predicate left with None is a gap — the next provider to build."""
    from . import engine
    owner: dict = {}
    for name, preds in PROVIDES.items():
        for pred in preds:
            owner[pred] = name
    for pred in engine._PREDICATES:
        if pred.startswith("name_suggests_") or pred == "publicly_discoverable":
            owner.setdefault(pred, "discovery")
    return {pred: owner.get(pred) for pred in engine._PREDICATES}


# --- KEV / public-exploit intelligence (version-gated) --------------------
# A small local catalog of known-exploited product versions. occam: a static
# subset, not the live CISA KEV feed — wire the feed (or NVD CPE matching) when
# breadth matters; the seam and the honesty property are what this proves.
# Each entry: the product, the highest version still vulnerable, what's known.
_KEV_CATALOG = [
    # Jenkins CVE-2024-23897 — unauth arbitrary file read; KEV-listed, PoC public.
    {"product": "jenkins", "vulnerable_through": "2.441",
     "known_exploited": True, "public_exploit": True},
]


def _ver_tuple(v: str) -> tuple:
    """Numeric dotted version -> comparable tuple. occam: numeric versions only
    (Jenkins etc.); swap in packaging.version if non-numeric ones appear."""
    try:
        return tuple(int(x) for x in v.split("."))
    except (ValueError, AttributeError):
        return ()


def kev_evidence(technology, version) -> dict:
    """Pure: (product, version) -> exploit evidence, gated on the version.

    Version-gated on purpose. "Jenkins is in KEV" is a fact about the product,
    not about this host — a patched instance is not exploitable. So only a
    running version at or below a known-exploited one earns the claim, and no
    version means no claim: the same honesty as I-1 (don't assert the
    unestablished). The provider states facts; whether they raise priority is
    the rule engine's call, never this file's."""
    if not technology or not version:
        return {}
    running = _ver_tuple(version)
    if not running:
        return {}
    ev: dict = {}
    for entry in _KEV_CATALOG:
        if entry["product"] == technology and running <= _ver_tuple(entry["vulnerable_through"]):
            if entry.get("known_exploited"):
                ev["known_exploited"] = True
            if entry.get("public_exploit"):
                ev["public_exploit"] = True
    return ev


@declares("kev", ("known_exploited", "public_exploit"))
def enrich_kev(g) -> int:
    """Attach exploit evidence where a host's (technology, version) matches the
    catalog. Reads only what the probe already established — offline, no
    engagement. Returns the number of hosts matched."""
    matched = 0
    for e in g.nodes.values():
        ev = kev_evidence(e.evidence.get("technology"), getattr(e, "observed", {}).get("version"))
        if ev:
            e.evidence.update(ev)
            matched += 1
    return matched


# --- TLS probe + certificate analysis -------------------------------------
# Two provider classes, cleanly split (see the Provider Contract in
# docs/ENGINEERING_PRINCIPLES.md): the TLS *probe* RECORDS a certificate
# fingerprint — an observation about one host — and never claims reuse. The
# *analyzer*, reading the whole graph, DERIVES `certificate_reused`. A probe has
# only ever seen one host; reuse is a graph-wide judgement, so it is the
# analyzer's, exclusively.
def cert_fingerprint(der: bytes) -> str:
    """Pure: DER-encoded cert -> its SHA-256 fingerprint. The minimum a reuse
    analyzer needs — nothing else is persisted until a rule consumes it
    (Provider Contract, checklist #7: smallest observation set that reasons)."""
    return hashlib.sha256(der).hexdigest()


def _tls_fetch(host: str, timeout: float = 8.0) -> bytes | None:
    """Return the peer certificate (DER) served on 443, or None.

    Verification is OFF on purpose: this observes whatever cert the host presents
    — self-signed or expired included — and only fingerprints it; it is never
    trusted for a secure session. Unreachable / no TLS => None (established
    nothing, invariant I-1)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False          # recon: observe the cert, don't validate it
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:  # noqa: S501 (recon: observe, never trust)
                return ss.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError, ValueError):
        return None


def tls_probe(host: str, timeout: float = 8.0) -> dict:
    """Probe one host's TLS cert. Returns an observation (fingerprint), never a
    predicate — 'reused' is the analyzer's graph-wide call, not this probe's."""
    if not _resolvable_and_global(host):
        return {}
    der = _tls_fetch(host, timeout)
    return {"cert_fingerprint": cert_fingerprint(der)} if der else {}


def enrich_tls(g, timeout: float = 8.0, workers: int = 8) -> int:
    """Record each probeable host's cert fingerprint into `observed`. Writes no
    predicate and no graph shape — a pure observation pass. Returns hosts reached."""
    targets = [e for e in g.nodes.values() if e.type in _PROBEABLE]
    if not targets:
        return 0
    reached = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for ent, obs in zip(targets, ex.map(lambda e: tls_probe(e.value, timeout), targets)):
            if obs:
                ent.observed.update(obs)
                reached += 1
    return reached


def _reused_fingerprints(fingerprints) -> set:
    """Pure: the fingerprints that appear on more than one host."""
    seen, reused = set(), set()
    for fp in fingerprints:
        (reused if fp in seen else seen).add(fp)
    return reused


@declares("cert_analysis", ("certificate_reused",))
def analyze_certificates(g) -> int:
    """Analysis provider: where the SAME cert (fingerprint) is served by two or
    more hosts, assert `certificate_reused` on each. Reads the graph, touches no
    network, mutates no graph shape — the first Analysis-class provider. Returns
    the number of hosts marked."""
    reused = _reused_fingerprints(
        fp for e in g.nodes.values() if (fp := getattr(e, "observed", {}).get("cert_fingerprint")))
    marked = 0
    for e in g.nodes.values():
        if getattr(e, "observed", {}).get("cert_fingerprint") in reused:
            e.evidence["certificate_reused"] = True
            marked += 1
    return marked


# --- administrative surface probe -----------------------------------------
# The first provider that requests more than `/`. Every probe until now asked
# the host one question; this one asks five, so the contract gains item 8:
# request the minimum path set that establishes the predicate. Four
# unambiguously administrative paths, plus one control.
#
# The control is what makes this evidence instead of a guess. Plenty of hosts
# answer 200 (or a redirect) for *every* path — a catch-all, an SPA router, a
# soft-404. So we first ask for a path that cannot exist, learn what "nothing
# here" looks like on this host, and only count a path that answers differently.
#
# `/login` is deliberately NOT in the set: a login page is evidence of
# authentication, not of an administrative surface, and `authentication_required`
# already carries that. Every path here is administrative or it isn't probed.
_ADMIN_PATHS = ("/admin/", "/administrator/", "/manager/", "/wp-admin/")
_CONTROL_PATH = "/argus-control-path-that-does-not-exist"
_ADMIN_TITLE_HINTS = ("admin", "dashboard", "console", "control panel", "manager")


def _shape(status: int, headers: dict, body: str) -> tuple:
    """The comparable shape of one response: status + title. Two paths with the
    same shape are the same page — which is the catch-all case, not two surfaces."""
    m = _TITLE_RE.search(body) if body else None
    return status, (m.group(1).strip().lower() if m else "")


def _is_admin_surface(status: int, headers: dict, title: str) -> bool:
    """Pure: does this response look like a real administrative interface?

    An auth challenge, a redirect into a login flow, or a served page whose title
    names an admin surface. A bare 200 with no such marker is a page we cannot
    characterise — and an uncharacterised page is not an admin interface.
    """
    if status in (401, 403) or "www-authenticate" in headers:
        return True
    if status in (301, 302, 303, 307, 308):
        return any(h in headers.get("location", "").lower() for h in _LOGIN_HINTS)
    if status == 200:
        return any(h in title for h in _LOGIN_HINTS + _ADMIN_TITLE_HINTS)
    return False


def admin_evidence(control: tuple, responses: dict) -> dict:
    """Pure: (control response, {path: response}) -> evidence. No I/O.

    Two conditions, and both are required. The path must not answer the way this
    host answers for something that isn't there — otherwise it's a catch-all and
    the path proves nothing. And what it returns must actually look like an
    administrative surface. `/admin` existing is not the claim; `/admin` behaving
    like an admin interface is.

    Never asserts False. Four paths came back empty-handed means we checked four
    paths, not that the host has no admin surface — so the predicate stays
    `unknown` (invariant I-1) rather than claiming a negative we did not establish.
    """
    for status, headers, body in responses.values():
        if not status:
            continue                      # never reached it: established nothing
        shape = _shape(status, headers, body)
        if shape == control:
            continue                      # answers like a path that isn't there
        if _is_admin_surface(status, headers, shape[1]):
            return {"has_admin_interface": True}
    return {}


def admin_probe(host: str, timeout: float = 8.0) -> dict:
    """Probe one host's administrative paths. Returns evidence; {} establishes
    nothing. Control request first — it both picks the scheme and defines what
    'nothing here' looks like, so an unreachable host costs exactly one request."""
    if not _resolvable_and_global(host):
        return {}
    for scheme in ("https", "http"):
        status, headers, body = _fetch(f"{scheme}://{host}{_CONTROL_PATH}", timeout)
        if status:
            return admin_evidence(
                _shape(status, headers, body),
                {p: _fetch(f"{scheme}://{host}{p}", timeout) for p in _ADMIN_PATHS})
    return {}


@declares("admin_probe", ("has_admin_interface",))
def enrich_admin(g, timeout: float = 8.0, workers: int = 8) -> int:
    """Attach admin-surface evidence to every probeable node. Returns hosts marked.

    Costs up to 5 requests per host against someone else's infrastructure, which
    is why the CLI puts it behind its own flag rather than folding it into
    `--probe`. Writes only to `Entity.evidence`; no nodes, edges, or findings.
    """
    targets = [e for e in g.nodes.values() if e.type in _PROBEABLE]
    if not targets:
        return 0
    marked = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for ent, ev in zip(targets, ex.map(lambda e: admin_probe(e.value, timeout), targets)):
            if ev:
                ent.evidence.update(ev)
                marked += 1
    return marked
