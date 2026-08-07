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
import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request

_UA = "Argus-Recon/0.1.0"
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

# Web-exposure observations, harvested from the owasp_scanner misconfig/crypto
# patterns and reshaped to fit the Provider Contract: the probe RECORDS what a
# single ordinary GET revealed (which hardening headers were absent, whether a
# cookie shipped without its flags) and asserts nothing about what it means. The
# rules in rules/*.toml draw the conclusion. Both come free from the `/` response
# the base probe already fetches — zero extra requests (checklist item 8).
_SECURITY_HEADERS = ("strict-transport-security", "content-security-policy",
                     "x-content-type-options", "x-frame-options")


def missing_security_headers(headers: dict) -> list:
    """Pure: which core hardening headers this response did NOT carry.

    Headers arrive already lowercased from `_fetch`. The list is the observation;
    the boolean predicate `security_headers_missing` is derived from it."""
    return [h for h in _SECURITY_HEADERS if h not in headers]


def cookie_is_insecure(headers: dict, scheme: str = "https"):
    """Pure: does the response's Set-Cookie lack Secure/HttpOnly? None if it set
    no cookie — 'no cookie' is not 'a secure cookie', so it stays unknown (I-1).

    occam: inspects the last Set-Cookie header only (urllib collapses repeats);
    a response juggling several cookies is judged on its last one. Upgrade path =
    read the raw header list if per-cookie flags start to matter. `Secure` is
    only meaningful over TLS, so its absence counts only when scheme is https."""
    sc = headers.get("set-cookie")
    if not sc:
        return None
    low = sc.lower()
    return "httponly" not in low or (scheme == "https" and "secure" not in low)


# --- subdomain-takeover fingerprints --------------------------------------
# A dangling DNS record (a CNAME to a deprovisioned SaaS bucket/app) leaves the
# subdomain pointing at a service that will hand control to whoever claims the
# name next. Each vendor serves a DISTINCTIVE "this isn't claimed" page, and that
# exact string is the signal — a generic 404 is not. Matching a vendor error is
# self-gating like the traversal /etc/passwd body: ordinary content can't forge
# it. Comes free from the body the base probe already fetched (zero extra
# requests, like clickjacking). occam: a curated high-signal set — extend it as
# new services appear; the provider never changes. A match is a strong lead a
# hunter still confirms by trying to claim the name.
_TAKEOVER_FINGERPRINTS = (
    ("github-pages", "there isn't a github pages site here"),
    ("aws-s3", "the specified bucket does not exist"),
    ("aws-s3", "nosuchbucket"),
    ("heroku", "no such app"),
    ("shopify", "sorry, this shop is currently unavailable"),
    ("fastly", "fastly error: unknown domain"),
    ("surge", "project not found"),
    ("bitbucket", "repository not found"),
    ("pantheon", "the gods are wise, but do not know of the site which you seek"),
    ("readthedocs", "unknown to read the docs"),
    ("wpengine", "the site you were looking for couldn't be found"),
    ("tilda", "please renew your subscription"),
)


def takeover_service(body: str) -> str | None:
    """Pure: which claimable service this response fingerprints, or None. The
    match IS the evidence — a vendor's unclaimed-name page, not a generic 404."""
    low = body.lower()
    for service, needle in _TAKEOVER_FINGERPRINTS:
        if needle in low:
            return service
    return None


def is_framable(headers: dict) -> bool:
    """Pure: can an attacker's page frame this one (clickjacking)? True unless the
    response constrains framing with X-Frame-Options DENY/SAMEORIGIN or a CSP
    frame-ancestors directive. occam: presence of frame-ancestors counts as
    protection without parsing its value — a directive that lists only trusted
    origins still blocks an arbitrary attacker frame; deprecated ALLOW-FROM is
    ignored by modern browsers, so it reads as framable (which it is)."""
    xfo = headers.get("x-frame-options", "").lower()
    if "deny" in xfo or "sameorigin" in xfo:
        return False
    return "frame-ancestors" not in headers.get("content-security-policy", "").lower()


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


def _fetch(url: str, timeout: float, data: bytes | None = None,
           extra_headers: dict | None = None) -> tuple[int, dict, str]:
    """GET (or POST when `data` is given) without redirects. Returns (status,
    lowercased headers, body). Unreachable => (0, {}, "") — a failure to connect
    establishes nothing. `extra_headers` add to the defaults (Origin for CORS,
    Content-Type for a GraphQL POST); they never override the User-Agent."""
    hdrs = {"User-Agent": _UA, "Accept": "*/*", **(extra_headers or {})}
    req = urllib.request.Request(url, data=data, headers=hdrs)
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


def evidence_from(status: int, headers: dict, body: str, scheme: str = "https") -> dict:
    """Pure: one HTTP response -> the evidence it establishes. No I/O.

    Only facts we actually observed go in. What the response doesn't show stays
    absent from the dict — absent means "unknown" to the engine (invariant I-1),
    and unknown is never the same claim as false.
    """
    if not status:
        return {}          # never reached it: we learned nothing, not "it's down"

    ev: dict = {"internet_facing": True}
    # Subdomain takeover reads a vendor "unclaimed" page, which is usually a 404 —
    # so it runs on any real response, before the status-specific branches below.
    if takeover_service(body):
        ev["subdomain_takeover"] = True
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
        # Hardening posture is only judgeable on a page that actually served.
        # A 200 with every header present is an established negative (checked,
        # fine), not silence — same honesty as authentication_required above.
        ev["security_headers_missing"] = bool(missing_security_headers(headers))
        # Framability is judgeable on the same served page — a False here means we
        # checked and it's protected, not silence (I-1). Costs zero extra requests.
        ev["clickjacking"] = is_framable(headers)

    cookie = cookie_is_insecure(headers, scheme)
    if cookie is not None:                       # None => no cookie set => unknown
        ev["insecure_cookie"] = cookie
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
            missing = missing_security_headers(headers) if status == 200 else []
            if missing:                       # the specifics, for a human/NYX to read
                observed["missing_headers"] = missing
            svc = takeover_service(body)      # which service, for the dossier/NYX
            if svc:
                observed["takeover_service"] = svc
            return evidence_from(status, headers, body, scheme), observed
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


@declares("http_probe", ("internet_facing", "technology", "authentication_required",
                         "security_headers_missing", "insecure_cookie", "clickjacking",
                         "subdomain_takeover"))
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


# --- exposed sensitive-file probe -----------------------------------------
# The owasp_scanner "information disclosure / exposed files" pattern, reshaped to
# the Provider Contract. Same control-gated discipline as admin_probe: a host
# that answers 200 for everything proves nothing, so we first learn what "not
# here" looks like, then only count a path that answers differently AND whose
# body actually looks like the sensitive file it claims to be. `/.git/HEAD`
# returning a soft-404 branded 200 is not an exposed repo; `/.git/HEAD` returning
# "ref: refs/heads/main" is. A signature per path is what makes this evidence
# instead of a guess — and it is exactly the disclosure that turns a domain into
# a lead when you sit down to hunt.
_SENSITIVE_PATHS = ("/.git/HEAD", "/.env", "/.DS_Store")
_ENV_LINE = re.compile(r"(?m)^[A-Z_][A-Z0-9_]*=")


def _looks_like(path: str, body: str) -> bool:
    """Pure: does `body` match the real content signature for `path`?
    occam: one cheap signature per path — enough to reject a soft-404. Add more
    paths (and their signatures) here; the provider itself never changes."""
    if path == "/.git/HEAD":
        return body.lstrip().startswith("ref:")            # a real git HEAD ref
    if path == "/.env":
        return bool(_ENV_LINE.search(body))                # KEY=VALUE dotenv lines
    if path == "/.DS_Store":
        return "Bud1" in body[:64]                          # DS_Store magic
    return False


def sensitive_evidence(control: tuple, responses: dict) -> dict:
    """Pure: (control response shape, {path: (status, headers, body)}) -> evidence.

    Both conditions required, same as admin_evidence: the path must not answer
    the way this host answers for something absent (else it's a catch-all), and
    the body must actually be the file. Never asserts False — three paths coming
    back empty means we checked three paths, not that nothing is exposed (I-1)."""
    for path, (status, headers, body) in responses.items():
        if not status:
            continue                          # never reached it: established nothing
        if _shape(status, headers, body) == control:
            continue                          # answers like a path that isn't there
        if status == 200 and _looks_like(path, body):
            return {"exposed_sensitive_file": True}
    return {}


def exposure_probe(host: str, timeout: float = 8.0) -> dict:
    """Probe one host's sensitive paths. Returns evidence; {} establishes nothing.
    Control request first — it picks the scheme and defines 'nothing here', so an
    unreachable host costs exactly one request (same shape as admin_probe)."""
    if not _resolvable_and_global(host):
        return {}
    for scheme in ("https", "http"):
        status, headers, body = _fetch(f"{scheme}://{host}{_CONTROL_PATH}", timeout)
        if status:
            return sensitive_evidence(
                _shape(status, headers, body),
                {p: _fetch(f"{scheme}://{host}{p}", timeout) for p in _SENSITIVE_PATHS})
    return {}


@declares("exposure_probe", ("exposed_sensitive_file",))
def enrich_exposure(g, timeout: float = 8.0, workers: int = 8) -> int:
    """Attach exposed-file evidence to every probeable node. Returns hosts marked.

    Requests up to 4 paths per host (control + 3 files) against someone else's
    infrastructure, so it rides the same opt-in active tier as admin_probe rather
    than the default probe. Writes only to `Entity.evidence`."""
    targets = [e for e in g.nodes.values() if e.type in _PROBEABLE]
    if not targets:
        return 0
    marked = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for ent, ev in zip(targets, ex.map(lambda e: exposure_probe(e.value, timeout), targets)):
            if ev:
                ent.evidence.update(ev)
                marked += 1
    return marked


# --- TCP port scan + service-version CVE match ----------------------------
# The first provider that speaks TCP instead of HTTP — the `nmap -p` half of a
# recon pass. It connects to a set of ports, records which answer, reads the
# banner a service volunteers on connect, and parses (product, version) out of
# it. That is pure observation: exactly the same move as reading a version out of
# X-Jenkins, just off a raw socket. It asserts NOTHING about risk.
#
# A second, offline step matches those versions against a local CVE catalog (same
# discipline and same ceiling as _KEV_CATALOG) and establishes ONE predicate,
# `known_vulnerable_service` — "a service on this host reported a version with a
# known CVE". WHICH CVEs, and whether each is exploited, ride in
# `observed["cves"]` for the dossier and NYX to read; the predicate is the single
# trigger a rule concludes on. The scan owns only that one predicate, so it never
# collides with the HTTP probe's `technology`/`version` (a host can run both).
#
# This is the loudest provider Argus has: a connect scan is unmistakable in the
# target's logs, so the CLI gates it behind its own flag, never the default probe.
_DEFAULT_PORTS = (21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                  993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200)

# banner substring -> canonical product name in the CVE catalog (lowercased).
_PRODUCT_ALIASES = {"openssh": "openssh", "vsftpd": "vsftpd", "proftpd": "proftpd",
                    "exim": "exim", "nginx": "nginx", "apache": "apache",
                    "microsoft-iis": "iis"}
# First dotted version in a banner. Numeric-only on purpose: OpenSSH's "8.9p1"
# keeps the "p1" out, so _ver_tuple (numeric dotted) can compare it. occam.
_VER_IN_BANNER = re.compile(r"\d+\.\d+(?:\.\d+){0,2}")


def parse_ports(spec: str) -> list[int]:
    """'22,80,8000-8100' -> sorted unique port list. Trust boundary (CLI input):
    rejects out-of-range or reversed ranges with ValueError, never silently."""
    ports: set[int] = set()
    for part in (p.strip() for p in spec.split(",")):
        if not part:
            continue
        lo, _, hi = part.partition("-")
        lo = int(lo)
        hi = int(hi) if hi else lo
        if not 1 <= lo <= hi <= 65535:
            raise ValueError(f"invalid port range: {part!r} (want 1..65535, low<=high)")
        ports.update(range(lo, hi + 1))
    return sorted(ports)


def parse_banner(banner: str) -> tuple:
    """Pure: a service banner -> (product, version) or (None, None).

    occam: substring product match + the first dotted version AFTER the product
    name (so "SSH-2.0-OpenSSH_7.4" reads 7.4, the product version, not 2.0, the
    protocol version). Good for services that name product and version together on
    connect (OpenSSH, vsFTPd, ProFTPd, Exim). A product that speaks only after a
    protocol handshake needs a protocol probe — add its alias/pattern here."""
    if not banner:
        return None, None
    low = banner.lower()
    for needle, canon in _PRODUCT_ALIASES.items():
        idx = low.find(needle)
        if idx != -1:
            m = _VER_IN_BANNER.search(banner, idx + len(needle))
            return canon, (m.group(0) if m else None)
    return None, None


# occam: a static demo catalog, same shape and same `<=` ceiling as _KEV_CATALOG
# — NOT the live NVD feed. Wire NVD CPE matching when breadth matters; the seam
# (scan -> version -> match -> report) and the honesty (version-gated, never a
# guess) are what this proves. `known_exploited`/`public_exploit` here are report
# metadata for observed["cves"], not predicates this provider claims to own.
_CVE_CATALOG = [
    {"product": "vsftpd", "vulnerable_through": "2.3.4", "cve": "CVE-2011-2523",
     "summary": "vsftpd 2.3.4 backdoor grants an unauthenticated root shell",
     "severity": "critical", "known_exploited": True, "public_exploit": True},
    {"product": "proftpd", "vulnerable_through": "1.3.5", "cve": "CVE-2015-3306",
     "summary": "ProFTPD mod_copy allows unauthenticated file read/write (RCE)",
     "severity": "critical", "known_exploited": True, "public_exploit": True},
    {"product": "openssh", "vulnerable_through": "7.7", "cve": "CVE-2018-15473",
     "summary": "OpenSSH username enumeration via authentication response timing",
     "severity": "medium", "known_exploited": False, "public_exploit": True},
    {"product": "exim", "vulnerable_through": "4.91", "cve": "CVE-2019-10149",
     "summary": "Exim 'Return of the WIZard' remote command execution",
     "severity": "critical", "known_exploited": True, "public_exploit": True},
]


def cve_matches(product, version) -> list:
    """Pure: (product, version) -> the catalog entries that apply, version-gated.

    Same honesty as kev_evidence: no product or no parseable version means no
    match — silence, never a guess (invariant I-1). Sorted by CVE id so the
    observation, and any fingerprint over it, is deterministic."""
    if not product or not version:
        return []
    running = _ver_tuple(version)
    if not running:
        return []
    return sorted(
        (e for e in _CVE_CATALOG
         if e["product"] == product and running <= _ver_tuple(e["vulnerable_through"])),
        key=lambda e: e["cve"])


def _probe_port(host: str, port: int, timeout: float) -> tuple:
    """Connect to one TCP port. Returns (state, banner):
      ("open",     banner)  — accepted; banner is what it volunteered (may be "")
      ("closed",   "")      — actively refused (RST): host up, nothing listening
      ("filtered", "")      — no response before the timeout: a firewall/CDN is
                              silently dropping the connection

    The closed/filtered split is the whole point of a scan against a modern host:
    most ports there are *filtered*, not closed, and the two are different facts —
    "refused" vs "no answer" — so they stay different (I-1). occam: connect scan
    can't see nmap's open|filtered nuance; a raw-SYN scan needs root and is a
    separate provider. Passive banner only — reads what a service says first,
    sends nothing."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                return "open", s.recv(256).decode("latin-1", "replace").strip()
            except OSError:                       # open, but volunteered nothing
                return "open", ""
    except ConnectionRefusedError:
        return "closed", ""
    except (socket.timeout, TimeoutError):
        return "filtered", ""
    except OSError:
        return "filtered", ""                     # unreachable / reset-less drop


def scan_host(host: str, ports=None, timeout: float = 4.0, workers: int = 32) -> dict:
    """Scan `host` over TCP. Returns an observation dict (never a risk claim):
      scanned:        int                              — how many ports we tried
      open_ports:     [int]                            — ports that accepted
      filtered_ports: [int]                            — ports that dropped us
      services:       [{port, banner, product, version}] — what each open port said
      cves:           [{port, product, version, cve, summary, severity, ...}]
    (closed ports are the boring majority — counted via `scanned`, not stored.)
    {} if `host` is not a safe, globally-routable target — the same SSRF guard
    every probe uses: a discovered name pointing inward is never connected to."""
    ports = list(_DEFAULT_PORTS) if ports is None else list(ports)   # [] means none, not default
    if not ports or not _resolvable_and_global(host):
        return {}
    open_ports, filtered, services, cves = [], [], [], []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, len(ports))) as ex:
        for port, (state, banner) in zip(ports, ex.map(lambda p: _probe_port(host, p, timeout), ports)):
            if state == "filtered":
                filtered.append(port)
            elif state == "open":
                open_ports.append(port)
                product, version = parse_banner(banner)
                services.append({"port": port, "banner": banner[:200],
                                 "product": product, "version": version})
                for hit in cve_matches(product, version):
                    cves.append({"port": port, "product": product, "version": version, **hit})
            # "closed": host up, nothing listening — reflected in `scanned` only
    obs: dict = {"scanned": len(ports)}
    if open_ports:
        obs["open_ports"] = sorted(open_ports)
    if filtered:
        obs["filtered_ports"] = sorted(filtered)
    if services:
        obs["services"] = services
    if cves:
        obs["cves"] = cves
    return obs


@declares("port_scan", ("known_vulnerable_service",))
def enrich_scan(g, ports=None, timeout: float = 4.0, workers: int = 8) -> int:
    """Scan every probeable host's TCP ports, record open ports + service versions
    in `observed`, and establish `known_vulnerable_service` where a version matches
    the CVE catalog. Returns hosts with >=1 catalog CVE.

    Loud and active — a connect scan is unmistakable in the target's logs, which
    is why the CLI gates it behind its own flag. Writes only to `observed`/
    `evidence`; no nodes, edges, or findings (Provider Contract)."""
    targets = [e for e in g.nodes.values() if e.type in _PROBEABLE]
    if not targets:
        return 0
    vulnerable = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for ent, obs in zip(targets, ex.map(lambda e: scan_host(e.value, ports, timeout), targets)):
            if obs:
                ent.observed.update(obs)
                if obs.get("cves"):
                    ent.evidence["known_vulnerable_service"] = True
                    vulnerable += 1
    return vulnerable


# --- path-traversal probe -------------------------------------------------
# Active, and the same control-gated discipline as admin_probe/exposure_probe:
# try a handful of traversal payloads for a file with a known signature, and
# assert only if the response BOTH differs from this host's "nothing here" answer
# AND actually contains the file. A 200 alone proves nothing (soft-404 / SPA /
# catch-all); a body with a real /etc/passwd root line proves arbitrary file read.
#
# The payloads are the same string four ways — plain, URL-encoded, doubled, and
# fully percent-encoded — because a naive filter often strips one form and misses
# the rest. occam: path-based payloads against `/` only, targeting the classic
# webroot / static-handler traversal (the quick win a hunter tries first). Real
# traversal usually lives in a request PARAMETER (?file=../../etc/passwd);
# discovering parameters is a bigger job — add a param-fuzzing provider when it
# matters. Signature is Unix /etc/passwd; add win.ini when a Windows target needs it.
_TRAVERSAL_PAYLOADS = (
    "/../../../../../../../../etc/passwd",
    "/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd",
    "/....//....//....//....//....//etc/passwd",
    "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
)
_PASSWD_RE = re.compile(r"(?m)^[a-z_][a-z0-9_-]*:[^:]*:\d+:\d+:")   # a real passwd line


def traversal_evidence(control: tuple, responses: dict) -> dict:
    """Pure: (control response shape, {payload: (status, headers, body)}) -> evidence.

    Both conditions required, same as sensitive_evidence: the payload must not
    answer the way this host answers for something absent (else it's a catch-all),
    and the body must actually be an /etc/passwd. Never asserts False — the
    payloads coming back empty means we tried them, not that traversal is
    impossible (invariant I-1)."""
    for status, headers, body in responses.values():
        if not status:
            continue                          # never reached it: established nothing
        if _shape(status, headers, body) == control:
            continue                          # answers like a path that isn't there
        if status == 200 and _PASSWD_RE.search(body):
            return {"path_traversal": True}
    return {}


def traversal_probe(host: str, timeout: float = 8.0) -> dict:
    """Probe one host for path traversal. Returns evidence; {} establishes nothing.
    Control request first — it picks the scheme and defines 'nothing here', so an
    unreachable host costs exactly one request (same shape as exposure_probe)."""
    if not _resolvable_and_global(host):
        return {}
    for scheme in ("https", "http"):
        status, headers, body = _fetch(f"{scheme}://{host}{_CONTROL_PATH}", timeout)
        if status:
            return traversal_evidence(
                _shape(status, headers, body),
                {p: _fetch(f"{scheme}://{host}{p}", timeout) for p in _TRAVERSAL_PAYLOADS})
    return {}


@declares("traversal_probe", ("path_traversal",))
def enrich_traversal(g, timeout: float = 8.0, workers: int = 8) -> int:
    """Attach path-traversal evidence to every probeable node. Returns hosts marked.

    Requests control + N payloads per host against someone else's infrastructure,
    so it rides the same opt-in active tier (`--probe-paths`) as admin_probe and
    exposure_probe. Writes only to `Entity.evidence`."""
    targets = [e for e in g.nodes.values() if e.type in _PROBEABLE]
    if not targets:
        return 0
    marked = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for ent, ev in zip(targets, ex.map(lambda e: traversal_probe(e.value, timeout), targets)):
            if ev:
                ent.evidence.update(ev)
                marked += 1
    return marked


# --- CORS misconfiguration probe ------------------------------------------
# One GET carrying an Origin header we chose. The exploitable misconfiguration is
# a server that ECHOES an arbitrary origin into Access-Control-Allow-Origin AND
# sets Access-Control-Allow-Credentials: true — that combination lets any website
# read this host's authenticated responses on a victim's behalf. Reflecting our
# unique random origin is inherently control-gated: a soft-404 / catch-all cannot
# forge back the exact origin string we sent, so no separate control request is
# needed. Low engagement (one benign GET), so it rides the base --probe tier.
#
# occam: flags only reflected-specific-origin + credentials, the classic high-
# signal case. ACAO:* is browser-rejected with credentials (not exploitable), and
# `Origin: null` reflection is a narrower variant — add each when a target needs
# it. Non-credentialed reflection exposes only public data, so it isn't claimed.
_CORS_PROBE_ORIGIN = "https://argus-cors-probe.example"


def cors_evidence(headers: dict, probe_origin: str = _CORS_PROBE_ORIGIN) -> dict:
    """Pure: does the response grant our arbitrary Origin credentialed access?

    No Access-Control-Allow-Origin at all => no claim (unknown, I-1). It counts
    only when the server echoed the exact origin we sent AND allows credentials.
    """
    acao = headers.get("access-control-allow-origin", "").strip()
    if not acao:
        return {}
    acac = headers.get("access-control-allow-credentials", "").strip().lower() == "true"
    if acao == probe_origin and acac:
        return {"cors_misconfig": True}
    return {}


def cors_probe(host: str, timeout: float = 8.0) -> dict:
    """Probe one host for a credentialed reflected-origin CORS grant. Returns
    evidence; {} establishes nothing. One GET with our probe Origin — an
    unreachable or non-global host costs nothing (SSRF guard first)."""
    if not _resolvable_and_global(host):
        return {}
    for scheme in ("https", "http"):
        status, headers, _ = _fetch(f"{scheme}://{host}/", timeout,
                                    extra_headers={"Origin": _CORS_PROBE_ORIGIN})
        if status:
            return cors_evidence(headers)
    return {}


@declares("cors_probe", ("cors_misconfig",))
def enrich_cors(g, timeout: float = 8.0, workers: int = 8) -> int:
    """Attach CORS-misconfiguration evidence to every probeable node. Returns hosts
    marked. One GET per host (same low engagement as the base HTTP probe), so the
    CLI folds it into --probe. Writes only to `Entity.evidence`."""
    targets = [e for e in g.nodes.values() if e.type in _PROBEABLE]
    if not targets:
        return 0
    marked = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for ent, ev in zip(targets, ex.map(lambda e: cors_probe(e.value, timeout), targets)):
            if ev:
                ent.evidence.update(ev)
                marked += 1
    return marked


# --- GraphQL introspection probe ------------------------------------------
# POST a minimal introspection query to a short list of conventional GraphQL
# paths. Introspection enabled in production hands an attacker the entire schema
# — every type, field, and mutation — which is the map they use for everything
# else. The signature is self-gating like the traversal /etc/passwd body: a
# response is only counted if its JSON actually carries a live __schema result,
# which a soft-404 or error page cannot forge, so no separate control request is
# needed. Multiple POSTs against someone else's server => the active --probe-paths
# tier, alongside admin/exposure/traversal.
#
# occam: a short conventional path list, not endpoint discovery; a query-only
# introspection, not the full type walk. Add paths / GET-transport / persisted-
# query bypass when a target needs it.
_GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/graphql/console", "/v1/graphql", "/query")
_INTROSPECTION_QUERY = b'{"query":"{__schema{queryType{name}}}"}'


def introspection_confirmed(body: str) -> bool:
    """Pure: does this body prove GraphQL introspection is live? True only when the
    JSON carries data.__schema.queryType.name — a shape an error/soft-404 can't fake."""
    try:
        data = (json.loads(body).get("data") or {}).get("__schema") or {}
        return bool((data.get("queryType") or {}).get("name"))
    except (ValueError, AttributeError, TypeError):
        return False


def graphql_probe(host: str, timeout: float = 8.0) -> dict:
    """Probe one host's conventional GraphQL paths for enabled introspection.
    Returns evidence; {} establishes nothing. A cheap reachability GET first, so
    an unreachable host costs one request before any POSTs (SSRF guard first)."""
    if not _resolvable_and_global(host):
        return {}
    for scheme in ("https", "http"):
        if not _fetch(f"{scheme}://{host}/", timeout)[0]:
            continue                       # host didn't answer on this scheme
        for path in _GRAPHQL_PATHS:
            status, _, body = _fetch(f"{scheme}://{host}{path}", timeout,
                                     data=_INTROSPECTION_QUERY,
                                     extra_headers={"Content-Type": "application/json"})
            if status == 200 and introspection_confirmed(body):
                return {"graphql_introspection": True}
        return {}                          # reached the host; no open introspection
    return {}


@declares("graphql_probe", ("graphql_introspection",))
def enrich_graphql(g, timeout: float = 8.0, workers: int = 8) -> int:
    """Attach GraphQL-introspection evidence to every probeable node. Returns hosts
    marked. Up to 1 + len(_GRAPHQL_PATHS) requests per host, so it rides the active
    --probe-paths tier with admin/exposure/traversal. Writes only to `Entity.evidence`."""
    targets = [e for e in g.nodes.values() if e.type in _PROBEABLE]
    if not targets:
        return 0
    marked = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for ent, ev in zip(targets, ex.map(lambda e: graphql_probe(e.value, timeout), targets)):
            if ev:
                ent.evidence.update(ev)
                marked += 1
    return marked


# --- email-spoofing analysis (DMARC enforcement over DoH) ------------------
# An Analysis-class provider like KEV/cert_analysis: it reads DNS, never touches
# the target host. DMARC is the record that actually stops From-header spoofing;
# a domain with no DMARC record, or a published policy of p=none (monitor-only),
# can be spoofed. It reuses the discovery layer's DNS-over-HTTPS resolver, so it
# adds no dependency and no engagement with the target — the query goes to a
# public resolver. occam: DMARC-only, on apex domain entities. A subdomain with
# no DMARC of its own inherits the org policy's sp= directive — checking that
# (and SPF -all alignment) is the upgrade path; DMARC absent / p=none is the
# honest, high-agreement floor the whole industry reports on.
_DMARC_RE = re.compile(r"v\s*=\s*dmarc1", re.I)
_DMARC_POLICY = re.compile(r"\bp\s*=\s*(none|quarantine|reject)", re.I)


def email_spoofable(dmarc_txts) -> bool:
    """Pure: do these _dmarc TXT records leave the domain open to email spoofing?
    True when no DMARC record is published, or its policy is p=none (not enforced)."""
    dmarc = next((t for t in dmarc_txts if _DMARC_RE.search(t)), None)
    if dmarc is None:
        return True                       # no DMARC at all → spoofable
    m = _DMARC_POLICY.search(dmarc)
    return bool(m and m.group(1).lower() == "none")


def _txt_records(name: str) -> list:
    """DoH TXT lookup via the discovery layer's resolver (dns.google). Returns the
    record strings ([] on failure). Reuses core.http_json — no new dependency, and
    the query never touches the target, only a public resolver."""
    from .core import http_json, q       # lazy: matches coverage()'s deferred import
    data = http_json(f"https://dns.google/resolve?name={q(name)}&type=TXT")
    return [str(a.get("data", "")).strip('"') for a in (data or {}).get("Answer", []) if a.get("data")]


@declares("email_spoof", ("email_spoofable",))
def enrich_email_spoof(g, workers: int = 8) -> int:
    """Establish `email_spoofable` on every apex-domain entity whose DMARC is
    absent or unenforced. DNS-only (public resolver) — no target engagement — so
    the CLI folds it into the base --probe tier. Writes only to `Entity.evidence`."""
    domains = [e for e in g.nodes.values() if e.type == "domain"]
    if not domains:
        return 0
    marked = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        results = ex.map(lambda e: email_spoofable(_txt_records(f"_dmarc.{e.value}")), domains)
        for ent, spoofable in zip(domains, results):
            if spoofable:
                ent.evidence["email_spoofable"] = True
                marked += 1
    return marked


# --- open-redirect probe --------------------------------------------------
# Active param injection, same self-gating discipline as the traversal probe:
# inject a UNIQUE external canary URL into conventional redirect parameters on
# `/`, and count it only if a 3xx Location points back at that exact canary host —
# a value the app cannot emit unless it followed our parameter (I-1). No open
# redirect to a host we didn't inject. occam: query-param redirects on `/` only;
# body/meta-refresh and path-segment redirects are the upgrade path.
_REDIRECT_PARAMS = ("redirect", "url", "next", "return", "returnurl", "dest",
                    "destination", "continue", "r", "u")
_REDIRECT_CANARY = "https://argus-openredirect-canary.example/"
_REDIRECT_HOST = "argus-openredirect-canary.example"
_REDIRECTS = (301, 302, 303, 307, 308)


def _location_host(location: str) -> str:
    """Pure: the host a Location header points at ('' if none/unparseable).
    Handles absolute and protocol-relative (//host/…) redirect targets."""
    try:
        return (urllib.parse.urlsplit(location.strip()).hostname or "").lower()
    except ValueError:
        return ""


def redirect_evidence(responses: dict, canary_host: str = _REDIRECT_HOST) -> dict:
    """Pure: {param: (status, location)} -> evidence. Open redirect only when a 3xx
    Location resolves to the exact external host we injected. Never asserts False —
    parameters coming back empty means we tried them, not that redirects are safe."""
    for status, location in responses.values():
        if status in _REDIRECTS and _location_host(location) == canary_host:
            return {"open_redirect": True}
    return {}


def redirect_probe(host: str, timeout: float = 8.0) -> dict:
    """Probe one host for an open redirect. Returns evidence; {} establishes nothing.
    Reachability GET first, so an unreachable host costs one request (SSRF guard first)."""
    if not _resolvable_and_global(host):
        return {}
    payload = urllib.parse.quote(_REDIRECT_CANARY, safe="")
    for scheme in ("https", "http"):
        if not _fetch(f"{scheme}://{host}/", timeout)[0]:
            continue
        responses = {}
        for p in _REDIRECT_PARAMS:
            status, headers, _ = _fetch(f"{scheme}://{host}/?{p}={payload}", timeout)
            responses[p] = (status, headers.get("location", ""))
        return redirect_evidence(responses)
    return {}


@declares("redirect_probe", ("open_redirect",))
def enrich_redirect(g, timeout: float = 8.0, workers: int = 8) -> int:
    """Attach open-redirect evidence to every probeable node. Returns hosts marked.
    1 + len(_REDIRECT_PARAMS) requests per host, so it rides the active --probe-paths
    tier with admin/exposure/traversal/graphql. Writes only to `Entity.evidence`."""
    targets = [e for e in g.nodes.values() if e.type in _PROBEABLE]
    if not targets:
        return 0
    marked = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for ent, ev in zip(targets, ex.map(lambda e: redirect_probe(e.value, timeout), targets)):
            if ev:
                ent.evidence.update(ev)
                marked += 1
    return marked


# --- reflected-XSS + SSTI injection probe ---------------------------------
# One active probe, two predicates — both from the SAME reflection of a unique
# canary, so it costs one request set. Inject a canary carrying an HTML-XSS
# marker and a template-injection marker into conventional parameters on `/`:
#   · reflected_xss — the raw <svg/onload=…> came back with its angle brackets
#     INTACT (unescaped HTML reflection). If the app HTML-encodes, the marker
#     comes back as &lt;svg…&gt; and is correctly NOT counted.
#   · ssti          — our {{7*7}} rendered to 49 flush against a unique marker
#     (argussti49), a value only a template engine that evaluated our injection
#     can produce. A literal reflection stays argussti{{7*7}} and is NOT counted.
# Both markers are unique tokens, so neither can be forged by ordinary page text
# (self-gating, I-1). occam: HTML-context XSS + {{ }} template syntax only;
# attribute/JS-context XSS and ${}/<%= %> engines are the upgrade path.
_INJECT_PARAMS = ("q", "s", "search", "query", "id", "name", "keyword", "message")
_XSS_PAYLOAD = "argusx55<svg/onload=confirm(1)>"     # raw <…> survives ⇒ unescaped reflection
_SSTI_MARK = "argussti"
_SSTI_PAYLOAD = _SSTI_MARK + "{{7*7}}"               # renders to argussti49 iff evaluated
_SSTI_EVAL = _SSTI_MARK + "49"
_INJECT_PAYLOAD = _XSS_PAYLOAD + _SSTI_PAYLOAD


def injection_evidence(bodies) -> dict:
    """Pure: the response bodies from injecting our canary -> {reflected_xss?, ssti?}.
    Never asserts False — an absent marker means the app didn't reflect it here,
    not that it's safe everywhere (I-1)."""
    ev: dict = {}
    for body in bodies:
        if not body:
            continue
        if _XSS_PAYLOAD in body:
            ev["reflected_xss"] = True
        if _SSTI_EVAL in body:
            ev["ssti"] = True
    return ev


def injection_probe(host: str, timeout: float = 8.0) -> dict:
    """Probe one host for reflected XSS / SSTI. Returns evidence; {} establishes
    nothing. Reachability GET first, so an unreachable host costs one request."""
    if not _resolvable_and_global(host):
        return {}
    payload = urllib.parse.quote(_INJECT_PAYLOAD, safe="")
    for scheme in ("https", "http"):
        if not _fetch(f"{scheme}://{host}/", timeout)[0]:
            continue
        bodies = [_fetch(f"{scheme}://{host}/?{p}={payload}", timeout)[2] for p in _INJECT_PARAMS]
        return injection_evidence(bodies)
    return {}


@declares("injection_probe", ("reflected_xss", "ssti"))
def enrich_injection(g, timeout: float = 8.0, workers: int = 8) -> int:
    """Attach reflected-XSS / SSTI evidence to every probeable node. Returns hosts
    marked. 1 + len(_INJECT_PARAMS) requests per host, so it rides the active
    --probe-paths tier with the other payload probes. Writes only to `Entity.evidence`."""
    targets = [e for e in g.nodes.values() if e.type in _PROBEABLE]
    if not targets:
        return 0
    marked = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for ent, ev in zip(targets, ex.map(lambda e: injection_probe(e.value, timeout), targets)):
            if ev:
                ent.evidence.update(ev)
                marked += 1
    return marked
