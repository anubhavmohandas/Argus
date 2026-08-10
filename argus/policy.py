"""Engagement policy — compile a pasted bug-bounty program page into the contract
that governs an investigation.

`argus/scope.py` answers one question: may a provider touch this host? A real
program says far more than that — a rate cap, an identity to send, techniques it
forbids, vulnerability classes it will not pay for, and the things it actually
wants found. This module turns the messy text a researcher copies off Intigriti /
HackerOne into a structured `EngagementPolicy` that:

    * builds a `scope.Scope` from the in/out-of-scope assets (reused, not re-done)
    * caps the request rate the tool sends
    * suppresses findings the program declared non-reportable (found ≠ reportable)
    * records the program's stated objectives and per-asset environment/tier

The compiler is deterministic and keyword-driven on purpose: same text in → same
policy out, no model, no network. It is a best-effort parser of human prose, so
it never *guesses a host it isn't sure of* (an unparseable scope line is warned,
not invented) and it never drops a finding on a class it did not explicitly see
excluded.

occam: section-router + keyword heuristics, tuned to the real DHL / KU Leuven /
Intigriti wording. Ceiling: free-prose scope ("any other domain from …") can't be
enforced and is surfaced as a warning; per-asset tier/env come from tokens in the
text, not a structured field. Extend `_NR_MAP` as new rule ids land.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from . import scope as scope_mod
from .engine import InvestigationResult

# --- vulnerability-class exclusions ---------------------------------------
# Program phrasing (substring, lowercased) -> the rule ids / conclusion tags a
# match should suppress. Only classes Argus can actually conclude are worth
# mapping; unmapped exclusions are still recorded (see `non_reportable_labels`)
# so the report can say "found, but the program excludes this".
_NR_MAP: list[tuple[tuple[str, ...], set[str]]] = [
    (("security header", "missing header", "hardening header"), {"missing_security_headers"}),
    (("clickjack",), {"clickjacking"}),
    (("cors",), {"cors"}),
    (("open redirect",), {"open_redirect"}),
    (("version disclosure", "banner grab", "banner-grab", "software version", "version banner"),
     {"version-disclosure"}),
    (("weak ssl", "weak tls", "ssl config", "tls config", "cipher"), {"weak-tls"}),
    (("email spoof", "spf record", "dmarc", "dkim"), {"email_spoofable"}),
    (("self-xss", "self xss"), {"self-xss"}),
    (("csrf",), {"csrf"}),
    (("username enum", "user enumeration", "email enum", "account enum"), {"user-enum"}),
    (("brute force", "brute-force", "rate limit"), {"rate-limit"}),
    (("open port", "port scan"), {"open-port"}),
]

# program objective (substring, lowercased) -> the rule ids / conclusion tags that
# count as *evidence toward that objective*. A finding whose class is here rises
# above generic findings for THIS engagement — it never changes confidence, only
# rank (confidence = how sure, importance = engagement context, kept separate).
_OBJ_MAP: list[tuple[tuple[str, ...], set[str]]] = [
    (("privilege escalation", "privesc", "access control", "authoriz", "idor", "broken access"),
     {"admin_interface_exposed", "access-control", "authz"}),
    (("sensitive data", "data access", "data exposure", "information disclosure", "pii", "secret"),
     {"exposed_secret", "exposed_sensitive_file", "secret"}),
    (("file read", "file write", "arbitrary file", "path traversal", "lfi", "rfi"),
     {"path_traversal"}),
    (("code execution", "rce", "remote code", "command execution", "command injection"),
     {"vulnerable_service", "ssti"}),
    (("template injection", "ssti"), {"ssti"}),
    (("xss", "cross-site scripting", "cross site scripting", "script execution"), {"reflected_xss"}),
    (("open redirect",), {"open_redirect"}),
    (("subdomain takeover", "takeover"), {"subdomain_takeover"}),
    (("graphql",), {"graphql_introspection"}),
]

_RATE_RE = re.compile(r"(\d+(?:\.\d+)?)\s*(?:requests?|reqs?|calls?)?\s*(?:/|per)\s*sec", re.I)
_UA_RE = re.compile(r"user[\s-]*agent\s*[:=]?\s*(.+)", re.I)
_TIER_RE = re.compile(r"\btier\s*[:=]?\s*(\d)", re.I)
_NO_PROD_SCAN_RE = re.compile(r"produc\w*.{0,40}(must not|do not|don't|shouldn't|cannot).{0,20}scan"
                              r"|(do not|don't|no).{0,20}scan.{0,40}produc", re.I)
_TEST_TOKENS = ("test", "acc", "acceptance", "staging", "stage", "uat", "qa", "dev", "sandbox")
_PROD_TOKENS = ("prod", "production", "www.", "live")

# header keyword -> section the following body lines belong to
_HEADERS: list[tuple[tuple[str, ...], str]] = [
    (("out of scope", "out-of-scope", "not in scope", "excluded", "exclusion",
      "not eligible", "non-qualifying", "non qualifying", "not applicable"), "out"),
    (("interesting target", "interesting", "priorit", "objective", "focus",
      "looking for", "we are interested", "qualifying vuln", "in-scope vuln"), "obj"),
    (("do not", "don't", "forbidden", "prohibited", "not allowed",
      "rules of engagement", "restriction"), "forbid"),
    (("in scope", "in-scope", "scope", "assets", "asset", "targets", "target",
      "domains", "domain"), "in"),
]


@dataclass
class Asset:
    pattern: str            # host / wildcard / CIDR, as it will enter the scope
    env: str = ""           # "test" | "prod" | "" (unknown — never guessed past tokens)
    tier: int | None = None
    action: str = "active"  # "active" | "passive" | "none"


@dataclass
class EngagementPolicy:
    scope: scope_mod.Scope
    rate_per_sec: float | None = None
    max_requests: int | None = None
    user_agent: str = ""
    forbidden: list[str] = field(default_factory=list)
    non_reportable: set[str] = field(default_factory=set)        # rule ids / tags to suppress
    non_reportable_labels: list[str] = field(default_factory=list)  # verbatim, for the report
    objectives: list[str] = field(default_factory=list)
    objective_targets: set[str] = field(default_factory=set)   # rule ids / tags the objectives imply
    assets: list[Asset] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    # --- integration with the running engine ------------------------------
    def apply(self) -> None:
        """Push the scope + rate into the provider layer, before any provider runs."""
        from . import providers   # lazy: avoid import cycle at module load
        providers.set_scope(self.scope)
        providers.set_rate(self.rate_per_sec, self.max_requests)

    def is_reportable(self, c) -> bool:
        """A finding the program explicitly excluded is not reportable — even though
        Argus still found and recorded it."""
        return not (c.rule in self.non_reportable or (set(c.tags) & self.non_reportable))

    def objective_match(self, c) -> bool:
        """Does this finding's class match something the program said it cares about?"""
        return bool(c.rule in self.objective_targets or (set(c.tags) & self.objective_targets))

    def action_for(self, host: str) -> str:
        """active / passive / none for a host, from scope + the matched asset's env."""
        if not self.scope.allows(host):
            return "none"
        for a in self.assets:
            if _host_in_pattern(host, a.pattern):
                return a.action
        return "active"

    def filter(self, result: InvestigationResult) -> tuple[InvestigationResult, list]:
        """Apply the engagement contract to a fresh investigation:
          * drop risk findings the program excluded or that name an out-of-scope host
          * mark findings that match a program objective and float them to the top

        Confidence is never touched — only rank. Priorities (attention ranking) and
        the degraded-error carrier pass through. Returns (filtered, suppressed) so the
        caller can *show* what it hid."""
        kept, suppressed = [], []
        for c in result.conclusions:
            if c.kind == "risk" and (not self.is_reportable(c) or not self.scope.allows(c.target)):
                suppressed.append(c)
                continue
            if c.kind == "risk" and self.objective_match(c) and "objective" not in c.tags:
                c.tags = c.tags + ["objective"]   # engagement annotation, not a rule change
            kept.append(c)
        # engagement ordering: objective-matched risks first (stable → confidence order
        # preserved within each group); priorities keep their own order untouched.
        risks = [c for c in kept if c.kind == "risk"]
        rest = [c for c in kept if c.kind != "risk"]
        risks.sort(key=lambda c: "objective" not in c.tags)   # False(0) = matched sorts first
        return InvestigationResult(risks + rest, result.fingerprint, result.error), suppressed

    def summary(self) -> str:
        """The engagement contract, human-readable — echoed before an investigation."""
        L = ["ENGAGEMENT POLICY"]
        L.append(f"  assets           {len(self.assets)} in scope")
        for a in self.assets[:12]:
            meta = " ".join(x for x in (a.env, f"tier{a.tier}" if a.tier else "", a.action) if x)
            L.append(f"    {a.pattern:<34} {meta}")
        L.append(f"  rate             {self.rate_per_sec or '—'} req/sec"
                 f"{'  max ' + str(self.max_requests) if self.max_requests else ''}")
        L.append(f"  user-agent       {self.user_agent or '—'}")
        L.append(f"  forbidden        {', '.join(self.forbidden) or '—'}")
        L.append(f"  non-reportable   {', '.join(self.non_reportable_labels) or '—'}")
        L.append(f"  objectives       {', '.join(self.objectives) or '—'}")
        for w in self.warnings:
            L.append(f"  ! {w}")
        return "\n".join(L)


def compile(text: str) -> EngagementPolicy:
    """Program text -> EngagementPolicy. Deterministic; never raises on messy prose
    (unparseable lines become `.warnings`), but an in-scope section that yields no
    usable host IS a warning worth reading — a policy that scopes nothing is a bug."""
    include: list[str] = []
    exclude: list[str] = []
    assets: list[Asset] = []
    forbidden: list[str] = []
    nr_ids: set[str] = set()
    nr_labels: list[str] = []
    objectives: list[str] = []
    warnings: list[str] = []

    no_prod_scan = bool(_NO_PROD_SCAN_RE.search(text))
    rate, ua = _scan_rate(text), _scan_ua(text)

    section = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        hdr, inline = _split_header(line)   # handles both "Header:" and inline "Header: a, b"
        if hdr is not None:
            section = hdr
            items = [s.strip() for s in re.split(r"[;,]", inline) if s.strip()]
        else:
            items = [_debullet(line)]
        for body in items:
            if not body:
                continue
            _route(section, body, include, exclude, assets, forbidden,
                   nr_ids, nr_labels, objectives, warnings, no_prod_scan)

    if section is not None and not include and not exclude:
        warnings.append("no scope parsed — check the pasted assets section")

    return EngagementPolicy(
        scope=scope_mod.Scope(include, exclude),
        rate_per_sec=rate, user_agent=ua,
        forbidden=forbidden, non_reportable=nr_ids, non_reportable_labels=nr_labels,
        objectives=objectives, objective_targets=_objective_targets(objectives),
        assets=assets, warnings=warnings,
    )


def _route(section, body, include, exclude, assets, forbidden,
           nr_ids, nr_labels, objectives, warnings, no_prod_scan) -> None:
    """Send one parsed item to its section's collector. Mutates the caller's lists."""
    if section == "in":
        host = _as_host(body)
        if host:
            include.append(host)
            assets.append(_asset(host, body, no_prod_scan))
        elif _looks_like_scope_intent(body):
            warnings.append(f"unparseable in-scope line (not enforced): {body!r}")
    elif section == "out":
        host = _as_host(body)
        if host:
            exclude.append(host)
        else:                           # a vulnerability class, not a host
            ids, label = _classify_exclusion(body)
            nr_ids |= ids
            if label not in nr_labels:
                nr_labels.append(label)
    elif section == "forbid":
        forbidden.append(body)
    elif section == "obj":
        objectives.append(body.lower())


# --- parsing internals ----------------------------------------------------
def _match_header(norm: str) -> str | None:
    for keys, sec in _HEADERS:          # ordered: 'out'/'obj' win over the generic 'in'
        if any(norm == k or norm.startswith(k + " ") or norm.startswith(k) for k in keys):
            return sec
    return None


def _split_header(line: str) -> tuple[str | None, str]:
    """(section, inline-content) for a header line, else (None, "").
    Recognises both a bare "Out of scope:" and an inline "Interesting: xss, redirect"."""
    if ":" in line:
        left, right = line.split(":", 1)
        sec = _match_header(re.sub(r"\s+", " ", left.strip().lower()))
        if sec:
            return sec, right.strip()
    norm = re.sub(r"\s+", " ", line.lower().strip().rstrip(":")).strip()
    if len(norm) <= 42:                 # a header is short; a sentence isn't
        return _match_header(norm), ""
    return None, ""


def _debullet(line: str) -> str:
    # require a space after the marker, so a leading "*" of a "*.host" wildcard survives
    return re.sub(r"^\s*(?:[-•·▪]\s+|\*\s+|\d+[.)]\s+)", "", line).strip()


def _as_host(line: str) -> str | None:
    """A scope-usable host/wildcard/CIDR, or None if the line is prose (has spaces,
    no dot) — so 'API key disclosure' is never mistaken for a host."""
    s = line.strip().rstrip("/.")
    if "://" in s:
        s = urlsplit(s).netloc
    elif " " in s:
        return None
    s = s.split("/")[0].split(":")[0].strip().lower()
    if not s:
        return None
    if scope_mod._as_net(s) is not None:
        return s
    if "." in s and scope_mod._valid_entry(s):
        return s
    return None


def _looks_like_scope_intent(body: str) -> bool:
    return bool(re.search(r"\.|/|domain|app|api|endpoint|host|url|ip\b", body, re.I))


def _asset(host: str, body: str, no_prod_scan: bool) -> Asset:
    low = (host + " " + body).lower()
    env = ""
    if any(t in low for t in _TEST_TOKENS):
        env = "test"
    elif any(t in low for t in _PROD_TOKENS):
        env = "prod"
    tier = int(_TIER_RE.search(body).group(1)) if _TIER_RE.search(body) else None
    action = "passive" if (env == "prod" and no_prod_scan) else "active"
    return Asset(pattern=host, env=env, tier=tier, action=action)


def _objective_targets(objectives: list[str]) -> set[str]:
    out: set[str] = set()
    for obj in objectives:
        for keys, ids in _OBJ_MAP:
            if any(k in obj for k in keys):
                out |= ids
    return out


def _classify_exclusion(body: str) -> tuple[set[str], str]:
    low = body.lower()
    for keys, ids in _NR_MAP:
        if any(k in low for k in keys):
            return set(ids), body
    return set(), body                  # recorded for the report even if unmapped


def _host_in_pattern(host: str, pattern: str) -> bool:
    return scope_mod.Scope(include=[pattern], exclude=[]).allows(host)


def _scan_rate(text: str) -> float | None:
    rates = [float(m.group(1)) for m in _RATE_RE.finditer(text)]
    return min(rates) if rates else None   # the most conservative cap the program states


def _scan_ua(text: str) -> str:
    m = _UA_RE.search(text)
    return m.group(1).strip() if m else ""


def demo() -> None:
    """Synthetic programs only — the parser is generic, never tuned to any real one."""
    from .engine import Conclusion

    # scope (apex/wildcard/prose) + rate + class exclusions, bulleted list style
    prog = """Example VDP
    Automated tooling: max 2 requests/sec
    Assets:
    *.example.com
    *.example.org
    Any other domain from the company
    Out of scope:
    - Banner grabbing / version disclosure
    - Missing security headers
    - CORS on non-sensitive endpoints
    """
    p = compile(prog)
    assert p.rate_per_sec == 2.0, p.rate_per_sec
    assert p.scope.allows("api.example.com") and not p.scope.allows("evil.net")
    assert "missing_security_headers" in p.non_reportable and "cors" in p.non_reportable
    assert any("Any other domain" in w for w in p.warnings)   # prose scope flagged, not invented

    hdr = Conclusion(rule="missing_security_headers", name="x", target="api.example.com",
                     confidence=25, ledger={}, kind="risk", tags=["exposure", "hardening"])
    cve = Conclusion(rule="vulnerable_service", name="x", target="api.example.com",
                     confidence=80, ledger={}, kind="risk", tags=["cve"])
    kept, dropped = p.filter(InvestigationResult([hdr, cve], "fp"))
    assert [c.rule for c in kept.risks] == ["vulnerable_service"], [c.rule for c in kept.risks]
    assert [c.rule for c in dropped] == ["missing_security_headers"]

    # host exclusions + inline objective; objective ranking beats confidence on rank only
    prog2 = """Assets:
    app.example.net
    Out of scope:
    login.example.net
    Interesting: privilege escalation
    Rate: 5 requests/sec
    """
    k = compile(prog2)
    assert k.rate_per_sec == 5.0
    assert not k.scope.allows("login.example.net") and k.scope.allows("app.example.net")
    assert "admin_interface_exposed" in k.objective_targets      # privesc objective -> admin-surface class
    obj_hit = Conclusion(rule="admin_interface_exposed", name="Admin", target="app.example.net",
                         confidence=40, ledger={}, kind="risk", tags=["access-control"])
    generic = Conclusion(rule="missing_security_headers", name="Headers", target="app.example.net",
                         confidence=90, ledger={}, kind="risk", tags=["hardening"])
    ranked, _ = k.filter(InvestigationResult([generic, obj_hit], "fp"))
    assert [c.rule for c in ranked.risks] == ["admin_interface_exposed", "missing_security_headers"]
    assert ranked.risks[0].confidence == 40 and "objective" in ranked.risks[0].tags   # rank up, confidence intact

    # URL assets + user-agent + prod-passive / test-active environment split
    prog3 = """In scope:
    https://test.example.io/app
    https://www.example.io/home
    Production URL must not be scanned.
    User-Agent: my-research-agent
    """
    j = compile(prog3)
    assert j.user_agent == "my-research-agent", j.user_agent
    envs = {a.pattern: (a.env, a.action) for a in j.assets}
    assert envs["test.example.io"] == ("test", "active"), envs
    assert envs["www.example.io"] == ("prod", "passive"), envs   # prod + "must not be scanned"
    print("policy demo passed")


if __name__ == "__main__":
    demo()
