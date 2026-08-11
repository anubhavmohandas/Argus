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

occam: section-router + keyword/shape heuristics, tuned to real platform-page
paste (DHL / KU Leuven / Intigriti). Raw pages are mostly furniture — nav chrome,
agreement prose, asset tables, a researcher/footer block — so routing runs behind
three structural gates: a footer sentinel (`_is_footer`), informational-section
headers that collect nothing (`_INFO_HEADERS`), and a per-line noise filter
(`_is_noise`: chrome, sublabels, cross-references, table rows, prose sentences).
Ceilings: free-prose network scope ("any other domain from …") is warned not
enforced; non-host scope (hardware/firmware product names) is recorded as a named
`Asset(network=False)` the operator reads but Argus cannot engage; a CIA-triad
objective stated in prose is recorded as a label only (too broad to drive rank);
per-asset env comes from tokens, and tier from either an inline token or the
table's own tier cell, which a flat paste drops on the line below the row — that
cell may also read "Out of scope", excluding its one row and NOT opening the
global out-of-scope section. Extend `_NR_MAP` as new rule ids land.
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
# same-line only ([ \t-] never crosses a newline) and a delimiter is required, so a
# bare "User agent" label whose value sits on the next line ("Not applicable", a
# platform placeholder) is not mistaken for the agent to send.
_UA_RE = re.compile(r"user[ \t-]*agent[ \t]*[:=][ \t]*(\S.*)", re.I)
_UA_PLACEHOLDERS = {"not applicable", "n/a", "none", "-", "any", "no restriction"}
_TIER_RE = re.compile(r"\btier\s*[:=]?\s*(\d)", re.I)
_NO_PROD_SCAN_RE = re.compile(r"produc\w*.{0,40}(must not|do not|don't|shouldn't|cannot).{0,20}scan"
                              r"|(do not|don't|no).{0,20}scan.{0,40}produc", re.I)
_TEST_TOKENS = ("test", "acc", "acceptance", "staging", "stage", "uat", "qa", "dev", "sandbox")
_PROD_TOKENS = ("prod", "production", "www", "live")

# Platform-page furniture: short UI/nav lines that would otherwise pass as items.
# Kept small and platform-generic on purpose — the structural gates (_is_noise
# shape rules, the footer sentinel, informational headers) do the heavy lifting.
_CHROME = {
    "give feedback", "view changes", "expand all", "filter text", "no bounty",
    "create submission", "view my submissions", "follow program", "program actions",
    "report illegal content", "description", "detail", "detail leaderboard",
    "leaderboard", "not applicable", "all", "dashboard", "programs", "inbox",
    "url", "wildcard", "type", "tier",   # asset-table column/type cells, not assets
    "ip range", "ip", "cidr", "ip address",
}

# The asset table's *type* column. Its presence is what proves the next line is a
# table cell rather than the next entry of a plain list or a section header —
# a bullet list of hosts never has one. See the tier-cell branch in `compile`.
_TYPE_CELLS = {"url", "wildcard", "ip range", "ip", "cidr", "ip address", "domain"}

# Once the policy body ends, platform pages append a researcher list, an activity
# feed and a legal footer. Nothing at or below these markers is policy — stop.
_FOOTER_MARKERS = (
    "researchers", "last contributors", "program actions", "activity",
    "last 90 day response times",
)

# Section headers that introduce program *prose* (eligibility, safe harbour, FAQ,
# severity, legal), not policy items. Hitting one ends the collecting section
# until the next real header, so its body is never recorded as scope/exclusions.
_INFO_HEADERS = (
    "severity assessment", "severity", "faq", "safe harbor", "safe harbour",
    "report eligibility", "product eligibility", "eligibility criteria",
    "security researcher", "researcher/reporter", "researcher and reporter",
    "sensitive and personal", "shared agreements", "intellectual property",
    "rules of engagement", "disclosure policy",
)

# header keyword -> section the following body lines belong to
_HEADERS: list[tuple[tuple[str, ...], str]] = [
    (("out of scope", "out-of-scope", "not in scope", "excluded", "exclusion",
      "not eligible", "non-qualifying", "non qualifying"), "out"),
    (("interesting target", "interesting", "priorit", "objective", "focus",
      "looking for", "we are interested", "qualifying vuln", "in-scope vuln",
      "worst-case scenario", "worst case scenario"), "obj"),
    (("do not", "don't", "forbidden", "prohibited", "not allowed",
      "restriction"), "forbid"),
    (("in scope", "in-scope", "scope", "assets", "asset", "targets", "target",
      "domains", "domain"), "in"),
]


@dataclass
class Asset:
    pattern: str            # host / wildcard / CIDR, or a named non-network asset
    env: str = ""           # "test" | "prod" | "" (unknown — never guessed past tokens)
    tier: int | None = None
    action: str = "active"  # "active" | "passive" | "none"
    network: bool = True     # False = hardware/firmware/product name; never enters host scope


@dataclass
class EngagementPolicy:
    scope: scope_mod.Scope
    rate_per_sec: float | None = None
    max_requests: int | None = None
    user_agent: str = ""
    request_headers: dict[str, str] = field(default_factory=dict)  # program-required headers to send
    forbidden: list[str] = field(default_factory=list)
    non_reportable: set[str] = field(default_factory=set)        # rule ids / tags to suppress
    non_reportable_labels: list[str] = field(default_factory=list)  # verbatim, for the report
    objectives: list[str] = field(default_factory=list)
    objective_targets: set[str] = field(default_factory=set)   # rule ids / tags the objectives imply
    assets: list[Asset] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    # --- integration with the running engine ------------------------------
    def apply(self) -> None:
        """Push the scope + rate + required identity headers into the provider
        layer, before any provider runs. A header value still holding the page's
        placeholder ('<your-username>') is NOT sent — announcing yourself as
        literal '<your-username>' identifies nobody; `unfilled_headers()` says so."""
        from . import providers   # lazy: avoid import cycle at module load
        providers.set_scope(self.scope)
        providers.set_rate(self.rate_per_sec, self.max_requests)
        hdrs = {k: v for k, v in self.request_headers.items() if not _is_placeholder(v)}
        if self.user_agent:
            hdrs["User-Agent"] = self.user_agent
        providers.set_headers(hdrs)

    def unfilled_headers(self) -> list[str]:
        """Required headers whose value is still the page's placeholder — the
        operator must supply a real one or the engagement is unattributable."""
        return [f"{k}: {v}" for k, v in self.request_headers.items() if _is_placeholder(v)]

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

    def summary(self, limit: int = 12) -> str:
        """The engagement contract, human-readable — echoed before an investigation.
        Long lists are capped at `limit` entries with an explicit "+N more" so the
        output never silently hides part of the contract (limit=0 = show all)."""
        def block(title: str, items: list[str]) -> list[str]:
            if not items:
                return [f"  {title:<16} —"]
            shown = items if limit <= 0 else items[:limit]
            out = [f"  {title:<16} {len(items)}"]
            out += [f"    · {s}" for s in shown]
            if len(items) > len(shown):
                out.append(f"    · … +{len(items) - len(shown)} more")
            return out

        L = ["ENGAGEMENT POLICY"]
        L += block("assets", [
            f"{a.pattern:<34} " + " ".join(x for x in (
                a.env, f"tier{a.tier}" if a.tier else "", a.action,
                "" if a.network else "(non-network)") if x)
            for a in self.assets
        ])
        L.append(f"  rate             {self.rate_per_sec or '—'} req/sec"
                 f"{'  max ' + str(self.max_requests) if self.max_requests else ''}")
        L.append(f"  user-agent       {self.user_agent or '—'}")
        L += block("headers", [
            f"{k}: {v}" + ("   ← FILL IN before probing" if _is_placeholder(v) else "")
            for k, v in self.request_headers.items()
        ])
        L += block("forbidden", self.forbidden)
        L += block("non-reportable", self.non_reportable_labels)
        # Which exclusions Argus can actually act on — the rest are report-only text.
        L.append(f"  → suppresses     {', '.join(sorted(self.non_reportable)) or '—'}")
        L += block("objectives", self.objectives)
        L += block("warnings", self.warnings)
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
    req_headers = _scan_request_headers(text)

    section = None
    batch: list[Asset] = []                 # assets from the previous source line — an
    armed = False                           # asset table puts their tier cell underneath
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if _is_footer(line):                # researcher list / activity feed / legal footer
            break
        cell = _TIER_CELL_RE.fullmatch(_debullet(line)) if armed else None
        if cell:                            # the asset table's tier column qualifies the row
            for a in batch:                 # above it — never a scope entry, never a section
                if cell.group(1):           # header, never a vulnerability category
                    a.tier = int(cell.group(1))
                    continue
                a.action = "none"           # an "Out of scope" cell excludes that row alone
                if a.pattern in include:
                    include.remove(a.pattern)
                exclude.append(a.pattern)
            batch, armed = [], False        # one row, one qualifying cell
            continue
        if batch and _norm(line) in _TYPE_CELLS:
            armed = True                    # host / TYPE / tier — only a table reaches a tier
            continue                        # cell, so only a table's "Out of scope" is one
        hdr, inline = _split_header(line)   # handles both "Header:" and inline "Header: a, b"
        if hdr is not None:
            section, batch, armed = hdr, [], False
            items = [s.strip() for s in re.split(r"[;,]", inline) if s.strip()]
        else:
            items = _split_items(_debullet(line))
        before = len(assets)
        for body in items:
            if not body:
                continue
            _route(section, body, include, exclude, assets, forbidden,
                   nr_ids, nr_labels, objectives, warnings, no_prod_scan)
        if len(assets) > before:            # a new row: it, not the last one, owns the next
            batch, armed = assets[before:], False   # type cell and the tier cell after it

    for w in _scan_objective_prose(text):   # CIA triad stated in prose (label only, no rank)
        if w not in objectives:
            objectives.append(w)

    named = [a for a in assets if not a.network]
    if section is not None and not include and not exclude and not named:
        warnings.append("no scope parsed — check the pasted assets section")
    elif named and not include:
        shown = ", ".join(a.pattern for a in named[:3]) + ("…" if len(named) > 3 else "")
        warnings.append(f"scope is non-network ({len(named)} named asset(s): {shown}) — "
                        f"recorded for the operator; no host for Argus to engage")

    return EngagementPolicy(
        scope=scope_mod.Scope(include, exclude),
        rate_per_sec=rate, user_agent=ua, request_headers=req_headers,
        forbidden=forbidden, non_reportable=nr_ids, non_reportable_labels=nr_labels,
        objectives=objectives, objective_targets=_objective_targets(objectives),
        assets=assets, warnings=warnings,
    )


def _route(section, body, include, exclude, assets, forbidden,
           nr_ids, nr_labels, objectives, warnings, no_prod_scan) -> None:
    """Send one parsed item to its section's collector. Mutates the caller's lists.
    Informational sections collect nothing; furniture/prose is dropped, never
    recorded as a policy item (that pollution was the whole bug on raw pages)."""
    if section not in ("in", "out", "forbid", "obj") or _is_noise(body):
        return
    if section == "in":
        host = _as_host(body)
        if host:
            include.append(host)
            assets.append(_asset(host, body, no_prod_scan))
        elif _looks_like_scope_intent(body):     # meant as a network target, unparseable
            warnings.append(f"unparseable in-scope line (not enforced): {body!r}")
        elif len(body.split()) >= 2:
            # a named non-network asset (hardware / firmware / product name) — recorded
            # for the operator, never enters host scope (Argus cannot engage it).
            assets.append(Asset(pattern=body.rstrip(". "), network=False, action="none"))
    elif section == "out":
        host = _as_host(body)
        if host:
            exclude.append(host)
            return
        ids, label = _classify_exclusion(body)   # a vulnerability class / excluded category
        nr_ids |= ids
        if (ids or len(body.split()) >= 2) and label not in nr_labels:
            nr_labels.append(label)              # single unmapped words are furniture, dropped
    elif section == "forbid":
        forbidden.append(body)
    elif section == "obj":
        objectives.append(body.lower().rstrip(". "))


# --- parsing internals ----------------------------------------------------
def _norm(line: str) -> str:
    return re.sub(r"\s+", " ", line.strip().lower())


# A header is often written as a possessive sentence ("Our worst-case scenarios are:"),
# so the keyword is one determiner in. Tried second, never instead: 'we are interested'
# is itself a key and must keep matching whole.
_LEAD_RE = re.compile(r"^(?:our|the|these|those|my)\s+")


def _match_header(norm: str) -> str | None:
    return _match_header_exact(norm) or _match_header_exact(_LEAD_RE.sub("", norm))


def _match_header_exact(norm: str) -> str | None:
    if any(norm == k or norm.startswith(k) for k in _INFO_HEADERS):
        return "_info"                  # prose section: recognised so it stops collection
    for keys, sec in _HEADERS:          # ordered: 'out'/'obj' win over the generic 'in'
        if any(norm == k or norm.startswith(k + " ") or norm.startswith(k) for k in keys):
            return sec
    return None


# The tier column of an asset table holds either a tier or the row's exclusion —
# "Out of scope" *as a cell* marks one row, and must not start the global section.
_TIER_CELL_RE = re.compile(r"tier\s*[:=]?\s*(\d+)\.?|out[ -]of[ -]scope", re.I)


def _split_items(line: str) -> list[str]:
    """One asset-table row can hold a whole block of hosts ('IP Range' rows paste as
    '1.2.3.4, 5.6.7.8, …'). Split only when EVERY part is a host, so prose with
    commas ('email spoofing, SPF, DMARC') stays the single item it is."""
    parts = [p.strip() for p in line.split(",")]
    if len(parts) > 1 and all(_as_host(p) for p in parts):
        return parts
    return [line]


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
    s = s.strip().lower()
    if not s:
        return None
    if scope_mod._as_net(s) is not None:      # a bare IP or CIDR: keep the mask intact
        return s                              # (a /24 is a range, not host 203.0.113.0)
    s = s.split("/")[0].split(":")[0].strip()  # a hostname: drop any URL path / port
    if "." in s and scope_mod._valid_entry(s):
        return s
    return None


def _looks_like_scope_intent(body: str) -> bool:
    """True when a non-host in-scope line still *means* a network target (a domain
    phrase, a path, an embedded dot) — so it is warned, not silently dropped nor
    mistaken for a hardware asset. A trailing sentence period is not an embedded
    dot: 'SDM firmware ... elements.' is a named asset, 'api.foo bar' is intent."""
    b = body.strip().rstrip(".")
    return bool(re.search(r"\w\.\w|/|\b(?:subdomain|domain|app|api|endpoint|host|url|ip)s?\b",
                          b, re.I))


def _is_noise(line: str) -> bool:
    """A pasted platform page is mostly furniture, prose and cross-references, not
    policy items. True for lines that must never be recorded as a scope/exclusion/
    forbidden/objective entry. Structural and platform-generic, not per-program.
    occam: shape heuristics; ceiling: a real >10-word exclusion or a bare one-word
    technique is dropped here — the former is unmappable prose anyway, the latter
    is re-admitted in the 'out' route when _classify_exclusion maps it."""
    low = _norm(line)
    if not low or low in _CHROME:
        return True
    if low.endswith(":"):                                # 'Hardware:', 'Minimum:' — a sublabel
        return True
    if low.endswith("section.") or re.search(r"\bsee\b.*\bsection\b", low):
        return True                                      # cross-reference prose
    if "\t" in line:                                     # a table row pasted as text
        return True
    if "feedback" in low and " " in low and "." not in low and len(low.split()) <= 4:
        return True                                      # 'Program feedback link' etc. — a UI link
    return len(low.split()) > 10                         # a sentence/paragraph, not an item


def _is_footer(line: str) -> bool:
    norm = re.sub(r"\s+", " ", line.lower()).rstrip("?:. ")
    return norm in _FOOTER_MARKERS or norm.startswith(("© copyright", "want to participate"))


_INTEREST_RE = re.compile(
    r"\b(?:particularly |especially |only |mainly |really |also )*interested in\s+(.+?)"
    r"(?:\s+(?:if|when|unless|where|provided|and|that|because)\b|[.,;:)]|$)", re.I)


def _scan_objective_prose(text: str) -> list[str]:
    """Objectives many programs state in prose, never under a header:
      * the CIA triad ('compromise of confidentiality, integrity, or availability')
        — recorded when ≥2 co-occur (a lone word is not a triad claim);
      * an explicit '(we're only) interested in <X>' focus — the bounded phrase X.
    Label-only unless X maps in _OBJ_MAP; then it also drives objective ranking."""
    low = text.lower()
    out = [w for w in ("confidentiality", "integrity", "availability") if w in low]
    out = out if len(out) >= 2 else []
    for m in _INTEREST_RE.finditer(text):
        phrase = re.sub(r"\s+", " ", m.group(1)).strip(" .,-").lower()
        if 2 <= len(phrase.split()) <= 8 and phrase not in out:
            out.append(phrase)
    return out


def _asset(host: str, body: str, no_prod_scan: bool) -> Asset:
    # match env tokens as whole labels/words, never as substrings, and never
    # against the host's TLD — `.dev`/`.app` are TLDs, not environments
    words = set(re.findall(r"[a-z]+", host.lower().rsplit(".", 1)[0]))
    words |= set(re.findall(r"[a-z]+", body.lower()))
    env = ""
    if words & set(_TEST_TOKENS):
        env = "test"
    elif words & set(_PROD_TOKENS):
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
    for line in text.splitlines():
        m = _UA_RE.match(line.strip())
        if m:
            v = m.group(1).strip().rstrip(".")
            if v.lower() not in _UA_PLACEHOLDERS:   # skip platform "Not applicable" rows
                return v
    return ""


_REQ_HDR_LABEL_RE = re.compile(r"(?:required[\s-]*)?request[\s-]*header", re.I)
_HEADER_LINE_RE = re.compile(r"([A-Za-z][A-Za-z0-9-]*)\s*:\s*(\S.*)")


def _is_placeholder(value: str) -> bool:
    """'<your-username>', '{handle}', 'YOUR_USERNAME' — a slot, not a value."""
    v = value.strip()
    return bool(re.search(r"[<{\[]|\byour[_ -]?\w+\b", v, re.I))


def _scan_request_headers(text: str) -> dict[str, str]:
    """Program-required request headers (e.g. Intigriti's 'Request header' config
    row → 'X-Intigriti: <your-username>'). Anchored on the config label so ordinary
    'Name: value' prose isn't harvested; the value sits on the label line or the
    next few. occam: value may be a '<placeholder>' the operator must fill before
    sending — captured verbatim and surfaced, not auto-sent."""
    lines = [l.strip() for l in text.splitlines()]
    out: dict[str, str] = {}
    for i, line in enumerate(lines):
        if not _REQ_HDR_LABEL_RE.fullmatch(line):
            continue
        for nxt in lines[i:i + 4]:              # label line itself, then a short lookahead
            m = _HEADER_LINE_RE.fullmatch(nxt)
            if m and m.group(2).lower() not in _UA_PLACEHOLDERS:
                out[m.group(1)] = m.group(2).strip()
                break
    return out


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

    # raw platform-page paste: nav chrome, agreement prose, an asset table, a CIA
    # objective stated in prose, a hardware-style scope with no host, and a footer.
    # The parser must keep the real items and drop the furniture (synthetic page).
    raw = """Dashboard
    Programs
    logo
    Give feedback
    Rules of engagement
    User agent
    Not applicable
    By participating in this program, you agree to follow the terms and adhere to the scope of the Program.
    Assets
    tier
    All
    Widget Firmware and Utilities
    Other
    No bounty
    In scope
    Give feedback
    See "Report Eligibility Criteria" section.
    Hardware:
    ExampleChip A100 family boards
    Firmware:
    Device firmware embedded in the above hardware elements.
    Out of scope
    Product Category\tBounty\tBonus
    Third-Party Products\tNo\tNo
    Missing security headers
    Issues that require deep physical access to the device are out of scope for bounty rewards.
    End of Life Products
    Severity assessment
    A path to the compromise of confidentiality, integrity, or availability is required.
    FAQ
    When is a bounty awarded?
    Researchers
    logo
    someuser
    © Copyright 2026
    """
    q = compile(raw)
    assert q.forbidden == [], q.forbidden                       # RoE prose is not "forbidden"
    assert q.user_agent == "", q.user_agent                     # "Not applicable" placeholder rejected
    assert not any("participating" in l.lower() for l in q.non_reportable_labels)  # agreement prose gone
    assert "Give feedback" not in q.non_reportable_labels and "logo" not in q.non_reportable_labels
    assert "someuser" not in q.non_reportable_labels            # footer block not parsed
    named = [a.pattern for a in q.assets if not a.network]      # hardware/firmware scope captured
    assert "ExampleChip A100 family boards" in named, named
    assert any("Device firmware embedded" in p for p in named), named
    assert q.scope._inc_dom == [] and q.scope._inc_net == []    # no host scope; nothing crashes
    assert "missing_security_headers" in q.non_reportable       # short mapped exclusion survives
    assert "End of Life Products" in q.non_reportable_labels    # real category survives
    assert not any("physical access" in l.lower() for l in q.non_reportable_labels)  # prose dropped
    assert {"confidentiality", "integrity", "availability"} <= set(q.objectives), q.objectives
    assert q.objective_targets == set()                         # CIA is label-only, drives no rank

    # platform config block: a required request header, a rate, an asset table with
    # type cells, an 'interested in' objective in prose, and a feedback-link false
    # asset (synthetic, not any real program).
    cfg = """Rules of engagement
    Give feedback
    User agent
    Not applicable
    Automated tooling
    max. 3 requests /sec
    Request header
    X-Example: <your-username>
    Assets
    app.example.com
    URL
    Tier 2
    *.example.com
    Wildcard
    In scope
    Give feedback
    Program feedback link
    We're only interested in privilege escalation within the same tenant if you can view another team's data.
    Out of scope
    Missing security headers
    """
    r = compile(cfg)
    assert r.request_headers == {"X-Example": "<your-username>"}, r.request_headers  # header captured
    assert r.rate_per_sec == 3.0, r.rate_per_sec
    assert r.user_agent == "", r.user_agent                     # "Not applicable" is not the UA
    assert r.scope.allows("app.example.com") and r.scope.allows("x.example.com")
    assert not any(not a.network for a in r.assets), [a.pattern for a in r.assets]   # no 'feedback link' junk
    assert not any("URL" in w for w in r.warnings), r.warnings   # 'URL' type cell isn't warned scope
    assert "privilege escalation within the same tenant" in r.objectives, r.objectives
    assert {"admin_interface_exposed", "access-control", "authz"} <= r.objective_targets
    assert "missing_security_headers" in r.non_reportable

    # a placeholder header is surfaced to the operator, never sent as-is
    from . import providers
    assert r.unfilled_headers() == ["X-Example: <your-username>"], r.unfilled_headers()
    r.apply()
    assert providers._ID_HEADERS == {}, providers._ID_HEADERS
    r.request_headers["X-Example"] = "devil748"          # operator filled it in
    r.apply()
    assert providers._ID_HEADERS == {"X-Example": "devil748"} and not r.unfilled_headers()
    providers.set_scope(None), providers.set_rate(), providers.set_headers()   # leave no global set

    # asset table pasted as flat text: a bounty grid that must contribute no tiers, an
    # 'IP Range' row holding a whole block of hosts, a tier cell stacked under each row,
    # and a bounded worst-case list as the objectives (synthetic; RFC 5737 IPs).
    table = """Bounties
    Tier 1
    €
    500
    Tier 3
    €
    50
    Assets
    tier
    All
    api.example.com
    URL
    Tier 1
    198.51.100.4, 198.51.100.5, 203.0.113.9
    IP Range
    Tier 1
    *.shop.example.org
    Wildcard
    Tier 3
    In scope
    Our worst-case scenarios are:
    Command execution on production services.
    Obtaining sensitive user data.
    Out of scope
    Missing security headers
    """
    t = compile(table)
    assert t.warnings == [], t.warnings              # 'IP Range' is a type cell, not a scope line
    # every IP of the block is its own asset, and the row's single tier cell covers them all
    assert {a.pattern: a.tier for a in t.assets} == {
        "api.example.com": 1, "198.51.100.4": 1, "198.51.100.5": 1,
        "203.0.113.9": 1, "*.shop.example.org": 3}, [(a.pattern, a.tier) for a in t.assets]
    assert t.scope.allows("198.51.100.4") and t.scope.allows("203.0.113.9")
    assert not t.scope.allows("198.51.100.6")        # only the listed IPs — no range invented
    # a tier label is asset metadata; it must never surface as an excluded vuln class
    assert not any("tier" in l.lower() for l in t.non_reportable_labels), t.non_reportable_labels
    assert "missing_security_headers" in t.non_reportable and t.non_reportable_labels == [
        "Missing security headers"], t.non_reportable_labels
    # bounded worst-case prose = the program's objectives (an existing model field), and
    # the ones that name a class Argus concludes also drive rank
    assert t.objectives == ["command execution on production services",
                            "obtaining sensitive user data"], t.objectives
    assert not any(not a.network for a in t.assets)  # not mis-recorded as named assets
    assert "vulnerable_service" in t.objective_targets, t.objective_targets
    rce = Conclusion(rule="vulnerable_service", name="RCE", target="api.example.com",
                     confidence=30, ledger={}, kind="risk", tags=["cve"])
    hdr2 = Conclusion(rule="open_redirect", name="Redirect", target="api.example.com",
                      confidence=95, ledger={}, kind="risk", tags=["redirect"])
    ranked, _ = t.filter(InvestigationResult([hdr2, rce], "fp"))
    assert [c.rule for c in ranked.risks] == ["vulnerable_service", "open_redirect"]

    # an asset table whose tier column reads "Out of scope" for ONE row. That cell is
    # row metadata: it excludes its own row and nothing else. Read as a section header
    # instead, it inverts the authorization boundary — the excluded row stays allowed
    # and every row below it is wrongly blocked. The real header must still switch.
    row_cell = """Assets
    tier
    All
    *.example.com
    Wildcard
    Out of scope
    technik.example.org
    URL
    Tier 3
    technik.beta.example.org
    URL
    Tier 3
    In scope
    Our worst-case scenarios are:
    Obtaining sensitive user data.
    Out of scope
    Missing security headers
    """
    x = compile(row_cell)
    assert x.warnings == [], x.warnings
    assert not x.scope.allows("a.example.com")                  # the cell excluded its row
    assert x.scope.allows("technik.example.org"), "row below an 'Out of scope' cell blocked"
    assert x.scope.allows("technik.beta.example.org"), "row below an 'Out of scope' cell blocked"
    assert {a.pattern: (a.tier, a.action) for a in x.assets} == {
        "*.example.com": (None, "none"), "technik.example.org": (3, "active"),
        "technik.beta.example.org": (3, "active")}, [(a.pattern, a.tier, a.action) for a in x.assets]
    # the later bare "Out of scope" is a real header: its body is still an exclusion,
    # and the objective section between them was not swallowed
    assert "missing_security_headers" in x.non_reportable, x.non_reportable
    assert x.objectives == ["obtaining sensitive user data"], x.objectives
    print("policy demo passed")


if __name__ == "__main__":
    demo()
