"""Investigator Rule Engine — the deterministic brain of the Investigation Engine.

Phase 3.1. Consumes an *immutable* investigation graph and produces conclusions,
each with a confidence score and a full explanation ledger. It never mutates the
graph, executes rule-supplied code, or performs discovery — see
docs/ENGINEERING_PRINCIPLES.md ("The Rule Engine invariant").

Rules are declarative data files (argus/rules/*.toml). A rule may only reference
predicates in the closed vocabulary below (`_PREDICATES`); an unknown predicate,
or any executable-looking key, fails to load. That is the "data must never
become executable" security boundary, enforced at load time.

Determinism (Principle 8): same graph + same rules + same engine => identical
conclusions. `fingerprint()` proves it — no randomness, no hidden state.

occam: predicate vocabulary is a closed dict resolved here, in engine code under
review — the ONLY place new investigator words are added. Rule files just use
them. Derived-facts / forward-chaining is deliberately out of v1.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .core import CRITICAL, HIGH, MEDIUM, LOW, INFO

try:
    import tomllib  # stdlib 3.11+
except ModuleNotFoundError:  # pragma: no cover - engine still runs on inline rules
    tomllib = None

_RULES_DIR = Path(__file__).parent / "rules"

_TOK = re.compile(r"[^a-z0-9]+")


def _tokens(value: str) -> set[str]:
    """Name signals from a hostname's labels, excluding the public suffix.

    The trailing TLD label is never an environment/tech signal: `.dev`, `.app`,
    `.zip` are gTLDs, not deployment hints. Dropping the last label stops
    `app.aikido.dev` reading as a dev environment while keeping the real signal
    in `dev.aikido.com`. Single-label values (bare hostnames, IP octets that
    can't match the word vocabulary anyway) pass through whole.

    occam: drops one label, not a full public-suffix list — `co.uk` leaves a
           harmless `co` that matches nothing. Add a PSL only if a suffix label
           ever collides with the vocabulary.
    """
    labels = value.lower().strip().rstrip(".").split(".")
    if len(labels) >= 2:
        labels = labels[:-1]  # drop the public-suffix / TLD label
    return {t for label in labels for t in _TOK.split(label) if t}


# --- investigator name vocabulary -----------------------------------------
# One home for the name-signal knowledge, two views of it:
#  · _TECH/_ADMIN/_PREPROD/_NOISE feed the name_suggests_* DISCOVERY predicates
#    (categorical: does the name suggest admin? tech? cdn?).
#  · _INTERESTING is the weighted view — how much an investigator should care —
#    that drives the priority output.
#
# THIS TABLE STAYS IN CODE ON PURPOSE. Read Principle 2 ("intelligence lives in
# rules, not the engine") and the obvious next move is to migrate these weights
# into a data file like the rule pack. Do not. `_priority()` is Argus's floor:
# investigate() is specified to answer "where do I look first?" even when the
# rule pack is missing or malformed (see its docstring). A floor whose vocabulary
# lives in a file that can fail to load is not a floor. The rule pack is
# investigator knowledge and belongs in data; this is the last-resort vocabulary
# that has to survive the rule pack being gone, and that is a different job.
#
# occam: overlapping tokens with the sets above, but they answer different
#        questions (is-it-admin vs how-interesting); unify only if they drift.
_TECH = {"jenkins", "gitlab", "grafana", "kibana", "phpmyadmin", "jira", "confluence"}
_ADMIN = {"admin", "portal", "dashboard", "phpmyadmin", "sso"}
_PREPROD = {"staging", "stage", "dev", "uat", "test"}

# tokens meaning "public plumbing, deprioritize" — the CDN-noise bucket.
_NOISE = {
    "cdn", "static", "assets", "img", "images", "media", "www", "edge",
    "cloudfront", "akamai", "fastly", "cachefly", "cdnjs", "gstatic",
}

# token -> (weight, why). Higher weight = an investigator should look sooner.
_INTERESTING: dict[str, tuple[int, str]] = {
    "admin": (5, "admin surface"),
    "internal": (5, "meant to be internal"),
    "vpn": (5, "remote access"),
    "vault": (5, "secrets store"),
    "jenkins": (5, "CI server"),
    "gitlab": (5, "source control"),
    "phpmyadmin": (5, "db admin surface"),
    "git": (4, "source control"),
    "sso": (4, "auth surface"),
    "grafana": (4, "monitoring"),
    "kibana": (4, "log access"),
    "staging": (4, "pre-prod (often weaker)"),
    "stage": (4, "pre-prod (often weaker)"),
    "dev": (4, "dev (often weaker)"),
    "uat": (4, "pre-prod (often weaker)"),
    "corp": (4, "corporate surface"),
    "db": (4, "database surface"),
    "database": (4, "database surface"),
    "sql": (4, "database surface"),
    "backup": (4, "backups"),
    "rdp": (4, "remote desktop"),
    "test": (3, "test (often weaker)"),
    "portal": (3, "app portal"),
    "dashboard": (3, "app dashboard"),
    "jira": (3, "internal tooling"),
    "confluence": (3, "internal wiki"),
    "storage": (3, "object storage"),
    "s3": (3, "object storage"),
    "ftp": (3, "file transfer"),
    "ssh": (3, "remote shell"),
    "api": (2, "api surface"),
    "gateway": (2, "gateway"),
    "mail": (1, "mail infra"),
}

_SEV_WEIGHT = {CRITICAL: 6, HIGH: 4, MEDIUM: 2, LOW: 1, INFO: 0}

# Structural allowlist: exactly these keys, nothing else. A denylist of scary
# words ("python", "eval", ...) only catches what we thought of, and silently
# accepts a typo'd `[[adjustment]]` that then never fires. Everything the
# schema doesn't recognise is a load error.
_ALLOWED_KEYS = {"id", "name", "description", "base_confidence", "tags",
                 "version", "requires", "adjustments", "outputs"}
_ALLOWED_ADJUSTMENT_KEYS = {"if", "add", "subtract"}
_ALLOWED_OUTPUT_KEYS = {"severity", "recommendation", "hypothesis"}


class RuleError(ValueError):
    """A rule file is malformed or references something outside the vocabulary."""


# --- predicate resolvers (the closed vocabulary) --------------------------
# Each resolver reads an entity (+ graph) and returns a value. `requires`
# compares that value to the rule's expected one; `adjustments` use truthiness.
# Resolvers are pure reads — they never write to the entity or graph.
def _ev(name):
    """Evidence-flag predicate: read what a provider asserted about the entity.

    Absent => None (unknown), never False. "Nobody checked" and "checked, it
    isn't" are different claims and Argus must never collapse them — that is
    invariant I-1 (Argus never invents negative evidence).
    """
    return lambda e, g: (getattr(e, "evidence", {}) or {}).get(name)


def _p_publicly_discoverable(e, g):
    """We found it through a public source (DNS, CT, RDAP).

    An observation about our own discovery — NOT a claim the host is
    reachable. A hostname in a CT log may never have resolved.
    """
    return e.type in ("domain", "subdomain", "ip")


def _p_name_suggests_technology(e, g):
    for t in _tokens(e.value):
        if t in _TECH:
            return t
    return None


def _p_name_suggests_admin(e, g):
    return bool(_tokens(e.value) & _ADMIN)


def _p_name_suggests_preprod(e, g):
    return bool(_tokens(e.value) & _PREPROD)


def _p_name_suggests_cdn(e, g):
    return bool(_tokens(e.value) & _NOISE)


# The vocabulary, in two tiers — the distinction is the point.
#
#   DISCOVERY predicates are *observations*: what a public source showed us,
#   or what the hostname itself says. Determinate, because the name is fully
#   known. `name_suggests_admin` is a fact about the name, and says so.
#
#   PROBE predicates are *facts about the host*. Only something that actually
#   checked can establish one, so they are evidence-backed only and stay
#   `unknown` until a provider asserts them. They are never inferred from a
#   name or an entity type.
#
# Keeping these apart is what stops "the hostname contains 'admin'" from being
# reported as "this host has an admin interface" — and it lets confidence
# distinguish suspected from verified.
_PREDICATES = {
    # discovery — observations
    "publicly_discoverable": _p_publicly_discoverable,
    "name_suggests_technology": _p_name_suggests_technology,
    "name_suggests_admin": _p_name_suggests_admin,
    "name_suggests_preprod": _p_name_suggests_preprod,
    "name_suggests_cdn": _p_name_suggests_cdn,
    # probe — facts, evidence-backed only
    "internet_facing": _ev("internet_facing"),
    "technology": _ev("technology"),
    "has_admin_interface": _ev("has_admin_interface"),
    "authentication_required": _ev("authentication_required"),
    "public_exploit": _ev("public_exploit"),
    "known_exploited": _ev("known_exploited"),
    "known_vulnerable_service": _ev("known_vulnerable_service"),
    "certificate_reused": _ev("certificate_reused"),
    # web-exposure facts (owasp_scanner patterns, provider-established)
    "security_headers_missing": _ev("security_headers_missing"),
    "insecure_cookie": _ev("insecure_cookie"),
    "exposed_sensitive_file": _ev("exposed_sensitive_file"),
    "exposed_secret": _ev("exposed_secret"),
    "path_traversal": _ev("path_traversal"),
    "clickjacking": _ev("clickjacking"),
    "cors_misconfig": _ev("cors_misconfig"),
    "graphql_introspection": _ev("graphql_introspection"),
    "subdomain_takeover": _ev("subdomain_takeover"),
    "open_redirect": _ev("open_redirect"),
    "reflected_xss": _ev("reflected_xss"),
    "ssti": _ev("ssti"),
    "email_spoofable": _ev("email_spoofable"),
}
# occam: no dns_resolves / http_reachable / tls_valid / certificate_seen yet —
#        nothing asserts them and no rule reads them. Add each with its probe.


@dataclass
class Conclusion:
    """Every engine output is one of these — there is no second output type.

    `kind` says what sort of investigator statement it is: `risk` comes from a
    rule file, `priority` from the built-in name evaluator below. Both carry the
    same ledger, so both are equally explainable. The set is closed like the
    predicate vocabulary — a rule cannot declare its own kind; a new one arrives
    with the engine code that emits it.

    Confidence is comparable *within* a kind, never across one: a priority is
    100% certain about what a name contains, which is not the same claim as a
    risk being 100% certain about a host. Read `.risks` for the confidence band,
    `.priority` for the ranking — never max() over the whole list.
    """
    rule: str
    name: str
    target: str            # the entity value the conclusion is about
    confidence: int        # clamped 0..100 — how sure, never how important
    ledger: dict           # traceable: evidence checks + the arithmetic
    kind: str = "risk"
    target_type: str = ""  # entity type the target is (subdomain/ip/...)
    severity: str = "info" # urgency label the rule attached
    recommendations: list = field(default_factory=list)
    hypotheses: list = field(default_factory=list)
    tags: list = field(default_factory=list)
    rule_version: int = 0  # provenance: which version of the rule concluded this

    @property
    def score(self) -> float:
        """The number this conclusion computed — its confidence for a risk, its
        attention weight for a priority. Always the ledger's own total, so it
        cannot drift away from the arithmetic that produced it."""
        return self.ledger.get("final", self.confidence)

    def to_dict(self) -> dict:
        return {
            "kind": self.kind, "rule": self.rule, "rule_version": self.rule_version,
            "name": self.name, "target": self.target, "target_type": self.target_type,
            "confidence": self.confidence, "severity": self.severity, "score": self.score,
            "ledger": self.ledger, "recommendations": self.recommendations,
            "hypotheses": self.hypotheses, "tags": self.tags,
        }


# --- validation (trust boundary — rule files are data, never code) --------
def _validate_rules(rules: list[dict]) -> None:
    # Shape first. Everything below assumes a list of tables, and a rule set that
    # isn't one must arrive here as a RuleError — investigate() degrades on
    # ValueError, so an uncaught TypeError/AttributeError would crash the
    # investigation instead of falling back to priority. The guarantee is
    # "malformed rules cost you reasoning, never the whole run"; these two lines
    # are what make it true for malformed *containers*, not just malformed rules.
    if not isinstance(rules, list):
        raise RuleError(f"rule set must be a list of tables, got {type(rules).__name__}")
    for r in rules:
        if not isinstance(r, dict):
            raise RuleError(f"rule must be a table, got {type(r).__name__}: {r!r}")
        rid = r.get("id")
        if not rid:
            raise RuleError(f"rule missing 'id': {r!r}")
        bad = set(r) - _ALLOWED_KEYS
        if bad:
            raise RuleError(f"rule {rid!r} has key(s) outside the rule schema: {sorted(bad)}")
        for adj in r.get("adjustments", []):
            bad = set(adj) - _ALLOWED_ADJUSTMENT_KEYS
            if bad:
                raise RuleError(f"rule {rid!r} adjustment has unknown key(s): {sorted(bad)}")
        bad = set(r.get("outputs", {})) - _ALLOWED_OUTPUT_KEYS
        if bad:
            raise RuleError(f"rule {rid!r} outputs has unknown key(s): {sorted(bad)}")
        base = r.get("base_confidence", 0)
        if not isinstance(base, int) or not 0 <= base <= 100:
            raise RuleError(f"rule {rid!r} base_confidence must be an int 0..100, got {base!r}")
        preds = set(r.get("requires", {})) | {a.get("if") for a in r.get("adjustments", [])}
        unknown = preds - set(_PREDICATES)
        if unknown:
            raise RuleError(f"rule {rid!r} uses predicates outside the vocabulary: {sorted(unknown)}")


def load_rules(rules_dir=None) -> list[dict]:
    """Load + validate every *.toml rule. occam: TOML via stdlib tomllib — no dep,
    and a format that structurally cannot carry code. 3.11+ for file loading."""
    if tomllib is None:
        raise RuleError("loading rule files needs Python 3.11+ (tomllib); pass rules to evaluate() directly otherwise")
    d = Path(rules_dir) if rules_dir else _RULES_DIR
    rules = []
    for fp in sorted(d.glob("*.toml")):
        with open(fp, "rb") as fh:
            rules.append(tomllib.load(fh))
    _validate_rules(rules)
    return rules


# --- evaluation -----------------------------------------------------------
def _requirement_met(pred: str, expected, e, g) -> bool | None:
    """True / False / None, where None means 'nobody established this'.

    I-1: silence never satisfies a requirement. A rule asking for
    `authentication_required = false` must NOT fire on a host no one ever
    probed — that would be Argus concluding a negative it never checked.
    """
    actual = _PREDICATES[pred](e, g)
    if actual is None:
        return None
    if isinstance(expected, bool):
        return bool(actual) == expected
    return str(actual).lower() == str(expected).lower()


def _evaluate_rule(rule: dict, e, g) -> Conclusion | None:
    """Fire `rule` against entity `e` if its requirements hold; else None."""
    evidence = []
    for pred, expected in sorted(rule.get("requires", {}).items()):
        met = _requirement_met(pred, expected, e, g)
        evidence.append({"predicate": pred, "expected": expected, "met": met})
        if met is not True:
            return None  # failed (False) or unestablished (None) — rule does not fire

    base = int(rule.get("base_confidence", 0))
    calc = [{"step": "base", "delta": base}]
    conf = base
    for adj in rule.get("adjustments", []):
        pred = adj["if"]
        delta = int(adj.get("add", 0)) - int(adj.get("subtract", 0))
        actual = _PREDICATES[pred](e, g)
        applied = None if actual is None else bool(actual)   # None = never checked
        evidence.append({"predicate": pred, "applied": applied, "delta": delta})
        if applied:
            conf += delta
            calc.append({"step": pred, "delta": delta})
    final = max(0, min(100, conf))  # clamp — confidence never exceeds evidence

    out = rule.get("outputs", {})
    return Conclusion(
        rule=rule["id"], rule_version=int(rule.get("version", 0)), kind="risk",
        name=rule.get("name", rule["id"]), target=e.value, target_type=e.type,
        confidence=final, severity=out.get("severity", "info"),
        ledger={"evidence": evidence, "calculation": calc, "final": final},
        recommendations=list(out.get("recommendation", [])),
        hypotheses=list(out.get("hypothesis", [])),
        tags=list(rule.get("tags", [])),
    )


def evaluate(g, rules=None) -> list[Conclusion]:
    """Read-only pass over the graph → deterministic conclusions with ledgers.

    One graph, one walk: for each entity, each rule that fires. No recursion,
    no mutation of `g`. Deterministic order: entities by key, rules by id,
    conclusions ranked by (confidence desc, target, rule)."""
    rules = rules if rules is not None else load_rules()
    _validate_rules(rules)
    rules = sorted(rules, key=lambda r: r["id"])
    entities = sorted(g.nodes.values(), key=lambda e: e.key)

    out = []
    for e in entities:
        for rule in rules:
            c = _evaluate_rule(rule, e, g)
            if c is not None:
                out.append(c)
    out.sort(key=lambda c: (-c.confidence, c.target, c.rule))
    return out


# --- reproducibility (Principle 8) ----------------------------------------
def _graph_digest(g) -> dict:
    """Canonical, sorted view of the evidence that conclusions depend on."""
    return {
        "nodes": sorted(
            [e.type, e.value.lower(), sorted((getattr(e, "evidence", {}) or {}).items())]
            for e in g.nodes.values()
        ),
        "edges": sorted([s, r, d] for (s, r, d) in getattr(g, "edges", [])),
        "findings": sorted([f.module, f.target.lower(), f.title, f.severity] for f in g.findings),
    }


def fingerprint(g, rules=None) -> str:
    """sha256 over (graph evidence + rule set). Same inputs => same hash =>
    same conclusions. This is the reproducibility guarantee, made checkable."""
    rules = rules if rules is not None else load_rules()
    payload = json.dumps({"graph": _graph_digest(g), "rules": sorted(rules, key=lambda r: r.get("id", ""))},
                         sort_keys=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


# --- rendering (used by the dossier) --------------------------------------
_MARK = {True: "✓", False: "✗", None: "?"}   # ? = nobody established this (I-1)


def ledger_lines(c: Conclusion) -> list[str]:
    """The explanation ledger as compact human lines — nothing hidden.

    Three marks, not two: `?` means unchecked, and never reads as a negative.
    """
    ev, unknown = [], []
    for chk in c.ledger["evidence"]:
        if "met" in chk:
            state = chk["met"]
            ev.append(f"{_MARK[state]} {chk['predicate']}={chk['expected']}")
        else:
            state = chk["applied"]
            sign = f"({'+' if chk['delta'] >= 0 else ''}{chk['delta']})"
            ev.append(f"{_MARK[state]} {chk['predicate']}{sign}")
        if state is None:
            unknown.append(chk["predicate"])
    calc = " ".join(
        (f"{s['delta']}" if s["step"] == "base" else f"{'+' if s['delta'] >= 0 else ''}{s['delta']}")
        for s in c.ledger["calculation"]
    )
    lines = [f"why:  {'  '.join(ev)}", f"calc: {calc} = {c.ledger['final']}"]
    if unknown:
        # unknowns aren't noise — each one is the next thing worth checking,
        # and each is a number this confidence does NOT account for.
        lines.append(f"open: not established — {', '.join(unknown)}")
    return lines


# --- priority (an investigator conclusion, not a second output type) ------
def _priority(g) -> list[Conclusion]:
    """Rank every entity by how much it deserves attention → priority-kind
    conclusions ("200 CDN, ignore; 4 admin portals, look first"). Pure read over
    the graph — like the whole engine, it never mutates a node.

    Confidence is 100 and the ranking rides on `score`, because those are two
    different claims: what a fully-known name contains is certain, how much it
    deserves attention is a weight. Collapsing them would make "look here first"
    read as "I am only 5% sure", which is not what the ledger says.

    The ledger has the same shape as a rule conclusion's, so the score is as
    traceable as any confidence — no opaque number reaches a consumer (I-2)."""
    findings_by_target: dict[str, list] = {}
    for f in g.findings:
        findings_by_target.setdefault(f.target.lower(), []).append(f)

    out = []
    for e in g.nodes.values():
        toks = _tokens(e.value)
        matched = sorted(toks & _INTERESTING.keys())
        noise = bool(toks & _NOISE)
        evidence = [{"predicate": f"name:{t}", "applied": True, "delta": _INTERESTING[t][0]}
                    for t in matched]
        if noise:
            evidence.append({"predicate": "name:cdn/static", "applied": True, "delta": -3})
        for f in findings_by_target.get(e.value.lower(), []):
            weight = _SEV_WEIGHT.get(f.severity, 0)
            if weight:   # an info finding moves nothing — don't pad the ledger with zeros
                evidence.append({"predicate": f"finding:{f.severity}", "applied": True, "delta": weight})
        score = float(sum(chk["delta"] for chk in evidence))
        why = ", ".join(dict.fromkeys(_INTERESTING[t][1] for t in matched))
        if not why:
            why = "public CDN/static plumbing" if noise else "nothing notable in the name"
        out.append(Conclusion(
            rule="name_priority", kind="priority", name=why,
            target=e.value, target_type=e.type, confidence=100,
            ledger={"evidence": evidence,
                    "calculation": [{"step": "base", "delta": 0}]
                                   + [{"step": c["predicate"], "delta": c["delta"]} for c in evidence],
                    "final": score},
            tags=["noise"] if noise else [],
        ))
    out.sort(key=lambda c: (-c.score, c.target))   # deterministic
    return out


# --- the one result object every consumer reads ---------------------------
@dataclass
class InvestigationResult:
    """The single object the dossier, JSON output, an API, or NYX all consume —
    never engine internals. Everything the Rule Engine concluded about a graph.

    One list, one type. Every output is a Conclusion and the `kind` says what
    sort; the views below are filters over that list, never parallel state."""
    conclusions: list          # every Conclusion: risks (confidence desc), then priorities (score desc)
    fingerprint: str           # reproducibility hash of (graph + rules)
    error: str = ""            # why reasoning degraded, if it did — see investigate()

    def of_kind(self, kind: str) -> list:
        return [c for c in self.conclusions if c.kind == kind]

    @property
    def risks(self) -> list:
        """What the rule pack concluded, ranked by confidence."""
        return self.of_kind("risk")

    @property
    def priority(self) -> list:
        """Every entity ranked by how much it deserves attention."""
        return self.of_kind("priority")

    @property
    def interesting(self) -> list:
        """What to look at first: scored above zero and not plumbing."""
        return [c for c in self.priority if c.score > 0 and "noise" not in c.tags]

    @property
    def noise(self) -> list:
        return [c for c in self.priority if "noise" in c.tags]

    @property
    def recommendations(self) -> list:
        """Deduped, in confidence order — flattened from the conclusions."""
        seen: list = []
        for c in self.conclusions:
            for r in c.recommendations:
                if r not in seen:
                    seen.append(r)
        return seen

    def to_dict(self) -> dict:
        return {
            "conclusions": [c.to_dict() for c in self.conclusions],
            "recommendations": self.recommendations,
            "fingerprint": self.fingerprint,
            "error": self.error,
        }


def investigate(g, rules=None) -> InvestigationResult:
    """Reason over a discovered graph → one InvestigationResult. The only
    reasoning entry point; discovery (pivot) hands its graph here.

    Degrades to name-based priority if the rule set is unavailable or malformed
    — a broken rule set must not blank out a live investigation. But the failure
    is *carried*, on `.error`, and every consumer shows it: a malformed rule file
    turning into "zero conclusions" would be a config bug reported as a clean
    result, which is exactly the false negative Argus must never produce.

    Note where `_priority(g)` sits: outside the try, in engine code, on every
    path. That — not its shape in the result — is what makes it the floor."""
    risks: list = []
    fp = error = ""
    try:
        rules = rules if rules is not None else load_rules()
        risks = evaluate(g, rules)
        fp = fingerprint(g, rules)
    except (ValueError, OSError) as e:   # RuleError is a ValueError — degrade, never silently
        error = f"{type(e).__name__}: {e}"
    return InvestigationResult(conclusions=risks + _priority(g), fingerprint=fp, error=error)
