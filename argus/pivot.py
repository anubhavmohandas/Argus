"""Argus pivot engine — the part that can't be denied.

Give it ONE seed (domain / ip / username / phone / email). It classifies the
seed, runs the right modules, extracts new entities from what comes back,
pivots into those, and keeps going within a bounded budget — building a single
connected entity graph instead of a pile of disconnected lookups.

This is the asset-graph discipline from Claude-OSINT + the Person-OSINT
"organize → correlate → verify → build profile" workflow, made executable.
Modules are the fuel; this is the engine.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import core
from .core import Finding, run_module, sort_by_severity
from .engine import ledger_lines

# What modules to run for each entity type. Order = cheap/authoritative first.
_PLAN: dict[str, list[str]] = {
    "domain":    ["rdap", "dns", "subdomains"],
    "subdomain": ["dns"],
    "ip":        ["ip"],
    "username":  ["username"],
    "phone":     ["phone"],
    "email":     [],   # expanded into domain + username below, no direct module
}

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_IP_HINT = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$|:")           # ipv4 or ipv6-ish
_PHONE_HINT = re.compile(r"^\+?[\d\s().-]{7,}$")


def classify(seed: str) -> str:
    s = seed.strip()
    if _EMAIL_RE.match(s):
        return "email"
    try:
        core.validate_ip(s)
        return "ip"
    except ValueError:
        pass
    try:
        core.validate_domain(s)
        return "domain"
    except ValueError:
        pass
    if _PHONE_HINT.match(s):
        return "phone"
    return "username"


@dataclass
class Entity:
    type: str
    value: str
    depth: int
    via: str = "seed"          # how we discovered it
    evidence: dict = field(default_factory=dict)  # predicate flags for the rule engine (set by evidence providers)

    @property
    def key(self) -> str:
        return f"{self.type}:{self.value.lower()}"


@dataclass
class Graph:
    nodes: dict[str, Entity] = field(default_factory=dict)
    edges: list[tuple[str, str, str]] = field(default_factory=list)  # (src_key, rel, dst_key)
    findings: list[Finding] = field(default_factory=list)

    def add(self, e: Entity, parent: Entity | None = None, rel: str = "") -> bool:
        new = e.key not in self.nodes
        if new:
            self.nodes[e.key] = e
        if parent is not None:
            edge = (parent.key, rel, e.key)
            if edge not in self.edges:
                self.edges.append(edge)
        return new

    def to_dict(self) -> dict:
        """Serialize the whole graph. Used by --json output and the memory store."""
        return {
            "nodes": [{"type": e.type, "value": e.value, "depth": e.depth, "via": e.via,
                       "evidence": e.evidence}
                      for e in self.nodes.values()],
            "edges": [{"src": s, "rel": r, "dst": d} for (s, r, d) in self.edges],
            "findings": [f.to_dict() for f in self.findings],
        }


# --- extraction: turn a module's findings into new entities to pivot into ---
def _extract(finding: Finding) -> list[tuple[str, str, str]]:
    """Return (child_type, child_value, relation) tuples from one finding."""
    out: list[tuple[str, str, str]] = []
    d = finding.data or {}
    m = finding.module

    if m == "dns":
        rtype = d.get("type")
        for rec in d.get("records", []):
            rec = str(rec).rstrip(".")
            if rtype in ("A", "AAAA"):
                out.append(("ip", rec, "resolves_to"))
            elif rtype == "MX":
                host = rec.split()[-1] if rec else ""      # "10 mail.x.com" -> host
                if host:
                    out.append(("domain", host, "mail_server"))
            elif rtype == "NS":
                out.append(("domain", rec, "nameserver"))
    elif m == "rdap":
        for ns in d.get("nameservers", []) or []:
            if ns:
                out.append(("domain", str(ns).rstrip("."), "nameserver"))
    elif m == "subdomains":
        for sub in d.get("subdomains", []) or []:
            out.append(("subdomain", sub, "subdomain_of"))
    elif m == "ip":
        if d.get("domain"):
            out.append(("domain", d["domain"], "reverse_dns"))
    return out


def _normalize_child(ctype: str, value: str) -> str | None:
    """Validate + normalize an extracted entity value. Returns None to drop junk."""
    value = value.strip()
    if ctype in ("domain", "subdomain"):
        try:
            return core.validate_domain(value)   # lowercases + rejects null-MX "0", numeric TLDs
        except ValueError:
            return None
    if ctype == "ip":
        try:
            return core.validate_ip(value)
        except ValueError:
            return None
    return value or None


@dataclass
class Budget:
    max_depth: int = 2
    max_entities: int = 40
    expand_subdomains: int = 0   # how many discovered subdomains to re-pivot (0 = list only)


def pivot(seed: str, budget: Budget | None = None) -> Graph:
    budget = budget or Budget()
    g = Graph()
    root = Entity(classify(seed), seed.strip(), depth=0)

    # email seed fans out into a domain + a username guess (no direct module)
    if root.type == "email":
        g.add(root)
        local, _, dom = seed.partition("@")
        try:
            core.validate_domain(dom)
            g.add(Entity("domain", dom, 1, via="email"), root, "email_domain")
        except ValueError:
            pass
        g.add(Entity("username", local, 1, via="email"), root, "email_local")
    else:
        g.add(root)

    queue = [e for e in g.nodes.values()]
    sub_expanded = 0

    while queue:
        if len(g.nodes) > budget.max_entities:
            break
        ent = queue.pop(0)
        if ent.depth > budget.max_depth:
            continue
        for mod_name in _PLAN.get(ent.type, []):
            try:
                findings = run_module(mod_name, ent.value)
            except (KeyError, ValueError):
                continue
            g.findings.extend(findings)
            for f in findings:
                for ctype, cvalue, rel in _extract(f):
                    cvalue = _normalize_child(ctype, cvalue)
                    if cvalue is None:
                        continue  # junk (null-MX "0 .", malformed host, bad IP) — never a node
                    # occam: bound the subdomain explosion — CT can return
                    #        thousands. Default lists them; --deep re-pivots N.
                    if ctype == "subdomain":
                        if sub_expanded >= budget.expand_subdomains:
                            child = Entity(ctype, cvalue, ent.depth + 2, via=mod_name)
                            g.add(child, ent, rel)   # recorded, not queued
                            continue
                        sub_expanded += 1
                    child = Entity(ctype, cvalue, ent.depth + 1, via=mod_name)
                    if g.add(child, ent, rel) and child.depth <= budget.max_depth:
                        queue.append(child)
    g.findings = sort_by_severity(g.findings)
    return g   # discovery produces the evidence graph; reasoning is engine.investigate(g)


def dossier(g: Graph, result) -> str:
    """Human-readable intelligence brief from a pivot graph + its InvestigationResult.
    Consumes only the result object — never engine internals."""
    lines = ["═" * 60, " ARGUS DOSSIER", "═" * 60]
    if result.error:
        # loud, and above everything: no conclusions here means the rules broke,
        # NOT that there was nothing to conclude.
        lines.append(f"\n ⚠  REASONING DEGRADED — conclusions unavailable: {result.error}")
    by_type: dict[str, list[Entity]] = {}
    for e in g.nodes.values():
        by_type.setdefault(e.type, []).append(e)

    lines.append(f"\n ENTITY GRAPH  ({len(g.nodes)} nodes · {len(g.edges)} edges)")
    for t in ("domain", "subdomain", "ip", "username", "phone", "email", "org", "asn"):
        ents = by_type.get(t)
        if ents:
            vals = ", ".join(sorted(e.value for e in ents)[:12])
            more = f"  (+{len(ents) - 12} more)" if len(ents) > 12 else ""
            lines.append(f"   {t:<10} {len(ents):>3}  {vals}{more}")

    top_p = result.interesting[:10]
    if top_p:
        lines.append("\n PRIORITY  (what an investigator looks at first)")
        for p in top_p:
            lines.append(f"   [{p.score:>4.0f}] {p.type:<9} {p.value:<34} {p.why}")
        if result.noise:
            lines.append(f"   deprioritized (CDN/static/plumbing): {len(result.noise)}")

    concl = [c for c in result.conclusions if c.priority != "noise"]
    if concl:
        lines.append("\n INVESTIGATOR CONCLUSIONS  (deterministic — every score is traceable)")
        for c in concl[:8]:
            lines.append(f"   [{c.confidence:>3}%] {c.target:<34} {c.name}  · priority: {c.priority}")
            for l in ledger_lines(c):
                lines.append(f"          {l}")
            for h in c.hypotheses:
                lines.append(f"          ↳ hypothesis: {h}")
            for r in c.recommendations:
                lines.append(f"          ↳ recommend:  {r}")

    sev_counts: dict[str, int] = {}
    for f in g.findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    lines.append(f"\n FINDINGS  ({len(g.findings)} total)")
    for sev in (core.CRITICAL, core.HIGH, core.MEDIUM, core.LOW, core.INFO):
        if sev_counts.get(sev):
            lines.append(f"   {sev:<10} {sev_counts[sev]}")

    top = [f for f in g.findings if f.severity in (core.CRITICAL, core.HIGH, core.MEDIUM, core.LOW)][:15]
    if top:
        lines.append("\n TOP SIGNALS")
        for f in top:
            lines.append(f"   [{f.severity:<8}] {f.module:<11} {f.title}")
    lines.append("═" * 60)
    return "\n".join(lines)
