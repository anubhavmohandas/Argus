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
    observed: dict = field(default_factory=dict)  # non-predicate facts a provider saw (e.g. version) — input for OTHER providers, invisible to the engine

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
                       "evidence": e.evidence, "observed": e.observed}
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


def pivot(seed: str, budget: Budget | None = None, on_step=None) -> Graph:
    """on_step(mod_name, value), if given, is called right before each module
    runs — the seam the CLI uses for live progress so a slow crt.sh/RDAP fetch
    doesn't look frozen. It may return a done() callable, which is invoked when
    the module finishes (or fails) so the CLI can stop a spinner. Default None
    keeps the library silent."""
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
            done = on_step(mod_name, ent.value) if on_step else None
            try:
                findings = run_module(mod_name, ent.value)
            except (KeyError, ValueError):
                continue
            finally:
                if done:
                    done()   # stop the spinner whether the module returned, raised, or was ^C'd
            g.findings.extend(findings)
            for f in findings:
                for ctype, cvalue, rel in _extract(f):
                    cvalue = _normalize_child(ctype, cvalue)
                    if cvalue is None:
                        continue  # junk (null-MX "0 .", malformed host, bad IP) — never a node
                    if ctype == "subdomain" and f"domain:{cvalue}" in g.nodes:
                        continue  # apex lists itself among its own SANs — already a
                                  # domain node; re-adding it fires every rule twice
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

    # Evidence summary: what kinds of evidence we actually hold. Passive rows
    # (DNS/RDAP/subdomains) come from discovery findings; active rows come from
    # what providers observed. When the active rows are all 0 the "no predicate
    # fired" outcome explains itself — passive DNS alone can't trip a service rule.
    ev: dict[str, int] = {}
    for f in g.findings:
        label = f"DNS {f.data['type']}" if f.module == "dns" and f.data.get("type") else f.module
        ev[label] = ev.get(label, 0) + 1
    active = {"Ports": 0, "Services": 0, "CVEs": 0, "Probed hosts": 0}
    for e in g.nodes.values():
        active["Ports"] += len(e.observed.get("open_ports", []))
        active["Services"] += len(e.observed.get("services", []))
        active["CVEs"] += len(e.observed.get("cves", []))
        active["Probed hosts"] += 1 if e.evidence else 0
    lines.append("\n EVIDENCE SUMMARY  (what was collected)")
    for label in sorted(ev):
        lines.append(f"   {label:<16} {ev[label]:>3}")
    for label, n in active.items():   # always shown — a 0 here is the point
        lines.append(f"   {label:<16} {n:>3}")

    # Always print PRIORITY + CONCLUSIONS, even when empty: silently ending after
    # FINDINGS reads as "Argus stopped halfway". Empty = engine ran, nothing fired.
    top_p = result.interesting[:10]
    lines.append("\n PRIORITY  (what an investigator looks at first)")
    if top_p:
        for p in top_p:
            lines.append(f"   [{p.score:>4.0f}] {p.target_type:<9} {p.target:<34} {p.name}")
        if result.noise:
            lines.append(f"   deprioritized (CDN/static/plumbing): {len(result.noise)}")
    else:
        depr = f" ({len(result.noise)} deprioritized as CDN/static/plumbing)" if result.noise else ""
        lines.append(f"   — no entity exceeded the prioritization threshold{depr}.")

    concl = [c for c in result.risks if "noise" not in c.tags]
    lines.append("\n INVESTIGATOR CONCLUSIONS  (deterministic — every score is traceable)")
    if concl:
        for c in concl[:8]:
            star = "★ " if "objective" in c.tags else ""   # matches a program objective (policy overlay)
            lines.append(f"   [{c.confidence:>3}%] {c.target:<34} {star}{c.name}  · severity: {c.severity}")
            for l in ledger_lines(c):
                lines.append(f"          {l}")
            for h in c.hypotheses:
                lines.append(f"          ↳ hypothesis: {h}")
            for r in c.recommendations:
                lines.append(f"          ↳ recommend:  {r}")
    else:
        # Three distinct empty states — collapsing them misleads the analyst,
        # because each implies a different next action:
        #   noise      → evidence matched, but only plumbing/CDN
        #   predicated → actionable evidence exists, no rule fired
        #   passive    → evidence exists but none of it is a predicate
        #   nothing    → no evidence at all
        noisy = len(result.risks)
        has_predicates = any(e.evidence for e in g.nodes.values())
        if noisy:
            why = f"all {noisy} matched conclusion(s) were plumbing/CDN noise"
        elif has_predicates:
            why = "no collected evidence matched any investigation predicate"
        elif g.findings:
            why = "collected evidence was informational only — no actionable predicate set"
        else:
            why = "no evidence was collected"
        lines.append(f"   — no rule matched the current evidence: {why}.")
        lines.append("     observed infrastructure appears consistent with normal public exposure.")
        lines.append("     no high-confidence investigative lead generated.")
        if not has_predicates:
            lines.append("     tip: run Active mode (2–4) to probe hosts for predicate evidence.")

    # Leaked secrets: the exposed-file probe recovered a real file whose body
    # carried a live-format credential. Redacted to a preview — Argus proves the
    # leak without re-leaking it. Highest-urgency thing on the page, so it sits
    # right under the conclusions.
    leaked = sorted((e.value, e.observed["secrets"]) for e in g.nodes.values()
                    if e.observed.get("secrets"))
    if leaked:
        lines.append("\n LEAKED SECRETS  (recovered from an exposed file — redacted)")
        for host, secrets in leaked:
            for s in secrets:
                lines.append(f"   [{s.get('severity', 'info'):<8}] {host:<30} {s['type']}  {s['preview']}")

    # Port map: what the TCP scan saw, per host. open ports carry their service +
    # version; filtered (firewall/CDN dropped us) and closed (refused) are the
    # distinction that matters on a modern host, so both are shown, not collapsed.
    scanned = sorted((e.value, e.observed) for e in g.nodes.values()
                     if e.observed.get("scanned"))
    if scanned:
        lines.append("\n PORT SCAN")
        for host, obs in scanned:
            total = obs.get("scanned", 0)
            openp, filt = obs.get("open_ports", []), obs.get("filtered_ports", [])
            closed = total - len(openp) - len(filt)
            lines.append(f"   {host}  ({total} scanned: {len(openp)} open, "
                         f"{len(filt)} filtered, {closed} closed)")
            svc = {s["port"]: s for s in obs.get("services", [])}
            for p in openp:
                s = svc.get(p, {})
                ver = f"  {s['product']} {s.get('version') or ''}".rstrip() if s.get("product") else ""
                lines.append(f"      {p:>5}/tcp  open{ver}")
            if filt:
                shown = ", ".join(str(p) for p in filt[:16])
                more = f"  (+{len(filt) - 16} more)" if len(filt) > 16 else ""
                lines.append(f"      filtered: {shown}{more}")

    # Known CVEs: the port scan's payoff, read straight from observed['cves'].
    # Rule conclusions carry the risk; the specific CVE ids/versions live here.
    cve_hosts = sorted((e.value, e.observed["cves"]) for e in g.nodes.values()
                       if e.observed.get("cves"))
    if cve_hosts:
        lines.append("\n KNOWN CVEs  (observed service version matched a known CVE)")
        for host, cves in cve_hosts:
            for c in cves:
                flags = [f for f, on in (("KEV", c.get("known_exploited")),
                                         ("public-exploit", c.get("public_exploit"))) if on]
                tag = f"  [{', '.join(flags)}]" if flags else ""
                port = f":{c['port']}" if c.get("port") else ""
                lines.append(f"   [{c.get('severity', 'info'):<8}] {host}{port}  {c['cve']}  "
                             f"{c['product']} {c.get('version') or '?'}  {c['summary']}{tag}")
                # References: the advisories / PoCs / write-ups NVD carries for the
                # CVE — "how it was used", for the human and NYX to read, never fired.
                for u in (c.get("references") or [])[:3]:
                    lines.append(f"              ↳ {u}")

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

    # Disclosure: where the target says to report. Not a finding — the opposite of
    # one — so it lives at the bottom, the "now file it" line after the findings.
    for host, sec in sorted((e.value, e.observed["security_txt"]) for e in g.nodes.values()
                            if e.observed.get("security_txt")):
        contacts = ", ".join(sec.get("contact", [])) or "(no Contact field)"
        lines.append(f"\n DISCLOSURE  {host} publishes security.txt → report to: {contacts}")
        break   # one is enough to tell the operator where to file
    lines.append("═" * 60)
    return "\n".join(lines)


# --- report export --------------------------------------------------------
# The dossier is for the terminal; this is the deliverable. One Markdown file per
# investigation, a section per rule conclusion: what it is, on which host, how sure
# Argus is and why (the same traceable ledger), how it was determined, and what to
# do. The "how determined" line is the provider's method, not a fabricated HTTP
# transcript — Argus doesn't yet persist the exact proving request, and inventing
# one would be a lie in a document meant to be pasted into a submission.
# occam: capturing the raw request/response per conclusion is the upgrade path
#        (providers would stash it in observed); the method + ledger is honest now.
_REPRO = {
    "path_traversal": "Requested a directory-traversal payload for /etc/passwd; the response body returned a real passwd file (a soft-404 cannot forge one).",
    "open_redirect": "Injected an external canary URL into common redirect parameters; a 3xx Location resolved to the exact canary host.",
    "reflected_xss": "Reflected an unescaped <svg/onload> canary through a query parameter — the angle brackets survived, so the HTML was not encoded.",
    "ssti": "Injected {{7*7}} next to a unique marker; the response rendered 49, proving server-side template evaluation, not a literal echo.",
    "exposed_sensitive_file": "Fetched a sensitive path (.git/.env/.DS_Store); the body matched the real file's content signature.",
    "exposed_secret": "The recovered file's body contained a credential in a live provider format (stored redacted).",
    "cors_misconfig": "Sent an arbitrary/null Origin; the server reflected it into Access-Control-Allow-Origin with Access-Control-Allow-Credentials: true.",
    "graphql_introspection": "POSTed a minimal introspection query; the server returned a live __schema result.",
    "subdomain_takeover": "The host served a vendor 'unclaimed name' page for a dangling DNS record — claimable by an attacker.",
    "known_vulnerable_service": "An open service's banner reported a version that matches a catalogued/NVD CVE.",
    "has_admin_interface": "Reached an administrative path that answered as a real admin surface (auth challenge / admin-titled page), differing from this host's not-found shape.",
    "email_spoofable": "The domain publishes no enforced DMARC policy (absent or p=none), so From-header spoofing is not blocked.",
    "insecure_cookie": "A Set-Cookie shipped without the Secure/HttpOnly flags.",
    "security_headers_missing": "The served response omitted core hardening headers (HSTS/CSP/X-Content-Type-Options/X-Frame-Options).",
    "clickjacking": "The response permitted framing — no X-Frame-Options DENY/SAMEORIGIN and no CSP frame-ancestors.",
    "certificate_reused": "The same TLS certificate fingerprint is served by more than one host in the graph.",
}


def _repro_for(c) -> str:
    """The method that established conclusion `c`, read from its own ledger — the
    first satisfied predicate we have a repro note for. Honest by construction: it
    describes what Argus actually did, keyed off the evidence that fired."""
    for chk in c.ledger.get("evidence", []):
        pred = chk.get("predicate")
        if pred in _REPRO and (chk.get("met") or chk.get("applied")):
            return _REPRO[pred]
    return "See the evidence ledger below for the predicates that fired."


def report_markdown(seed: str, g, result) -> str:
    """A bug-bounty-ready Markdown report for one investigation. Consumes only the
    graph + InvestigationResult (never engine internals), same as the dossier."""
    import datetime as _dt
    now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    risks = [c for c in result.risks if "noise" not in c.tags]
    out = [f"# ARGUS report — `{seed}`", "",
           f"*Generated {now}. Deterministic: same evidence + rules → same report "
           f"(fingerprint `{result.fingerprint[:16] or 'n/a'}`).*", ""]
    if result.error:
        out += [f"> ⚠ **Reasoning degraded** — conclusions may be incomplete: {result.error}", ""]

    contacts = next((sec.get("contact", []) for e in g.nodes.values()
                     if (sec := e.observed.get("security_txt"))), [])
    out += ["## Summary", "",
            f"- Entity graph: **{len(g.nodes)}** nodes, **{len(g.edges)}** edges from seed `{seed}`",
            f"- Reportable conclusions: **{len(risks)}**",
            f"- Where to report: {', '.join(contacts) if contacts else '_no security.txt found — check the program page_'}", ""]

    if not risks:
        out += ["## Findings", "", "_No deterministic conclusion was reached. "
                "Run an active tier (`--probe` / `--probe-paths` / `--scan`) to collect evidence._", ""]
        return "\n".join(out)

    out += ["## Findings", ""]
    for i, c in enumerate(risks, 1):
        obj = " · ⭐ matches a program objective" if "objective" in c.tags else ""
        out += [f"### {i}. {c.name} — `{c.target}`  ({c.severity.upper()}, {c.confidence}% confidence){obj}", "",
                f"**Target:** `{c.target}` ({c.target_type})  ·  **Rule:** `{c.rule}` v{c.rule_version}", "",
                "**How Argus determined this**", "", _repro_for(c), "",
                "**Evidence ledger**", "", "```"]
        out += ledger_lines(c)
        out += ["```", ""]
        if c.hypotheses:
            out += ["**Impact hypothesis**", ""] + [f"- {h}" for h in c.hypotheses] + [""]
        if c.recommendations:
            out += ["**Remediation**", ""] + [f"- {r}" for r in c.recommendations] + [""]
    out += ["---", "",
            "*Generated by ARGUS — a deterministic offensive-intelligence engine. "
            "Every finding above carries the evidence that proves it; verify before filing.*"]
    return "\n".join(out)
