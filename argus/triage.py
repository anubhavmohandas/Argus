"""Triage — ARGUS's own deterministic investigation reasoning.

Reasoning happens *during* collection, not only at the end ("200 are CDN,
ignore; 4 are admin portals — high priority"). This is not a placeholder to
be swapped out for an LLM: it is encoded investigator expertise, and it's
ARGUS's job permanently — the tool stays useful with no LLM present. After
every pivot it tags each entity by what its name and findings reveal, scores
how much an investigator should care, and lets the graph surface priorities.
NYX (later) reasons *on top* of this output (prioritize / top_priority /
why); it reads these results, it does not replace them.
"""
from __future__ import annotations

import re

from .core import CRITICAL, HIGH, MEDIUM, LOW, INFO

# token -> (weight, why). Higher weight = an investigator should look sooner.
# occam: name-based heuristic. A staging box can hide behind a boring name;
#        this is the cheap first pass. Upgrade path = NYX / content probing.
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

# tokens meaning "public plumbing, deprioritize" — the CDN-noise bucket.
_NOISE = {
    "cdn", "static", "assets", "img", "images", "media", "www", "edge",
    "cloudfront", "akamai", "fastly", "cachefly", "cdnjs", "gstatic",
}

_SEV_WEIGHT = {CRITICAL: 6, HIGH: 4, MEDIUM: 2, LOW: 1, INFO: 0}

_TOK = re.compile(r"[^a-z0-9]+")


def _tokens(value: str) -> set[str]:
    return {t for t in _TOK.split(value.lower()) if t}


def prioritize(g) -> "object":
    """Score + tag every node from its name and the findings on it. Mutates g."""
    findings_by_target: dict[str, list] = {}
    for f in g.findings:
        findings_by_target.setdefault(f.target.lower(), []).append(f)

    for e in g.nodes.values():
        toks = _tokens(e.value)
        tags: set[str] = set()
        score = 0.0
        for tok in toks & _INTERESTING.keys():
            tags.add(tok)
            score += _INTERESTING[tok][0]
        if toks & _NOISE:
            tags.add("noise")
            score -= 3
        for f in findings_by_target.get(e.value.lower(), []):
            score += _SEV_WEIGHT.get(f.severity, 0)
        e.tags = tags
        e.score = score
    return g


def top_priority(g, n: int = 10) -> list:
    """Highest-scoring entities (score > 0), most-interesting first."""
    ranked = [e for e in g.nodes.values() if e.score > 0]
    ranked.sort(key=lambda e: e.score, reverse=True)
    return ranked[:n]


def why(e) -> str:
    """One-line 'why it matters' derived from an entity's tags."""
    parts = [_INTERESTING[t][1] for t in e.tags if t in _INTERESTING]
    if not parts and "noise" in e.tags:
        return "public CDN/static plumbing"
    return ", ".join(dict.fromkeys(parts))
