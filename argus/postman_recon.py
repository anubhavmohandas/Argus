"""Postman workspace mining — Kongsec Stage 1, the ARGUS way.

Public Postman workspaces are, incidentally, one of the largest indexes of real
production tokens on the internet: engineers paste a bearer/api-key into an
environment variable and forget to make the workspace private. This module
searches public workspaces matching a brand/domain, pulls each workspace's
environment/globals JSON, and runs the 48-pattern catalog + shared triage over
it.

Honesty / guardrails:
- Passive w.r.t. the bug-bounty target: it queries Postman (a third party),
  never the target itself.
- Self-reported fragility: these are Postman's *unofficial* `_api` endpoints.
  They can change shape or disappear; every fetch is defensive and the HTTP
  layer is injected so the logic is testable offline.
- NON-GOAL held: a found token is redacted and reported. This module never
  replays it against the target's `/me` / `/whoami` to prove it live — that is
  the recon→unauthorized-access line, and Argus's stated non-goal.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from .core import Finding, module, INFO, q
from .modules import scan_text
from .triage import is_false_positive, redact

_UA = "Argus-Recon/0.1.0"
_PROXY = "https://www.postman.com/_api/ws/proxy"
_WS = "https://www.postman.com/_api/workspace"


def _post_json(url: str, payload: dict, timeout: float = 15.0):
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={
        "User-Agent": _UA, "Content-Type": "application/json", "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
            return json.loads(r.read().decode("utf-8", "replace"))
    except (urllib.error.HTTPError, urllib.error.URLError, ValueError, OSError):
        return None


def _get_json(url: str, timeout: float = 15.0):
    req = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
            return json.loads(r.read().decode("utf-8", "replace"))
    except (urllib.error.HTTPError, urllib.error.URLError, ValueError, OSError):
        return None


def _search_workspaces(brand: str):
    """Query Postman's public search for workspaces matching a brand.
    Returns a list of {id, name, slug, publicHandle} best-effort."""
    payload = {
        "service": "search", "method": "POST", "path": "/search-all",
        "body": {
            "queryText": brand, "domain": "public", "queryIndexType": "runtime",
            "size": 25, "from": 0,
        },
    }
    data = _post_json(_PROXY, payload)
    out = []
    if not data:
        return out
    docs = (((data.get("data") or {}) if isinstance(data, dict) else {}) or {})
    hits = data.get("data") if isinstance(data.get("data"), list) else docs.get("results", [])
    for item in (hits or []):
        doc = item.get("document", item) if isinstance(item, dict) else {}
        ws_id = doc.get("id") or doc.get("workspaceId")
        if ws_id:
            out.append({
                "id": ws_id,
                "name": doc.get("name", ""),
                "slug": doc.get("slug", ""),
                "publicHandle": doc.get("publicHandle", ""),
            })
    return out


def _workspace_text(ws_id: str) -> str:
    """Pull a workspace's environment/globals JSON as scannable text."""
    chunks = []
    for suffix in ("", "/globals"):
        data = _get_json(f"{_WS}/{q(ws_id)}{suffix}")
        if data:
            chunks.append(json.dumps(data))
    return "\n".join(chunks)


def postman_scan(brand: str, *, search=_search_workspaces, fetch=_workspace_text):
    """Core logic, injectable for offline tests. Yields triaged secret Findings
    from public Postman workspaces matching `brand`."""
    seen: set[tuple[str, str]] = set()
    for ws in search(brand):
        ws_id = ws.get("id", "")
        text = fetch(ws_id)
        if not text:
            continue
        handle = ws.get("publicHandle") or f"https://www.postman.com/{ws.get('slug','')}"
        for hit in scan_text(text, source=handle):
            value = str(hit.data.get("match", ""))
            if is_false_positive(value):
                continue
            key = (ws_id, redact(value))
            if key in seen:
                continue
            seen.add(key)
            yield Finding(
                "postman_dork", brand,
                f"{hit.title} leaked in public Postman workspace: {ws.get('name') or ws_id}",
                hit.severity,
                data={
                    "workspace": handle, "workspace_id": ws_id,
                    "secret_type": hit.title, "match_redacted": redact(value),
                    "confidence": 85,
                    "hypothesis": (
                        "A credential in a live provider format sits in a public Postman "
                        "workspace tied to this brand. Treat it as compromised and rotate it; "
                        "inspect the workspace environment to confirm."
                    ),
                },
                source="postman",
            )


@module("postman_dork", kind="domain",
        help="Mine public Postman workspaces for secrets tied to a brand/domain")
def postman_dork(domain: str):
    # brand = the registrable label (example.com -> example) plus the full domain
    brand = domain.split(".")[0] if "." in domain else domain
    found = False
    for q_ in dict.fromkeys([brand, domain]):  # dedupe, keep order
        for f in postman_scan(q_):
            found = True
            yield f
    if not found:
        yield Finding("postman_dork", domain, "no triaged secret exposures in public Postman workspaces",
                      INFO, source="postman")
