"""JavaScript-bundle secret extraction — frontend JS is the third of the three
artefacts that leak first (after Postman and GitHub).

Passive by design (I-5): this module pulls archived `.js` / `.js.map` URLs from
the Wayback Machine and scans the ARCHIVED copies — it never fetches from the
live bug-bounty target. That keeps it inside the passive tier, same as the
`wayback` and `subdomains` modules. A live-target JS scan (current bundles,
source-map reconstruction) belongs at the `--probe` tier as a provider; this
module is the honest passive slice and says so.

Reuses the 48-pattern catalog + shared triage. Secrets are redacted; nothing is
validated against any service.
"""
from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request

from .core import Finding, module, INFO, q
from .modules import scan_text
from .triage import is_false_positive, redact

_UA = "Argus-Recon/0.1.0"


def _cdx_js(domain: str, timeout: float = 25.0, limit: int = 200):
    """Archived .js / .map URLs for a domain via Wayback CDX (newest-ish first)."""
    import json
    url = (f"https://web.archive.org/cdx/search/cdx?url=*.{q(domain)}/*"
           f"&output=json&fl=timestamp,original&filter=original:.*\\.(js|map)$"
           f"&collapse=urlkey&limit={limit}")
    req = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
            data = json.loads(r.read().decode("utf-8", "replace"))
    except (urllib.error.HTTPError, urllib.error.URLError, ValueError, OSError):
        return []
    out = []
    for row in (data[1:] if data and len(data) > 1 else []):  # row 0 = header
        ts, original = row[0], row[1]
        out.append(f"https://web.archive.org/web/{ts}id_/{original}")
    return out


def _fetch(url: str, timeout: float = 20.0, cap: int = 2 * 1024 * 1024) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
            return r.read(cap).decode("utf-8", "replace")
    except (urllib.error.HTTPError, urllib.error.URLError, OSError):
        return ""


def jsmap_scan(domain: str, *, list_js=_cdx_js, fetch=_fetch, max_files: int = 40):
    """Core logic, injectable for offline tests. Yields triaged secret Findings
    from archived JS/source-map files for `domain`."""
    seen: set[str] = set()
    urls = list_js(domain)[:max_files]
    for u in urls:
        body = fetch(u)
        if not body:
            continue
        # the original (non-archive) URL, for the report
        origin = u.split("id_/", 1)[-1] if "id_/" in u else u
        for hit in scan_text(body, source=origin):
            value = str(hit.data.get("match", ""))
            if is_false_positive(value):
                continue
            red = redact(value)
            if red in seen:
                continue
            seen.add(red)
            yield Finding(
                "jsmap", domain,
                f"{hit.title} in JS bundle: {urllib.parse.urlsplit(origin).path.rsplit('/', 1)[-1]}",
                hit.severity,
                data={
                    "js_url": origin, "archived_url": u,
                    "secret_type": hit.title, "match_redacted": red,
                    "line": hit.data.get("line"), "confidence": 80,
                    "hypothesis": (
                        "A credential in a live provider format is shipped in this site's "
                        "JavaScript bundle (archived copy). Client-side code is public; treat "
                        "it as exposed and rotate it."
                    ),
                },
                source="wayback",
            )


@module("jsmap", kind="domain",
        help="Extract secrets from a site's archived JS/source-map bundles (passive, via Wayback)")
def jsmap(domain: str):
    found = False
    for f in jsmap_scan(domain):
        found = True
        yield f
    if not found:
        yield Finding("jsmap", domain, "no triaged secrets in archived JS bundles", INFO,
                      source="wayback")
