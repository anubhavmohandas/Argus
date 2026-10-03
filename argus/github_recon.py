"""GitHub secret-recon module — find credentials leaked in public GitHub code
that reference a target domain, triage out the false positives, and prove each
hit against the live RAW file.

The ARGUS way, honestly:
- REUSES the 48-pattern catalog (modules.scan_text) and the shared triage
  helpers (triage.py) — no second copy of the predicates or the FP logic.
- Self-gating (I-3): a finding is only claimed when the fetched RAW file at HEAD
  of that commit STILL contains a value in a real provider format (AKIA…, ghp_…,
  sk_live_…). A soft result (file gone / force-pushed) is never a positive.
- Passive w.r.t. the bug-bounty target: it searches PUBLIC GitHub (a third party),
  never the target. Needs GITHUB_TOKEN because code-search requires auth.

NON-GOAL held deliberately: finds and PROVES exposure; never uses a discovered
third-party credential against its vendor's API. The generated curl only
re-fetches the RAW GitHub file for the analyst to read.
"""
from __future__ import annotations

import os
import urllib.error
import urllib.request

from .core import Finding, module, INFO, q
from .modules import scan_text
from .triage import shannon_entropy, is_false_positive, redact  # noqa: F401 (re-exported)

_UA = "Argus-Recon/0.1.0"
_API = "https://api.github.com/search/code"

# Dork keywords paired with the target domain. Bounded — GitHub's authenticated
# code-search allows ~10 req/min, so this is budget-limited like admin_probe.
_DORKS = [
    "aws_secret_access_key", "api_key", "client_secret", "access_token",
    "jwt_secret", "db_password", "secret_token", "filename:.env",
]


def _gh_get(url: str, token: str, timeout: float = 15.0):
    """Authenticated GET against the GitHub API → parsed JSON or None."""
    import json
    req = urllib.request.Request(url, headers={
        "User-Agent": _UA,
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
            return json.loads(r.read().decode("utf-8", "replace"))
    except (urllib.error.HTTPError, urllib.error.URLError, ValueError, OSError):
        return None


def _raw_get(url: str, timeout: float = 15.0) -> tuple[int, str]:
    req = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
            return r.status, r.read(512 * 1024).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except (urllib.error.URLError, OSError):
        return 0, ""


def _raw_url(html_url: str) -> str:
    """github.com/owner/repo/blob/<ref>/path → raw.githubusercontent.com/owner/repo/<ref>/path"""
    return html_url.replace("https://github.com/", "https://raw.githubusercontent.com/", 1).replace("/blob/", "/", 1)


def github_dork_scan(domain: str, token: str, *, gh_get=_gh_get, raw_get=_raw_get,
                     max_hits_per_dork: int = 5):
    """Core logic, dependency-injected so tests run offline. Yields Findings for
    triaged, self-gated secret exposures referencing `domain`."""
    seen: set[tuple[str, str]] = set()
    for dork in _DORKS:
        query = f'"{domain}" {dork}'
        data = gh_get(f"{_API}?q={q(query)}&per_page={max_hits_per_dork}", token)
        if not data or "items" not in data:
            continue
        for item in data["items"][:max_hits_per_dork]:
            html_url = item.get("html_url", "")
            if not html_url:
                continue
            repo = (item.get("repository") or {}).get("full_name", "")
            path = item.get("path", "")
            raw = _raw_url(html_url)
            status, body = raw_get(raw)
            if status != 200 or not body:
                continue  # file gone / force-pushed / private → cannot self-gate
            for hit in scan_text(body, source=raw):
                value = str(hit.data.get("match", ""))
                if is_false_positive(value):
                    continue
                key = (raw, redact(value))
                if key in seen:
                    continue
                seen.add(key)
                yield Finding(
                    "github_dork", domain,
                    f"{hit.title} leaked in public GitHub: {repo}",
                    hit.severity,
                    data={
                        "repository": f"https://github.com/{repo}" if repo else "",
                        "raw_url": raw, "file": path, "dork": dork,
                        "secret_type": hit.title, "match_redacted": redact(value),
                        "line": hit.data.get("line"),
                        "verify_cmd": f"curl -sS '{raw}'",
                        "confidence": 90,
                        "hypothesis": (
                            "A credential in a live provider format is committed to a public "
                            "GitHub repo that references this domain. Treat it as compromised "
                            "and rotate it; confirm with the RAW URL above."
                        ),
                    },
                    source="github",
                )


@module("github_dork", kind="domain",
        help="Find secrets leaked in public GitHub code that reference a domain (needs GITHUB_TOKEN)")
def github_dork(domain: str):
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        yield Finding("github_dork", domain,
                      "GITHUB_TOKEN not set — GitHub code search requires auth; skipping",
                      INFO, source="github")
        return
    found = False
    for f in github_dork_scan(domain, token):
        found = True
        yield f
    if not found:
        yield Finding("github_dork", domain, "no triaged secret exposures found on GitHub",
                      INFO, source="github")
