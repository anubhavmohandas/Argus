"""GitHub organisation + git-history secret scan — Kongsec Stage 2, deeper than
code-search.

`github_dork` searches the CURRENT state of public code. But the Kongsec case
log puts ~85% of confirmed credential finds in COMMIT HISTORY: a secret added in
commit 42 and "removed" in commit 43 is still there for anyone who clones. This
module enumerates a target org's public repos, shallow-clones them (depth 50 —
enough to catch recently-removed secrets without pulling all history), runs
`git log -p`, and scans the added lines with the 48-pattern catalog + triage.

Tradeoff flagged honestly: this module is NOT pure-stdlib — it shells out to
`git`. That breaks Argus's "stdlib-only core" for this one module, which is why
it lives in its own file and degrades gracefully when `git` is missing. The clone
touches GitHub, never the bug-bounty target, so it stays passive w.r.t. the
target. Needs GITHUB_TOKEN to enumerate repos.

NON-GOAL held: finds and proves; never uses a discovered credential anywhere.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request

from .core import Finding, module, INFO, q
from .modules import scan_text
from .triage import is_false_positive, redact

_UA = "Argus-Recon/0.1.0"
_API = "https://api.github.com"


def _gh_get(url: str, token: str, timeout: float = 15.0):
    req = urllib.request.Request(url, headers={
        "User-Agent": _UA, "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}", "X-GitHub-Api-Version": "2022-11-28",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
            return json.loads(r.read().decode("utf-8", "replace"))
    except (urllib.error.HTTPError, urllib.error.URLError, ValueError, OSError):
        return None


def _list_repos(org: str, token: str, max_repos: int = 10):
    """Public repo clone URLs for an org (falls back to a user account)."""
    for kind in ("orgs", "users"):
        data = _gh_get(f"{_API}/{kind}/{q(org)}/repos?per_page={max_repos}&type=public&sort=pushed", token)
        if isinstance(data, list) and data:
            return [r["clone_url"] for r in data if not r.get("fork") and r.get("clone_url")][:max_repos]
    return []


def _history_text(clone_url: str, depth: int = 50, timeout: int = 120) -> str:
    """Shallow-clone a repo and return its `git log -p` diff text. '' on failure
    or if git is unavailable."""
    if not shutil.which("git"):
        return ""
    tmp = tempfile.mkdtemp(prefix="argus_gh_")
    try:
        r = subprocess.run(
            ["git", "clone", "--quiet", "--depth", str(depth), clone_url, tmp],
            capture_output=True, timeout=timeout,
        )
        if r.returncode != 0:
            return ""
        log = subprocess.run(
            ["git", "-C", tmp, "log", "-p", "--all", f"--max-count={depth}"],
            capture_output=True, timeout=timeout, text=True, errors="replace",
        )
        return log.stdout or ""
    except (subprocess.SubprocessError, OSError):
        return ""
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def github_org_scan(org: str, token: str, *, list_repos=_list_repos, history=_history_text):
    """Core logic, injectable for offline tests. Yields triaged secret Findings
    from the commit history of an org's public repos."""
    seen: set[tuple[str, str]] = set()
    for clone_url in list_repos(org, token):
        repo = clone_url.rsplit("/", 1)[-1].removesuffix(".git")
        text = history(clone_url)
        if not text:
            continue
        # only consider added lines (diff '+'), where a committed secret lives
        added = "\n".join(ln[1:] for ln in text.splitlines() if ln.startswith("+") and not ln.startswith("+++"))
        for hit in scan_text(added, source=f"{org}/{repo} (history)"):
            value = str(hit.data.get("match", ""))
            if is_false_positive(value):
                continue
            key = (repo, redact(value))
            if key in seen:
                continue
            seen.add(key)
            yield Finding(
                "github_org", org,
                f"{hit.title} in git history: {org}/{repo}",
                hit.severity,
                data={
                    "repository": f"https://github.com/{org}/{repo}",
                    "secret_type": hit.title, "match_redacted": redact(value),
                    "confidence": 85,
                    "hypothesis": (
                        "A credential in a live provider format exists in this repo's commit "
                        "history (possibly 'removed' in a later commit but never rewritten). "
                        "Anyone who clones can recover it — rotate and purge from history."
                    ),
                },
                source="github",
            )


@module("github_org", kind="domain",
        help="Scan a target org's public-repo COMMIT HISTORY for secrets (needs GITHUB_TOKEN + git)")
def github_org(domain: str):
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        yield Finding("github_org", domain,
                      "GITHUB_TOKEN not set — repo enumeration requires auth; skipping",
                      INFO, source="github")
        return
    if not shutil.which("git"):
        yield Finding("github_org", domain,
                      "git not found on PATH — github_org needs git to clone history; skipping",
                      INFO, source="github")
        return
    org = domain.split(".")[0] if "." in domain else domain
    found = False
    for f in github_org_scan(org, token):
        found = True
        yield f
    if not found:
        yield Finding("github_org", domain, f"no triaged secrets in {org}'s public repo history",
                      INFO, source="github")
