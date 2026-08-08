"""Engagement scope — a program's in/out-of-scope allowlist, enforced by the tool.

A bug-bounty program's rules of engagement live in the operator's memory today:
"prod only", "*.example.com in scope, corp.example.com out". This turns those
rules into a file every ACTIVE provider honours, so a target the program excluded
is never touched, no matter what discovery pulled into the graph.

Scope gates provider *engagement with the target* — the HTTP/TLS/TCP probes that
connect to someone else's host. It deliberately does NOT gate passive public
lookups (DNS/CT/RDAP discovery, DMARC over a public resolver): reading a public
record about a domain is not touching it, and that is what keeps discovery able
to map the graph the operator then narrows.

File format (one entry per line; blank lines and `#` comments ignored):

    example.com            # apex + every subdomain (standard bounty semantics)
    *.example.com          # subdomains only (not the apex)
    10.0.0.0/8             # an IP or CIDR block
    203.0.113.7
    !corp.example.com      # exclusion — a leading ! removes a host from scope

Rules: exclusions win over inclusions. If the file lists any inclusion pattern, a
host must match one to be in scope; a file with only exclusions means
"everything except those".
"""
from __future__ import annotations

import ipaddress
from pathlib import Path


class Scope:
    """A parsed engagement scope. `allows(host)` is the one question providers ask."""

    def __init__(self, include: list[str], exclude: list[str]):
        # Split each side into (domain patterns, ip networks) once, at load.
        self._inc_dom, self._inc_net = _split(include)
        self._exc_dom, self._exc_net = _split(exclude)

    def allows(self, host: str) -> bool:
        """Is `host` (a domain, subdomain, or IP string) in scope to be touched?"""
        host = (host or "").strip().lower().rstrip(".")
        if not host:
            return False
        if _matches(host, self._exc_dom, self._exc_net):
            return False                       # exclusion wins, always
        if not self._inc_dom and not self._inc_net:
            return True                        # only-exclusions file => allow the rest
        return _matches(host, self._inc_dom, self._inc_net)


def load(path: str) -> Scope:
    """Parse a scope file into a Scope. Raises ValueError on an unreadable file or
    an entry that is neither a valid domain-pattern nor an IP/CIDR (a bad scope
    file must fail loudly — silently mis-scoping is worse than not scoping)."""
    try:
        text = Path(path).read_text()
    except OSError as e:
        raise ValueError(f"cannot read scope file {path!r}: {e}") from e
    include, exclude = [], []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        target, entry = (exclude, line[1:].strip()) if line.startswith("!") else (include, line)
        if not entry or not _valid_entry(entry):
            raise ValueError(f"scope file {path!r} line {lineno}: not a domain or IP/CIDR: {raw.strip()!r}")
        target.append(entry.lower())
    return Scope(include, exclude)


# --- matching internals ---------------------------------------------------
def _as_net(entry: str):
    """entry -> an ip_network if it is one, else None. A bare IP becomes a /32|/128."""
    try:
        return ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return None


def _valid_entry(entry: str) -> bool:
    if _as_net(entry) is not None:
        return True
    host = entry[2:] if entry.startswith("*.") else entry
    # a domain label set: letters/digits/hyphens in dotted labels
    return bool(host) and all(
        part and all(c.isalnum() or c == "-" for c in part) for part in host.split("."))


def _split(entries: list[str]):
    doms, nets = [], []
    for e in entries:
        net = _as_net(e)
        (nets if net is not None else doms).append(net if net is not None else e)
    return doms, nets


def _matches(host: str, doms: list[str], nets: list) -> bool:
    ip = None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        pass
    if ip is not None:
        return any(ip in net for net in nets)
    for pat in doms:
        if pat.startswith("*."):
            base = pat[2:]
            if host.endswith("." + base):     # subdomains only, never the apex
                return True
        elif host == pat or host.endswith("." + pat):   # apex + any subdomain
            return True
    return False


def demo() -> None:
    s = Scope(include=["example.com", "*.dev.example.org", "10.0.0.0/8"],
              exclude=["corp.example.com"])
    assert s.allows("example.com")
    assert s.allows("api.example.com")
    assert not s.allows("corp.example.com")          # exclusion wins
    assert not s.allows("api.corp.example.com")      # under an excluded host
    assert not s.allows("example.org")               # *.dev only, not apex
    assert s.allows("a.dev.example.org")
    assert not s.allows("dev.example.org")           # wildcard is subdomains only
    assert s.allows("10.1.2.3") and not s.allows("11.0.0.1")
    assert not s.allows("other.com")                 # inclusions present => must match one
    only_excl = Scope(include=[], exclude=["bad.com"])
    assert only_excl.allows("anything.com") and not only_excl.allows("bad.com")
    print("scope demo passed")


if __name__ == "__main__":
    demo()
