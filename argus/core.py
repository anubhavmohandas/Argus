"""Argus core: finding model, module registry, HTTP + validation helpers.

Everything a recon module needs lives here. A module is just a function
registered with @module(...) that takes a target string and yields Finding
objects. Keeping the framework in one file is deliberate — modules plug in,
the core stays small.
"""
from __future__ import annotations

import ipaddress
import json
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from typing import Callable, Iterable

# --- severity -------------------------------------------------------------
# Same ladder the secret catalog uses, plus INFO for neutral recon facts.
CRITICAL, HIGH, MEDIUM, LOW, INFO = "critical", "high", "medium", "low", "info"
_SEV_ORDER = {CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0}


@dataclass
class Finding:
    module: str
    target: str
    title: str
    severity: str = INFO
    data: dict = field(default_factory=dict)
    source: str = ""          # where the fact came from (api/url/tool)

    def to_dict(self) -> dict:
        return asdict(self)


# --- module registry ------------------------------------------------------
@dataclass
class Module:
    name: str
    fn: Callable[[str], Iterable[Finding]]
    kind: str          # what a target should look like: ip|domain|phone|username|path|any
    help: str


MODULES: dict[str, Module] = {}


def module(name: str, kind: str = "any", help: str = ""):
    """Register a recon module. The wrapped fn takes a target, yields Findings."""
    def deco(fn):
        MODULES[name] = Module(name=name, fn=fn, kind=kind, help=help or (fn.__doc__ or "").strip())
        return fn
    return deco


# --- input validation (trust boundary — do not skip) ----------------------
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")


def validate_ip(target: str) -> str:
    """Return a normalized IP or raise ValueError."""
    return str(ipaddress.ip_address(target.strip()))


def validate_domain(target: str) -> str:
    """Return a lowercased hostname or raise ValueError. Strips scheme/path if pasted."""
    t = target.strip().lower()
    if "://" in t:
        t = urllib.parse.urlsplit(t).hostname or ""
    t = t.split("/")[0].split(":")[0]
    if not _DOMAIN_RE.match(t):
        raise ValueError(f"not a valid domain: {target!r}")
    if t.rsplit(".", 1)[-1].isdigit():  # all-numeric TLD => it's a (malformed) IP, not a domain
        raise ValueError(f"not a valid domain (numeric TLD): {target!r}")
    return t


def check_target(kind: str, target: str) -> str:
    """Validate/normalize a target for a module kind. Raises ValueError on bad input."""
    if kind == "ip":
        return validate_ip(target)
    if kind == "domain":
        return validate_domain(target)
    # phone/username/path/any: light cleaning, reject control chars
    t = target.strip()
    if not t or any(ord(c) < 32 for c in t):
        raise ValueError(f"invalid target: {target!r}")
    return t


# --- HTTP (stdlib only — keeps Argus dependency-light) --------------------
_UA = "Argus-Recon/0.1.0"


def http_get(url: str, timeout: float = 12.0) -> tuple[int, str]:
    """GET a URL. Returns (status, body). Network/HTTP errors return (0, "").
    URL must be fully formed by the caller with query parts already quoted."""
    req = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (recon fetches external targets by design)
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return 0, ""


def http_json(url: str, timeout: float = 12.0):
    """GET + parse JSON. Returns parsed object or None."""
    status, body = http_get(url, timeout)
    if status and body:
        try:
            return json.loads(body)
        except ValueError:
            return None
    return None


def q(value: str) -> str:
    """URL-encode a value for safe use in a query string / path segment."""
    return urllib.parse.quote(value, safe="")


# --- runners --------------------------------------------------------------
def run_module(name: str, target: str) -> list[Finding]:
    mod = MODULES.get(name)
    if not mod:
        raise KeyError(f"unknown module: {name}. Known: {', '.join(sorted(MODULES))}")
    clean = check_target(mod.kind, target)
    return list(mod.fn(clean))


def run_all(target: str) -> list[Finding]:
    """Run every module whose kind validates the target (best-effort sweep)."""
    out: list[Finding] = []
    for name, mod in MODULES.items():
        try:
            clean = check_target(mod.kind, target)
        except ValueError:
            continue  # target doesn't fit this module — skip silently in sweep mode
        try:
            out.extend(mod.fn(clean))
        except Exception as e:  # one module failing must not kill the sweep
            out.append(Finding(module=name, target=target, title=f"module error: {e}", severity=INFO))
    return out


def sort_by_severity(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: _SEV_ORDER.get(f.severity, 0), reverse=True)
