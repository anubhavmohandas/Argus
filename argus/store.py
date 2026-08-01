"""Investigation memory — persist every pivot, compare against past runs.

This is the "I've investigated this before / 14 new subdomains" capability.
Each pivot is saved as one JSON case file under ARGUS_HOME; before the next
run finishes, the CLI asks the store what it saw last time and diffs.

The graph stops being just today's output — it becomes what Argus remembers.

occam: flat JSON case files keyed by seed, stdlib only. That's enough for
per-seed history + an entity diff. The bigger ideas — an Intelligence-Memory
index that correlates *across* seeds (same AWS acct / GitHub org), and
`argus ask` reasoning over years of graphs — are NYX's job and plug in here:
they read these same case files. SQLite lands when a query needs it.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import re
from pathlib import Path

_SLUG_RE = re.compile(r"[^a-z0-9._-]+")


def home() -> Path:
    """Where case files live. Override with $ARGUS_HOME (defaults to ~/.argus)."""
    base = os.environ.get("ARGUS_HOME") or os.path.join(os.path.expanduser("~"), ".argus")
    d = Path(base) / "investigations"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _slug(seed: str) -> str:
    return _SLUG_RE.sub("_", seed.strip().lower()) or "seed"


def save(seed: str, g) -> Path:
    """Write one case file for this pivot. Returns its path."""
    now = _dt.datetime.now(_dt.timezone.utc)
    rec = {"seed": seed, "timestamp": now.isoformat(), **g.to_dict()}
    path = home() / f"{_slug(seed)}__{now.strftime('%Y%m%dT%H%M%S')}.json"
    path.write_text(json.dumps(rec, indent=2))
    return path


def history(seed: str) -> list[dict]:
    """All prior case files for this seed, oldest first."""
    out: list[dict] = []
    for fp in sorted(home().glob(f"{_slug(seed)}__*.json")):
        try:
            out.append(json.loads(fp.read_text()))
        except (OSError, ValueError):
            continue  # a corrupt case file must not break a live investigation
    return out


def diff_keys(prev: dict, g) -> tuple[set[str], set[str]]:
    """(entities new since prev, entities in prev but gone now). Keys are type:value."""
    prev_keys = {f"{n['type']}:{str(n['value']).lower()}" for n in prev.get("nodes", [])}
    cur_keys = set(g.nodes.keys())
    return cur_keys - prev_keys, prev_keys - cur_keys


def _by_type(keys: set[str], t: str) -> int:
    return sum(1 for k in keys if k.startswith(t + ":"))


def compare_line(prev: dict, g) -> str:
    """One-line summary of what changed since the previous investigation."""
    new, gone = diff_keys(prev, g)
    bits = []
    for t in ("subdomain", "domain", "ip"):
        c = _by_type(new, t)
        if c:
            bits.append(f"+{c} new {t}(s)")
    for t in ("subdomain", "domain", "ip"):
        c = _by_type(gone, t)
        if c:
            bits.append(f"-{c} {t}(s) gone")
    return ", ".join(bits) or "no entity changes since last run"
