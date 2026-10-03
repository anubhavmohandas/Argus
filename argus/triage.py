"""Shared secret-triage helpers — the deterministic parts of the Kongsec
"smart mode" analyst: entropy scoring, false-positive filtering, and redaction.

Used by every secret-recon module (github_dork, postman_dork, jsmap,
github_org) so the triage logic lives once. The LLM analyst prompt in
docs/recon/ is the optional layer on top of this.
"""
from __future__ import annotations

import math

# Values a human triager discards on sight (from the analyst playbook).
FP_TOKENS = {
    "test", "testing", "demo", "example", "sample", "dummy", "fake", "placeholder",
    "password", "passwd", "password123", "1234", "123456", "admin", "administrator",
    "changeme", "default", "secret", "your_secret", "your_api_key", "api_key_here",
    "token_here", "xxxxx", "abcdef", "foobar", "localhost", "example.com", "redacted",
    "none", "null", "undefined",
}

# Provider-format prefixes carry their own structure/entropy — never entropy-gate these.
_STRUCTURED_PREFIXES = (
    "AKIA", "ASIA", "ghp_", "gho_", "github_pat_", "sk_live_", "sk-ant-", "sk-proj-",
    "AIza", "xox", "hf_", "dop_v1_", "npm_", "dckr_pat_", "SG.", "pypi-AgENdGV",
    "glpat-", "ATATT3xFfGF0",
)


def shannon_entropy(s: str) -> float:
    """Bits per character. Real keys sit high (>3.5); words/placeholders low."""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_false_positive(value: str, *, min_entropy: float = 3.0) -> bool:
    """True if a detected secret value looks like a placeholder/test/dummy."""
    v = value.strip().strip("'\"")
    low = v.lower()
    if len(v) < 8:
        return True
    if low in FP_TOKENS:
        return True
    if any(tok in low for tok in ("your_", "_here", "example", "changeme", "placeholder", "redacted", "xxxx")):
        return True
    if len(set(v)) <= 3:  # "aaaaaaaa", "12121212"
        return True
    if shannon_entropy(v) < min_entropy and not any(v.startswith(p) for p in _STRUCTURED_PREFIXES):
        return True
    return False


def redact(value: str) -> str:
    """Keep first/last 4 chars for identification; mask the middle. Never store
    a usable secret in Argus output."""
    v = value.strip().strip("'\"")
    if len(v) <= 10:
        return v[0] + "…" + v[-1] if len(v) > 2 else "…"
    return f"{v[:4]}…{v[-4:]} ({len(v)} chars)"
