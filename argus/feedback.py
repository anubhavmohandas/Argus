"""Researcher feedback — turn verdicts on past findings into an explainable rank
nudge for future ones. The "Argus learns" layer, kept honest.

`store.py` remembers what Argus *observed*. This remembers what a human *judged*:
was that `exposed_secret` a real bug, a false positive, a dup? Those verdicts
accumulate in an append-only JSONL and, once there's enough of them, gently push
a rule's findings up or down the ranking on the next run.

Three hard rules keep this from becoming an opaque model that rewrites its own
truth:

  1. Confidence is never touched. Feedback moves *rank* (attention), never a
     finding's confidence — the same wall policy.py respects. A learned nudge is
     a separate, bounded rank key, not a rewrite of the arithmetic.
  2. It never auto-suppresses. Overwhelming FP evidence produces a *suggestion*
     to add a class to the program's non_reportable list — a human confirms it.
     Two examples are not a pattern; see `suppression_suggestions`.
  3. Every nudge is explainable. `adjustment()` returns the delta *and* the
     reason lines behind it ("+0.11 historical precision (12 TP / 13 verdicts)"),
     which land in the conclusion's ledger and print in the dossier.

occam: JSONL + Counter, stdlib only, same ARGUS_HOME discipline as store.py.
Ceiling: aggregates per (program, rule) with additive-smoothing shrinkage so
small samples barely move — no per-target model, no cross-program generalization
(that waits for real verdicts to fill the store). No file lock on append; single
user CLI, one small line per write. SQLite lands when a query needs a join.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
from collections import Counter, defaultdict
from pathlib import Path

from .engine import InvestigationResult

# Researcher verdicts. Positive = worth attention, negative = noise, duplicate =
# real-but-not-novel (neutral for rank in v1, still recorded). Closed set — an
# unknown verdict is a caller bug, not silently stored.
VERDICTS = ("true_positive", "false_positive", "duplicate", "useful", "irrelevant")
_ALIASES = {"tp": "true_positive", "fp": "false_positive", "dup": "duplicate",
            "dupe": "duplicate", "noise": "irrelevant"}
_POS = {"true_positive", "useful"}      # counts toward precision / rank-up
_NEG = {"false_positive", "irrelevant"} # counts toward fp-rate / rank-down

# Rank-nudge tuning. CAP bounds feedback's total influence so it stays a nudge,
# never a takeover; PRIOR is the shrinkage strength — how much evidence it takes
# before a rule's history reaches full weight (confidence_factor = n/(n+PRIOR)).
_CAP = 0.20
_PRIOR = 8.0
# suppression is only *suggested*, and only when the evidence is lopsided and large
_SUPPRESS_MIN_FP = 10


def _home() -> Path:
    """The ARGUS_HOME base (defaults to ~/.argus), owner-only. Feedback lives at
    its root as a sibling of the investigations/ case files.

    occam: mirrors store._home()'s permission discipline rather than importing it,
    because store's returns the investigations/ subdir, not this base."""
    base = Path(os.environ.get("ARGUS_HOME") or os.path.join(os.path.expanduser("~"), ".argus"))
    base.mkdir(parents=True, exist_ok=True)
    base.chmod(0o700)   # a verdict names someone else's asset + the bug on it
    return base


def _path() -> Path:
    return _home() / "feedback.jsonl"


def _canon(verdict: str) -> str:
    v = _ALIASES.get(verdict.strip().lower(), verdict.strip().lower())
    if v not in VERDICTS:
        raise ValueError(f"unknown verdict {verdict!r} — one of {VERDICTS} (or tp/fp/dup)")
    return v


def record(rule: str, target: str, verdict: str, *,
           program: str = "", seed: str = "", fingerprint: str = "", note: str = "") -> Path:
    """Append one researcher verdict. Validates at the boundary — researcher input
    is data, so a blank rule/target or bad verdict is rejected, never stored."""
    rule = (rule or "").strip()
    target = (target or "").strip()
    if not rule or not target:
        raise ValueError("feedback needs a non-empty rule and target")
    rec = {
        "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "program": program.strip(), "seed": seed.strip(),
        "rule": rule, "target": target, "fingerprint": fingerprint,
        "verdict": _canon(verdict), "note": note.strip(),
    }
    p = _path()
    if not p.exists():
        p.touch(mode=0o600)   # owner-only BEFORE any verdict lands in it
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")   # occam: no lock — single-user CLI, atomic small append
    return p


def _load(program: str | None = None) -> list[dict]:
    """All verdicts, oldest first; optionally scoped to one program. A corrupt
    line is skipped, never fatal — same discipline as store.history."""
    p = _path()
    if not p.exists():
        return []
    out: list[dict] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if program is None or rec.get("program", "") == program:
            out.append(rec)
    return out


def tally(program: str = "") -> dict[str, Counter]:
    """Verdict counts per rule for one program: {rule: Counter(verdict -> n)}."""
    out: dict[str, Counter] = defaultdict(Counter)
    for rec in _load(program):
        out[rec.get("rule", "")][rec.get("verdict", "")] += 1
    return dict(out)


def adjustment(rule: str, program: str = "", counts: Counter | None = None) -> tuple[float, list[str]]:
    """(rank delta, explainable reason lines) for one rule, from its history.

    delta ∈ [-CAP, +CAP]. Two shrinkage-weighted components, exactly the two the
    dossier shows: a precision reward and a false-positive penalty. Small samples
    barely move (confidence_factor); a rule with no history returns (0.0, [])."""
    if counts is None:
        counts = tally(program).get(rule, Counter())
    pos = sum(counts[v] for v in _POS)
    neg = sum(counts[v] for v in _NEG)
    observed = pos + neg
    if observed == 0:
        return 0.0, []
    cf = observed / (observed + _PRIOR)         # 0..1, needs real evidence for full weight
    precision, fp_rate = pos / observed, neg / observed
    prec_contrib = _CAP * cf * precision        # 0..CAP
    fp_contrib = -_CAP * cf * fp_rate           # -CAP..0
    reasons: list[str] = []
    if round(prec_contrib, 2) >= 0.01:
        reasons.append(f"+{prec_contrib:.2f} historical precision ({pos} TP / {observed} verdicts)")
    if round(-fp_contrib, 2) >= 0.01:
        reasons.append(f"-{-fp_contrib:.2f} historical false-positive rate ({neg} noise / {observed})")
    return prec_contrib + fp_contrib, reasons


def suppression_suggestions(program: str = "") -> list[str]:
    """Rules whose history is lopsided enough to *propose* (never apply) adding to
    the program's non_reportable list. Conservative: needs many FP and zero TP —
    two examples never qualify."""
    out: list[str] = []
    for rule, c in sorted(tally(program).items()):
        fp = c["false_positive"]
        if c["true_positive"] == 0 and fp >= _SUPPRESS_MIN_FP:
            out.append(f"{rule}: {fp} FP / 0 TP — candidate for non_reportable (review before adding)")
    return out


def annotate(result: InvestigationResult, program: str = "") -> InvestigationResult:
    """Re-rank a fresh investigation by learned feedback, explainably.

    Risks are re-sorted objective-first (preserving policy's grouping) then by
    feedback delta, with confidence order intact within a tie. Confidence is never
    touched; the delta + its reasons are attached to each moved finding's ledger
    so the dossier can show *why* it moved. Priorities pass through untouched."""
    counts = tally(program)
    if not counts:
        return result
    risks = result.risks
    for c in risks:
        delta, reasons = adjustment(c.rule, program, counts.get(c.rule))
        if reasons:
            c.ledger = {**c.ledger, "feedback": {"delta": round(delta, 4), "reasons": reasons}}
    # stable sort: objective group first (as policy left it), then higher delta,
    # then the incoming confidence order survives for equal deltas.
    risks.sort(key=lambda c: ("objective" not in c.tags,
                              -c.ledger.get("feedback", {}).get("delta", 0.0)))
    rest = [c for c in result.conclusions if c.kind != "risk"]
    return InvestigationResult(risks + rest, result.fingerprint, result.error)


def demo() -> None:
    import tempfile
    from .engine import Conclusion

    with tempfile.TemporaryDirectory() as d:
        os.environ["ARGUS_HOME"] = d

        # unknown verdict and blank fields are rejected at the boundary
        for bad in [lambda: record("r", "t", "maybe"),
                    lambda: record("", "t", "tp"),
                    lambda: record("r", "", "tp")]:
            try:
                bad(); assert False, "should have raised"
            except ValueError:
                pass

        # a rule proven valuable ranks up; two FP is NOT enough to suppress
        for _ in range(12):
            record("exposed_secret", "api.x.com", "tp", program="acme")
        record("exposed_secret", "api.x.com", "fp", program="acme")
        for _ in range(2):
            record("weird_header", "x.com", "fp", program="acme")

        d_secret, r_secret = adjustment("exposed_secret", "acme")
        d_weird, r_weird = adjustment("weird_header", "acme")
        assert d_secret > 0.09, d_secret                     # strong, positive
        assert -0.06 < d_weird < 0, d_weird                  # slight down, not a cliff
        assert any("precision" in s for s in r_secret) and any("false-positive" in s for s in r_weird)
        assert suppression_suggestions("acme") == [], "2 FP must never suggest suppression"

        # only overwhelming, one-sided evidence *suggests* (not applies) suppression
        for _ in range(30):
            record("weird_header", "x.com", "fp", program="acme")
        sug = suppression_suggestions("acme")
        assert len(sug) == 1 and sug[0].startswith("weird_header"), sug

        # annotate re-ranks without touching confidence, and records why
        hi_noise = Conclusion(rule="weird_header", name="hdr", target="x.com",
                              confidence=90, ledger={"final": 90}, kind="risk", tags=[])
        lo_good = Conclusion(rule="exposed_secret", name="secret", target="api.x.com",
                             confidence=40, ledger={"final": 40}, kind="risk", tags=[])
        ranked = annotate(InvestigationResult([hi_noise, lo_good], "fp"), "acme")
        assert [c.rule for c in ranked.risks] == ["exposed_secret", "weird_header"], \
            [c.rule for c in ranked.risks]          # valued rule floats above louder noise
        assert ranked.risks[0].confidence == 40    # rank moved, confidence intact
        assert "feedback" in ranked.risks[0].ledger and ranked.risks[0].ledger["feedback"]["reasons"]

        # program isolation: acme's history must not colour another program
        assert adjustment("exposed_secret", "other") == (0.0, [])

    del os.environ["ARGUS_HOME"]
    print("feedback demo passed")


if __name__ == "__main__":
    demo()
