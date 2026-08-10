"""Behavioral proof: does Argus become a better investigator after being used?

Not a unit test of feedback.py's math (that's its demo()) — a simulation of four
realistic runs that asserts the *loop* works end to end: verdicts on one run change
the ranking of the next, and only in the ways we allow. Deterministic, no network:
synthetic findings stand in for a pivot's output so the proof is about ranking, not
discovery.

The four claims, each an assertion below:
  Run 1  baseline — no history, ranking is pure confidence order
  Run 2  same program, same findings — a valued rule floats over louder noise
  Run 3  a DIFFERENT program — experience does not leak
  Run 4  a rule fed only noise — pushed down, and flagged for review (not suppressed)
"""
from __future__ import annotations

import os
import tempfile

from argus import feedback
from argus.engine import Conclusion, InvestigationResult


def _run(program: str) -> list[str]:
    """One simulated investigation over the SAME two findings, ranked through the
    live feedback layer. Fresh Conclusions each call (annotate annotates ledgers)."""
    findings = [
        # engine hands risks over in confidence order: loud noise first, quiet gem second
        Conclusion(rule="missing_headers", name="Headers", target="www.acme.com",
                   confidence=90, ledger={"final": 90}, kind="risk", tags=[]),
        Conclusion(rule="exposed_secret", name="Leaked key", target="api.acme.com",
                   confidence=40, ledger={"final": 40}, kind="risk", tags=[]),
    ]
    ranked = feedback.annotate(InvestigationResult(findings, "fp"), program=program)
    return [c.rule for c in ranked.risks]


def demo() -> None:
    with tempfile.TemporaryDirectory() as d:
        os.environ["ARGUS_HOME"] = d

        # --- Run 1: no history — ranking is exactly what the rules concluded -----
        assert _run("acme") == ["missing_headers", "exposed_secret"], "baseline must be confidence order"

        # --- researcher labels Run 1: the quiet finding was the real bug, the loud
        #     one was noise. This is the whole point of the loop.
        for _ in range(6):
            feedback.record("exposed_secret", "api.acme.com", "tp", program="acme")
        for _ in range(4):
            feedback.record("missing_headers", "www.acme.com", "fp", program="acme")

        # --- Run 2: same program, same findings — experience reorders them -------
        assert _run("acme") == ["exposed_secret", "missing_headers"], \
            "a rule proven valuable must outrank louder noise on the next run"

        # confidence is untouched — only rank moved
        ranked = feedback.annotate(
            InvestigationResult(
                [Conclusion(rule="exposed_secret", name="x", target="api.acme.com",
                            confidence=40, ledger={"final": 40}, kind="risk", tags=[])], "fp"),
            program="acme")
        top = ranked.risks[0]
        assert top.confidence == 40, "feedback must never change confidence"
        assert "feedback" in top.ledger and top.ledger["feedback"]["reasons"], "the nudge must be explainable"

        # --- Run 3: a different program has none of acme's experience -----------
        assert _run("globex") == ["missing_headers", "exposed_secret"], \
            "one program's verdicts must not leak into another"

        # --- Run 4: a rule fed nothing but noise sinks AND is flagged for review,
        #     but is never auto-suppressed by the tool.
        assert feedback.suppression_suggestions("acme") == [], "4 FP is not enough to suggest suppression"
        for _ in range(30):
            feedback.record("missing_headers", "www.acme.com", "fp", program="acme")
        sug = feedback.suppression_suggestions("acme")
        assert len(sug) == 1 and sug[0].startswith("missing_headers"), sug
        assert _run("acme")[0] == "exposed_secret", "noisy rule stays demoted under the valued one"

    del os.environ["ARGUS_HOME"]
    print("feedback learning proof passed — Argus reranks from experience, "
          "without leaking, changing truth, or auto-suppressing")


if __name__ == "__main__":
    demo()
