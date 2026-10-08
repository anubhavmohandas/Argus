"""Reportability engine + structured report + deterministic critic — ARGUS's final output.

The end of the pipeline: a REPORT_READY finding becomes a report a triager can validate fast.
Everything here is assembled from the structured evidence the earned lifecycle already stored
on the finding (scope, reproduction, boundary, impact, dedupe) plus the immutable
observations — ARGUS arranges provenance, it never invents narrative. The optional NYX layer
may later polish wording, but it can never add evidence, change a verdict, or lift the ceiling
this module sets.

Three deterministic stages, in order:

  reportability(finding) → REPORTABLE | NOT_READY | DO_NOT_REPORT
      a checklist over the earned evidence. DO_NOT_REPORT when the program excludes it;
      NOT_READY (with the exact missing pieces) until every prerequisite is earned.

  generate(campaign, finding) → a structured Report
      title, summary, boundary, prerequisites, researcher-controlled accounts, steps to
      reproduce (from the actual experiment records), expected vs observed, demonstrated
      impact (exactly the structured impact effects — never more), reproduction status,
      scope/policy context, evidence refs, root-cause/dedupe context, remediation.

  critique(report) → PASS | WARN | BLOCK
      BLOCK on anything that would mislead a triager: not reproduced, a missing prerequisite,
      no expected/observed, an impact claim beyond the structured evidence, an overstated
      severity word, or a secret/credential value that leaked into the prose. WARN on
      unresolved duplicate uncertainty or thin evidence. A BLOCK means the UI must NOT call
      the report submission-ready.

Two security lines held here (reusing existing code):
  * a response body that leaked a credential is reported AS impact, but the raw secret is
    never rendered — providers.secrets_in returns masked previews only, and the body is
    withheld in favour of them. The critic re-scans the final text and BLOCKs on any leak.
  * reportability is the policy's call — a non-reportable finding is DO_NOT_REPORT, full stop.

occam: dataclass + a markdown renderer, no template engine. The impact section is literally
the stored demonstrated_effects list, so "impact text cannot exceed the evidence" is true by
construction, and the critic double-checks it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from . import finding as finding_mod, providers

# severity/impact words a report may NOT use unless the structured evidence states them —
# the critic BLOCKs on any of these appearing outside the evidence-backed effects.
_OVERSTATED = (
    "all customers", "all users", "every user", "pii", "personally identifiable",
    "account takeover", "full compromise", "rce", "remote code execution",
    "financial loss", "critical severity", "catastrophic", "mass",
)
_EVIDENCE_STAGES = finding_mod._EVIDENCE_STAGES

REPORTABLE, NOT_READY, DO_NOT_REPORT = "REPORTABLE", "NOT_READY", "DO_NOT_REPORT"
PASS, WARN, BLOCK = "PASS", "WARN", "BLOCK"


@dataclass
class Report:
    finding_id: str
    campaign_id: str
    title: str
    host: str
    technique: str
    classification: str
    reportable: bool
    state: str
    summary: str = ""
    security_boundary: dict = field(default_factory=dict)
    prerequisites: list[str] = field(default_factory=list)
    controlled_accounts: list[str] = field(default_factory=list)
    repro_steps: list[str] = field(default_factory=list)
    expected: str = ""
    observed: str = ""
    demonstrated_impact: list[str] = field(default_factory=list)
    reproduction_status: dict = field(default_factory=dict)
    scope_context: dict = field(default_factory=dict)
    root_cause: dict = field(default_factory=dict)
    remediation: list[str] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)        # per-observation request/response
    evidence_refs: list[str] = field(default_factory=list)    # immutable record ids
    impact_signals: list[dict] = field(default_factory=list)  # masked secrets leaked in responses
    reportability: str = NOT_READY
    reportability_reasons: list[str] = field(default_factory=list)
    critic_verdict: str = BLOCK
    critic_issues: list[dict] = field(default_factory=list)   # {level, msg}
    submittable: bool = False


# --- reportability engine (Phase 6) ---------------------------------------
def reportability(f: finding_mod.Finding) -> tuple[str, list[str]]:
    """Deterministic readiness verdict over the finding's earned evidence."""
    if not f.reportable:
        return DO_NOT_REPORT, [f"program excludes this finding: {f.suppressed_reason or 'not reportable'}"]
    missing = []
    checks = {
        "scope confirmed": "IN_SCOPE" in f.evidence,
        "reproduced": bool(f.evidence.get("REPRODUCIBLE", {}).get("reproduced")),
        "boundary confirmed": bool(f.evidence.get("BOUNDARY_CONFIRMED", {}).get("confirmed")),
        "impact confirmed": bool(f.evidence.get("IMPACT_CONFIRMED", {}).get("demonstrated_effects")),
        "duplicate checked": "DUPLICATE_CHECKED" in f.evidence,
    }
    for name, ok in checks.items():
        if not ok:
            missing.append(f"missing: {name}")
    if missing or f.state != "REPORT_READY":
        if f.state != "REPORT_READY" and not missing:
            missing.append(f"lifecycle at {f.state}, not REPORT_READY")
        return NOT_READY, missing
    return REPORTABLE, []


# --- evidence assembly ----------------------------------------------------
def _body_note(body: str) -> tuple[str, list[dict]]:
    """A renderable note for a response body + any masked secrets it leaked. A body with a
    secret is WITHHELD (we report the leak, we don't re-leak it); a clean body is excerpted."""
    secrets = providers.secrets_in(body or "")
    if secrets:
        return f"[body withheld: {len(secrets)} secret(s) detected — see impact]", secrets
    excerpt = (body or "").strip()
    return (excerpt[:600] + ("…" if len(excerpt) > 600 else "")) or "[empty body]", []


def _repro_steps(boundary: dict, baseline_req: dict, mutation_req: dict,
                 repro: dict) -> list[str]:
    """Reproduction steps built from the ACTUAL request records — never fabricated. Uses
    identity NAMES, never auth secrets."""
    owner = boundary.get("owner_identity", "the owner account")
    nonowner = boundary.get("nonowner_identity", "a second account")
    resource = boundary.get("resource", "the object")
    b_method = baseline_req.get("method", "GET")
    b_path = urlsplit(baseline_req.get("url", "")).path or "/"
    steps = [
        f"Authenticate as researcher-owned test account `{owner}`.",
        f"Use researcher-controlled object `{resource}` owned by `{owner}`.",
        f"Baseline: as `{owner}`, send `{b_method} {b_path}` and observe the authorized response.",
        f"Repeat the same request as researcher-owned account `{nonowner}` against the same object.",
        "Compare the authorization outcome of the two responses.",
    ]
    trials = repro.get("trial_experiment_ids") or []
    if trials:
        steps.append(f"Reproduced across {len(trials)} independent trial(s): "
                     f"{', '.join(trials)}.")
    return steps


def _remediation(technique: str) -> list[str]:
    """Technically useful, not overconfident. For authorization findings only — adapted to
    what the evidence showed, never claiming the exact internal root cause."""
    return [
        "Enforce authorization at the object/action boundary, not only at authentication.",
        "Derive the acting identity's access from server-side session context, not from a "
        "client-supplied owner or object id.",
        "Centralize the object-ownership check so every action on the object shares it.",
        "Add regression tests covering the owner vs non-owner case for this object.",
    ]


def generate(campaign, finding_id: str) -> Report:
    """Assemble a structured report from a finding + its earned evidence + the source
    experiment's observations. Runs the reportability engine and the critic. Never fabricates
    evidence; the impact section is exactly the stored demonstrated effects."""
    f = finding_mod._get(campaign, finding_id)
    if f is None:
        raise KeyError(f"no finding {finding_id!r}")
    exp = next((e for e in campaign.experiments() if e["id"] == f.experiment_id), None)
    obs = [o for o in campaign.observations() if o["experiment_id"] == f.experiment_id]
    baseline_id = (exp or {}).get("baseline_obs", "")

    evidence, impact_signals = [], []
    baseline_req, mutation_req, mutation_resp = {}, {}, {}
    for o in obs:
        note, secrets = _body_note(o.get("response", {}).get("body_excerpt", ""))
        impact_signals.extend(secrets)
        req, resp = o.get("request", {}), o.get("response", {})
        is_baseline = o["id"] == baseline_id
        if is_baseline:
            baseline_req = req
        else:
            mutation_req, mutation_resp = req, resp
        evidence.append({
            "label": "baseline" if is_baseline else "mutation",
            "method": req.get("method", ""), "url": req.get("url", ""),
            "request_headers": req.get("headers", {}),       # already <redacted> at capture
            "status": resp.get("status"), "body_note": note})
    evidence.sort(key=lambda e: e["label"] != "baseline")    # baseline first

    bnd = f.evidence.get("BOUNDARY_CONFIRMED", {})
    imp = f.evidence.get("IMPACT_CONFIRMED", {})
    scope = f.evidence.get("IN_SCOPE", {})
    repro = f.evidence.get("REPRODUCIBLE", {})
    dedupe = f.evidence.get("DUPLICATE_CHECKED", {})

    btype = bnd.get("boundary_type", "unknown")
    nonowner_access = bnd.get("nonowner_access", "")
    observed = (f"The non-owner `{bnd.get('nonowner_identity','')}` request returned "
                f"{mutation_resp.get('status','?')} ({nonowner_access}) on "
                f"`{bnd.get('owner_identity','')}`'s object `{bnd.get('resource','')}`."
                if bnd.get("confirmed") else "")
    expected = ("The non-owner request should be denied (401/403) — access to the object "
                "should be scoped to its owner." if bnd.get("confirmed") else "")

    refs = sorted(set(bnd.get("evidence_refs", []) + imp.get("evidence_refs", [])
                      + [f.experiment_id] + (repro.get("trial_experiment_ids") or [])))

    r = Report(
        finding_id=f.id, campaign_id=f.campaign_id,
        title=f.title or f"{btype} on {f.host}",
        host=f.host, technique=f.technique, classification=f.classification,
        reportable=f.reportable, state=f.state,
        summary=(bnd.get("rationale", "") or f"Candidate {f.technique} issue on {f.host}."),
        security_boundary=bnd,
        prerequisites=[f"Two researcher-owned test accounts: `{bnd.get('owner_identity','A')}` "
                       f"and `{bnd.get('nonowner_identity','B')}`.",
                       f"A researcher-controlled `{imp.get('resource_type','object')}` owned by "
                       f"`{bnd.get('owner_identity','A')}`."] if bnd.get("confirmed") else [],
        controlled_accounts=[x for x in (bnd.get("owner_identity"), bnd.get("nonowner_identity")) if x],
        repro_steps=_repro_steps(bnd, baseline_req, mutation_req, repro) if bnd.get("confirmed") else [],
        expected=expected, observed=observed,
        demonstrated_impact=list(imp.get("demonstrated_effects", [])),
        reproduction_status={
            "reproduced": bool(repro.get("reproduced")),
            "requested_trials": repro.get("requested_trials"),
            "completed_trials": repro.get("completed_trials"),
            "classifications": repro.get("classifications", []),
            "last_verified": repro.get("last_verified", ""),
        },
        scope_context=scope, root_cause=dedupe,
        remediation=_remediation(f.technique),
        evidence=evidence, evidence_refs=refs, impact_signals=impact_signals,
    )
    r.reportability, r.reportability_reasons = reportability(f)
    r.critic_verdict, r.critic_issues = critique(r)
    r.submittable = (r.reportability == REPORTABLE and r.critic_verdict != BLOCK)
    return r


# --- the critic (Phase 8) -------------------------------------------------
def critique(report: Report) -> tuple[str, list[dict]]:
    """Deterministic PASS/WARN/BLOCK over the assembled report. BLOCK means the UI must not
    present it as submission-ready."""
    issues: list[dict] = []

    def add(level: str, msg: str):
        issues.append({"level": level, "msg": msg})

    if report.reportability == DO_NOT_REPORT:
        add(BLOCK, f"program excludes this finding: {report.reportability_reasons}")
    if not report.reproduction_status.get("reproduced"):
        add(BLOCK, "not reproduced: a single observation can be a fluke — run reproduction")
    for reason in report.reportability_reasons:
        if reason.startswith("missing:"):
            add(BLOCK, reason)
    if report.security_boundary.get("confirmed") and not (report.expected and report.observed):
        add(BLOCK, "expected vs observed is missing")
    if report.security_boundary.get("confirmed") and not report.demonstrated_impact:
        add(BLOCK, "no demonstrated impact backing the report")

    # impact prose may not exceed the structured impact evidence, nor overstate severity.
    # Word-boundary match so "rce" never fires on "resource", "mass" never on "massive".
    rendered = render(report).lower()
    effects_text = " ".join(report.demonstrated_impact).lower()
    for word in _OVERSTATED:
        pat = r"\b" + re.escape(word) + r"\b"
        if re.search(pat, rendered) and not re.search(pat, effects_text):
            add(BLOCK, f"overstated/unsupported claim: {word!r} is not in the structured impact")

    # no raw secret/credential value may appear in the rendered report.
    leaked = providers.secrets_in(render(report))
    if leaked:
        add(BLOCK, f"a secret/credential value leaked into the report text ({len(leaked)})")

    # duplicate uncertainty is a warning, not a block.
    rel = report.root_cause.get("relation")
    if rel in ("UNKNOWN", "LIKELY_RELATED"):
        add(WARN, f"duplicate/root-cause uncertainty: relation is {rel}")
    if len([e for e in report.evidence]) < 2:
        add(WARN, "thin evidence: expected a baseline + mutation observation")

    levels = {i["level"] for i in issues}
    verdict = BLOCK if BLOCK in levels else WARN if WARN in levels else PASS
    return verdict, issues


# --- markdown rendering ---------------------------------------------------
def render(report: Report) -> str:
    """The report as submittable markdown. Deterministic — same report in, same text out.
    Never renders a raw secret (bodies with secrets are already withheld upstream)."""
    L = [f"# {report.title}", "",
         f"- **Host:** `{report.host}`",
         f"- **Technique:** `{report.technique}`",
         f"- **Boundary:** {report.security_boundary.get('boundary_type', 'unknown')}",
         f"- **Reproduced:** {'yes' if report.reproduction_status.get('reproduced') else 'NO'}",
         f"- **Readiness:** {report.reportability}",
         f"- **Critic:** {report.critic_verdict}",
         f"- **Submittable:** {'YES' if report.submittable else 'NO'}", ""]

    if report.summary:
        L += ["## Summary", report.summary, ""]
    if report.prerequisites:
        L += ["## Prerequisites"] + [f"- {p}" for p in report.prerequisites] + [""]
    if report.controlled_accounts:
        L += ["## Researcher-controlled accounts/resources",
              "Demonstrated on researcher-controlled test accounts: "
              + ", ".join(f"`{a}`" for a in report.controlled_accounts), ""]
    if report.repro_steps:
        L += ["## Steps to reproduce"] + [f"{i}. {s}" for i, s in enumerate(report.repro_steps, 1)] + [""]
    if report.expected or report.observed:
        L += ["## Expected vs observed",
              f"- **Expected:** {report.expected or '—'}",
              f"- **Observed:** {report.observed or '—'}", ""]
    if report.demonstrated_impact:
        L += ["## Demonstrated impact"] + [f"- {e}" for e in report.demonstrated_impact]
        L += ["", "_Demonstrated on researcher-controlled test objects; real-user blast radius "
              "is not established by this test._", ""]
    if report.reproduction_status.get("reproduced") is not None:
        rs = report.reproduction_status
        L += ["## Reproduction status",
              f"- reproduced: {'yes' if rs.get('reproduced') else 'no'} "
              f"({rs.get('completed_trials', 0)}/{rs.get('requested_trials', 0)} trials)", ""]
    if report.scope_context:
        sc = report.scope_context
        L += ["## Scope / policy context",
              f"- asset `{sc.get('asset','')}` in the frozen campaign scope "
              f"(policy `{sc.get('policy_version','')}`)",
              f"- source experiment verdict: {sc.get('experiment_verdict','')}", ""]
    L.append("## Evidence")
    for e in report.evidence:
        L += [f"### {e['label']}  ·  `{e['method']} {e['url']}`  →  {e['status']}",
              "```", e["body_note"], "```", ""]
    if report.evidence_refs:
        L += ["**Evidence records:** " + ", ".join(f"`{r}`" for r in report.evidence_refs), ""]
    if report.impact_signals:
        L.append("## Impact — secrets leaked in response")
        for s in report.impact_signals:
            L.append(f"- **{s['type']}** ({s['severity']}): `{s['preview']}`")
        L.append("")
    if report.root_cause:
        rc = report.root_cause
        L += ["## Root-cause / duplicate context",
              f"- relation: {rc.get('relation','')} ({rc.get('reason_for_cluster','')})",
              f"- cluster `{rc.get('cluster_id','')}` · {len(rc.get('finding_ids', []))} finding(s)", ""]
    if report.remediation:
        L += ["## Suggested remediation"] + [f"- {x}" for x in report.remediation] + [""]

    # the critic checklist, so a human sees exactly what is unresolved.
    if report.critic_issues:
        L.append(f"## Critic — {report.critic_verdict}")
        L += [f"- [{i['level']}] {i['msg']}" for i in report.critic_issues]
    else:
        L.append("## Critic — PASS ✓")
    return "\n".join(L)


def demo() -> None:
    """Self-check (offline): a reproduced, report-ready finding renders a submittable report
    with expected/observed, evidence-backed impact, and real reproduction steps; a leaked
    secret is reported but never rendered raw; an incomplete finding is NOT_READY with the
    exact missing pieces; the critic BLOCKs an unreproduced finding."""
    import os
    import tempfile
    from . import campaign as campaign_mod, finding as fmod, reproduce, resource as resource_mod
    from .differential import Variant, run
    from .identity import Identity, register

    with tempfile.TemporaryDirectory() as tmp:
        os.environ["ARGUS_HOME"] = tmp
        os.environ["A_TOK"], os.environ["B_TOK"] = "tok-a", "tok-b"
        c = campaign_mod.create("Assets:\napi.acme.example\nRate: 9 requests/sec\n", name="Acme")
        a = Identity(name="user_a", role="customer", tenant="t1", researcher_owned=True, credential_ref="A_TOK")
        b = Identity(name="user_b", role="customer", tenant="t1", researcher_owned=True, credential_ref="B_TOK")
        register(c, a); register(c, b)
        resource_mod.assert_ownership(c, resource_mod.Ownership(
            resource_type="order", resource_value="order-1", owner_identity="user_a",
            researcher_controlled=True))
        base = Variant(a, method="GET", path="/api/orders/1", resource="order-1", owner=a)
        mut = Variant(b, method="GET", path="/api/orders/1", resource="order-1", owner=a)
        leak = lambda *x: (200, {"content-type": "application/json"},
                           '{"key":"AKIAIOSFODNN7EXAMPLE","total":9}')
        r = run(c, "differential_cross_account", "api.acme.example", base, mut, fetch=leak)
        f = fmod.promote(c, next(e for e in c.experiments() if e["id"] == r.experiment_id))

        # incomplete -> NOT_READY with exact missing pieces, critic BLOCKs (not reproduced)
        rep0 = generate(c, f.id)
        assert rep0.reportability == NOT_READY and any("reproduced" in x for x in rep0.reportability_reasons)
        assert rep0.critic_verdict == BLOCK and not rep0.submittable
        assert rep0.impact_signals and "AKIAIOSFODNN7EXAMPLE" not in render(rep0)

        # earn every stage
        reproduce.verify(c, "differential_cross_account", "api.acme.example", base, mut,
                         trials=2, fetch=leak, finding_id=f.id)
        fmod.confirm_scope(c, f.id); fmod.confirm_boundary(c, f.id)
        fmod.confirm_impact(c, f.id); fmod.complete_dedupe(c, f.id); fmod.mark_report_ready(c, f.id)

        rep = generate(c, f.id)
        assert rep.reportability == REPORTABLE, rep.reportability_reasons
        assert rep.critic_verdict in (PASS, WARN) and rep.submittable, rep.critic_issues
        assert rep.expected and rep.observed
        assert rep.demonstrated_impact and "READ" in rep.demonstrated_impact[0]
        md = render(rep)
        assert "## Steps to reproduce" in md and "## Expected vs observed" in md
        assert "Authorization" not in md.replace("<redacted>", "")  # no raw auth value
        assert "AKIAIOSFODNN7EXAMPLE" not in md

        del os.environ["A_TOK"], os.environ["B_TOK"]
    del os.environ["ARGUS_HOME"]
    print("report demo passed")


if __name__ == "__main__":
    demo()
