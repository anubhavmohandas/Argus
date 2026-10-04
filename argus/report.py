"""Report generation + a deterministic critic — ARGUS's final standalone output.

The end of the pipeline: a REPORT_READY finding becomes a structured report a researcher
can submit. ARGUS owns the deterministic parts — gathering the immutable evidence,
redacting any secret a response leaked, and running a fixed quality checklist. The LLM
critique (prose quality, severity argument) is NYX's optional layer ON TOP; nothing here
needs it, so ARGUS produces a submittable report with no NYX present.

Two security lines held here, both reusing code that already exists:
  * a response body that leaked a credential is reported as IMPACT, but the raw secret is
    never rendered — `providers.secrets_in` already returns masked previews only, and a
    body with any secret is withheld in favour of those previews.
  * reportability is the policy's call — a non-reportable finding is never `submittable`,
    even if every other check passes (found ≠ reportable, one more time).

The critic is a checklist, not a judge: it lists what's missing (not reproduced, evidence
thin, lifecycle incomplete, out of scope). `submittable` is simply "critic found nothing
AND the program accepts the class". A human still decides to send it.

occam: the report is a dataclass + a markdown renderer, no template engine. Evidence is
read straight from the stored Observations — the report computes nothing new, it arranges
existing provenance.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import finding as finding_mod, providers


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
    reproduced: bool
    evidence: list[dict] = field(default_factory=list)       # per-observation request/response
    impact_signals: list[dict] = field(default_factory=list)  # masked secrets leaked in responses
    critic_issues: list[str] = field(default_factory=list)
    submittable: bool = False


def _body_note(body: str) -> tuple[str, list[dict]]:
    """A renderable note for a response body + any masked secrets it leaked. A body with a
    secret is WITHHELD (we report the leak, we don't re-leak it); a clean body is excerpted."""
    secrets = providers.secrets_in(body or "")
    if secrets:
        return f"[body withheld: {len(secrets)} secret(s) detected — see impact]", secrets
    excerpt = (body or "").strip()
    return (excerpt[:600] + ("…" if len(excerpt) > 600 else "")) or "[empty body]", []


def _critique(f: finding_mod.Finding, obs: list[dict], reproduced: bool) -> list[str]:
    """The fixed quality checklist. Each failed check is one line a human can act on."""
    issues = []
    if not f.reportable:
        issues.append(f"NOT REPORTABLE: {f.suppressed_reason or 'program excludes this'}")
    if f.state != "REPORT_READY":
        issues.append(f"lifecycle incomplete: still at {f.state} (need REPORT_READY)")
    if not reproduced:
        issues.append("not reproduced: a single observation can be a fluke — run reproduce.verify")
    if len(obs) < 2:
        issues.append(f"thin evidence: {len(obs)} observation(s), expected baseline + mutation")
    if not f.title.strip():
        issues.append("no title")
    return issues


def generate(campaign, finding_id: str) -> Report:
    """Assemble a report from a finding + its source experiment's observations. Arranges
    existing provenance and runs the critic — it never fabricates evidence."""
    f = finding_mod._get(campaign, finding_id)
    if f is None:
        raise KeyError(f"no finding {finding_id!r}")
    exp = next((e for e in campaign.experiments() if e["id"] == f.experiment_id), None)
    obs = [o for o in campaign.observations() if o["experiment_id"] == f.experiment_id]
    baseline_id = (exp or {}).get("baseline_obs", "")

    evidence, impact = [], []
    for o in obs:
        note, secrets = _body_note(o.get("response", {}).get("body_excerpt", ""))
        impact.extend(secrets)
        req = o.get("request", {})
        resp = o.get("response", {})
        evidence.append({
            "label": "baseline" if o["id"] == baseline_id else "mutation",
            "method": req.get("method", ""), "url": req.get("url", ""),
            "request_headers": req.get("headers", {}),       # already <redacted> at capture
            "status": resp.get("status"), "body_note": note})
    evidence.sort(key=lambda e: e["label"] != "baseline")    # baseline first

    reproduced = any(h.get("to") == "REPRODUCIBLE" for h in f.history)
    issues = _critique(f, obs, reproduced)
    return Report(
        finding_id=f.id, campaign_id=f.campaign_id, title=f.title, host=f.host,
        technique=f.technique, classification=f.classification, reportable=f.reportable,
        state=f.state, reproduced=reproduced, evidence=evidence, impact_signals=impact,
        critic_issues=issues, submittable=(not issues and f.reportable))


def render(report: Report) -> str:
    """The report as submittable markdown. Deterministic — same report in, same text out."""
    L = [f"# {report.title}", "",
         f"- **Host:** `{report.host}`",
         f"- **Technique:** `{report.technique}`",
         f"- **Classification:** {report.classification}",
         f"- **Reproduced:** {'yes' if report.reproduced else 'NO'}",
         f"- **Reportable:** {'yes' if report.reportable else 'no — ' + 'excluded'}",
         f"- **Submittable:** {'YES' if report.submittable else 'NO (see critic)'}", ""]
    L.append("## Evidence")
    for e in report.evidence:
        L += [f"### {e['label']}  ·  `{e['method']} {e['url']}`  →  {e['status']}",
              "```", e["body_note"], "```", ""]
    if report.impact_signals:
        L.append("## Impact — secrets leaked in response")
        for s in report.impact_signals:
            L.append(f"- **{s['type']}** ({s['severity']}): `{s['preview']}`")
        L.append("")
    if report.critic_issues:
        L.append("## Critic — resolve before submitting")
        L += [f"- [ ] {i}" for i in report.critic_issues]
    else:
        L.append("## Critic — all checks passed ✓")
    return "\n".join(L)


def demo() -> None:
    """Self-check (offline): a reproduced, report-ready finding renders a submittable
    report; a thin/out-of-scope one is flagged NOT submittable with actionable critic
    lines; a leaked secret is reported as impact but never rendered raw."""
    import os
    import tempfile
    from . import campaign as campaign_mod, finding as fmod
    from .campaign import Experiment, Observation

    with tempfile.TemporaryDirectory() as tmp:
        os.environ["ARGUS_HOME"] = tmp
        c = campaign_mod.create("Assets:\napi.acme.example\n", name="Acme")
        exp = c.save_experiment(Experiment(
            campaign_id=c.id, hypothesis="idor?", technique="differential_cross_account",
            host="api.acme.example", verdict="ALLOW_WITH_LIMITS", verdict_reason="owned",
            status="EVALUATED", classification="suspicious"))
        base_o = c.save_observation(Observation(
            experiment_id=exp.id, request={"method": "POST", "url": "https://api.acme.example/o/1", "headers": {"Authorization": "<redacted>"}, "body": ""},
            response={"status": 403, "headers": {}, "body_excerpt": "forbidden", "body_len": 9}))
        c.save_observation(Observation(
            experiment_id=exp.id, request={"method": "POST", "url": "https://api.acme.example/o/1", "headers": {"Authorization": "<redacted>"}, "body": ""},
            response={"status": 200, "headers": {}, "body_excerpt": "AKIAIOSFODNN7EXAMPLE secret body", "body_len": 32}))
        exp.baseline_obs = base_o.id
        c.save_experiment(exp)

        f = fmod.promote(c, next(e for e in c.experiments() if e["id"] == exp.id))
        # not yet reproduced / not report-ready -> NOT submittable, with critic lines
        r0 = generate(c, f.id)
        assert not r0.submittable
        assert any("not reproduced" in i for i in r0.critic_issues)
        assert any("lifecycle incomplete" in i for i in r0.critic_issues)
        # a leaked AWS key is reported as impact, never rendered raw
        assert r0.impact_signals and "AKIAIOSFODNN7EXAMPLE" not in render(r0)
        assert "body withheld" in render(r0)

        # walk it to REPORT_READY with a reproduction in history
        fmod.advance(c, f.id, "REPRODUCIBLE", note="reproduced 3/3")
        for s in ("IN_SCOPE", "BOUNDARY_CONFIRMED", "IMPACT_CONFIRMED", "DUPLICATE_CHECKED", "REPORT_READY"):
            fmod.advance(c, f.id, s)
        r = generate(c, f.id)
        assert r.reproduced and r.submittable, (r.reproduced, r.critic_issues)
        assert r.critic_issues == []
        md = render(r)
        assert md.startswith("# ") and "baseline" in md and "## Evidence" in md
        assert r.evidence[0]["label"] == "baseline" and r.evidence[0]["status"] == 403

        # an out-of-scope finding is never submittable regardless of lifecycle
        oos = fmod.promote(c, {"id": "exp-oos", "technique": "differential_cross_account",
                               "host": "evil.example", "classification": "suspicious"})
        assert not generate(c, oos.id).submittable
        assert any("NOT REPORTABLE" in i for i in generate(c, oos.id).critic_issues)
    del os.environ["ARGUS_HOME"]
    print("report demo passed")


if __name__ == "__main__":
    demo()
