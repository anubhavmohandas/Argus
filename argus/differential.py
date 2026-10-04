"""Differential runner — baseline → one controlled mutation → comparison → observation.

The spec's core experimental primitive: hold everything constant, change exactly ONE
thing, and ask whether the response changed in a way that matters. The one thing is
usually *who* is asking (identity A vs identity B on the same object — the cross-account
authorization test) or a single request field; never two at once (that is uncontrolled
fuzzing, which `_require_single_mutation` refuses).

Two safety rules this module exists to hold, both deriving from the spec:

  1. EVERY outbound active request passes through `EngagementPolicy.can_test`
     INDEPENDENTLY. Gating the parent experiment is not enough — the baseline and the
     mutation are each gated on their own account/ownership, and a non-ALLOW verdict
     stops that request (the comparison simply does not execute).

  2. Cross-account execution is approval-free ONLY when the identity that OWNS the
     targeted object is a researcher-owned test account. That decision is `can_test`'s
     (its `differential_cross_account` row reads `account.researcher_owned`); this
     module never infers ownership from a name — it passes the explicit owner Identity.

ARGUS/NYX boundary: this runs deterministic primitives (execute, normalize, compare)
and records facts + a conservative first-pass classification. It never decides a
finding is real — "vulnerable" is reserved for the later reproduction/NYX layers.

occam: comparison is a normalized dict diff, not a semantic model. Volatile noise
(dates, uuids, trace ids, long tokens) is regex-scrubbed before the body compare;
ceiling: JSON-structure diffing is len+normalized-equality only — a field-level JSON
diff lands when a finding needs to point at the one key that changed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from . import providers
from .campaign import Experiment, Observation
from .identity import Identity
from .policy import Verdict

# --- the two-request model ------------------------------------------------
# A differential is a (baseline, mutation) pair of Variants that differ in exactly
# ONE axis. `owner` is the identity whose object this request targets — the account
# can_test weighs for cross-account approval; it is explicit, never guessed.
_AXES = ("identity", "method", "path", "body", "resource")


@dataclass
class Variant:
    identity: Identity                 # the account the request is sent AS (its auth header)
    method: str = "GET"
    path: str = "/"
    body: str = ""
    resource: str = ""                 # the object being acted on (e.g. "order_a"), for provenance
    owner: Identity | None = None      # who OWNS that object; None => the actor owns it

    def account(self) -> Identity:
        """The identity can_test must weigh — the owner of the targeted object (the
        potential victim), falling back to the actor when the actor owns it."""
        return self.owner or self.identity

    def _axis_values(self) -> dict:
        return {"identity": self.identity.name, "method": self.method.upper(),
                "path": self.path, "body": self.body, "resource": self.resource}


@dataclass
class DiffResult:
    experiment_id: str
    technique: str
    host: str
    hypothesis: str
    executed: bool                     # False when a request's policy gate blocked it
    decision: str                      # the governing verdict (blocking one, or the mutation's)
    decision_reason: str
    classification: str                # "", secure, suspicious, inconclusive (never 'vulnerable' here)
    mutation: dict = field(default_factory=dict)       # the single controlled change {axis, baseline, mutation}
    baseline: dict = field(default_factory=dict)       # normalized baseline view
    mutation_view: dict = field(default_factory=dict)  # normalized mutation view
    comparison: dict = field(default_factory=dict)
    baseline_obs: str = ""
    mutation_obs: str = ""


# --- normalization: strip volatile noise before comparing ------------------
# Response headers that change every request regardless of authorization — they must
# never make two otherwise-identical responses look different.
_VOLATILE_HEADERS = {
    "date", "age", "expires", "last-modified", "etag", "x-request-id",
    "x-amzn-requestid", "x-amzn-trace-id", "x-trace-id", "x-correlation-id",
    "x-runtime", "x-timer", "cf-ray", "x-served-by", "report-to", "nel",
    "x-cache", "via", "x-amz-cf-id", "x-amz-request-id",
}
# Security-relevant headers whose change IS meaningful to an authorization test.
_SECURITY_HEADERS = (
    "content-security-policy", "strict-transport-security", "x-frame-options",
    "www-authenticate", "access-control-allow-origin", "x-content-type-options",
)
# Volatile body tokens -> a stable placeholder, so dynamic values don't mask a real
# structural difference (or invent one). Order matters: uuid/timestamp before tokens.
_SCRUB = [
    (re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"), "<uuid>"),
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"), "<ts>"),
    (re.compile(r"\b[A-Za-z0-9_\-]{24,}\b"), "<token>"),   # api keys / csrf / session blobs
    (re.compile(r"\b\d{10,13}\b"), "<epoch>"),             # unix timestamps (sec/ms)
]


def _scrub(body: str) -> str:
    for rx, tag in _SCRUB:
        body = rx.sub(tag, body)
    return body


def _access_outcome(status: int) -> str:
    """The authorization reading of a status code: did the request reach the object?"""
    if status == 0:
        return "error"              # never reached it — establishes nothing (I-1)
    if status in (401, 403):
        return "denied"
    if status == 404:
        return "notfound"           # ambiguous: hidden-by-404 or truly absent
    if 200 <= status < 300:
        return "granted"
    if 300 <= status < 400:
        return "redirect"
    return "other"


def normalize(status: int, headers: dict, body: str) -> dict:
    """One raw response -> the comparable view. Pure; keeps only what an authorization
    differential reasons over, with volatile noise removed. The RAW response is stored
    separately on the Observation — this never replaces the evidence, it summarizes it."""
    h = {k.lower(): v for k, v in (headers or {}).items()}
    return {
        "status": status,
        "access": _access_outcome(status),
        "location": h.get("location", ""),                      # redirect destination
        "content_length": len(body or ""),
        "content_type": h.get("content-type", ""),
        "set_cookie": bool(h.get("set-cookie")),                # session effect (presence, not value)
        "security_headers": {k: h[k] for k in _SECURITY_HEADERS if k in h},
        "body_normalized": _scrub(body or ""),
        "stable_headers": {k: v for k, v in h.items() if k not in _VOLATILE_HEADERS},
    }


def compare(base: dict, mut: dict) -> dict:
    """Normalized baseline vs mutation -> the differential. Booleans say WHAT changed;
    the authorization-outcome change is the one that matters most for an access test."""
    return {
        "status": [base["status"], mut["status"]],
        "status_changed": base["status"] != mut["status"],
        "access": [base["access"], mut["access"]],
        "authorization_outcome_changed": base["access"] != mut["access"],
        "redirect_changed": base["location"] != mut["location"],
        "content_length_delta": mut["content_length"] - base["content_length"],
        "body_changed": base["body_normalized"] != mut["body_normalized"],
        "security_headers_changed": base["security_headers"] != mut["security_headers"],
        "set_cookie_changed": base["set_cookie"] != mut["set_cookie"],
    }


def _classify(technique: str, mutation: Variant, base: dict, mut: dict, cmp: dict) -> str:
    """ARGUS's deterministic first pass — a fact about the comparison, not a verdict on
    severity. 'suspicious' flags a candidate for NYX/reproduction; it is NEVER
    'vulnerable' (that needs a reproduction the spec puts in a later slice)."""
    if base["access"] == "error" or mut["access"] == "error":
        return "inconclusive"                       # a request never landed — can't compare
    if technique == "differential_cross_account":
        # The ONLY suspicious cross-account signal is B reaching A's object. B being
        # DENIED is the correct, secure outcome — the access legitimately differs
        # between two identities, so the generic 'outcome changed' rule must NOT apply.
        cross_identity = (mutation.owner is not None
                          and mutation.identity.name != mutation.owner.name)
        return "suspicious" if (cross_identity and mut["access"] == "granted") else "secure"
    # same-account differential: a single request-field change that flips the
    # authorization outcome is the interesting signal.
    return "suspicious" if cmp["authorization_outcome_changed"] else "secure"


# --- the gated executor ----------------------------------------------------
def _default_fetch(method: str, url: str, headers: dict, body: str) -> tuple[int, dict, str]:
    """Real transport: reuses the provider throttle, SSRF guard and _ID_HEADERS.
    `providers._permitted` is an independent host backstop (global-routable + armed
    policy) on top of the per-request can_test above it."""
    host = urlsplit(url).hostname or ""
    if not providers._permitted(host):
        return 0, {}, ""                            # SSRF / disarmed-scope backstop
    data = body.encode() if body else None
    return providers._fetch(url, timeout=8.0, data=data, extra_headers=headers, method=method)


def _execute(campaign, technique: str, host: str, v: Variant, intensity: float, fetch):
    """Gate ONE variant through can_test, then send it iff allowed. Returns
    (decision, status, raw_headers, raw_body, request_record). An unauthorized verdict
    returns without sending — the request simply never happens."""
    decision = campaign.policy.can_test(host, technique, intensity, v.account())
    url = f"https://{host}{v.path if v.path.startswith('/') else '/' + v.path}"
    req_record = {"method": v.method.upper(), "url": url,
                  "headers": _redact(v.identity.auth_headers()), "body": v.body}
    campaign.audit("differential_request_decision", host=host, technique=technique,
                   identity=v.identity.name, owner=v.account().name,
                   verdict=decision.verdict.value, reason=decision.reason)
    if not decision.allowed:
        return decision, 0, {}, "", req_record      # blocked: no outbound request
    status, headers, resp_body = fetch(v.method.upper(), url, v.identity.auth_headers(), v.body)
    return decision, status, headers, resp_body, req_record


def _redact(headers: dict) -> dict:
    """Store that an auth header was sent, never the secret itself — the Observation is
    persisted to disk, and a resolved token must never land there."""
    return {k: "<redacted>" for k in headers}


def _require_single_mutation(baseline: Variant, mutation: Variant) -> dict:
    """Enforce the one-controlled-change rule. Returns {axis, baseline, mutation} for the
    single differing axis, or raises — two changed axes is uncontrolled fuzzing, which a
    differential must refuse (you can't attribute a response change to one cause)."""
    b, m = baseline._axis_values(), mutation._axis_values()
    changed = [a for a in _AXES if b[a] != m[a]]
    if len(changed) != 1:
        raise ValueError(
            f"differential needs exactly ONE controlled mutation; {len(changed)} axes "
            f"differ: {changed or '[none]'} — model a sequence explicitly if intended")
    axis = changed[0]
    return {"axis": axis, "baseline": b[axis], "mutation": m[axis],
            "resource": mutation.resource, "resource_owner": mutation.account().name}


# --- the primitive: run one differential -----------------------------------
def run(campaign, technique: str, host: str, baseline: Variant, mutation: Variant,
        hypothesis: str = "", intensity: float = 1.0, fetch=None) -> DiffResult:
    """Execute one differential and record it. The full flow:

        validate single mutation
        → gate + execute baseline (can_test, independently)
        → gate + execute mutation (can_test, independently)
        → normalize both, compare
        → classify (deterministic first pass)
        → persist Experiment (with mutation provenance) + both Observations
        → return structured DiffResult

    A blocked request short-circuits: the Experiment is still recorded (status reflects
    what the policy decided), but no comparison is fabricated from a request that never
    ran. `fetch` is injectable for tests; production uses the throttled, SSRF-guarded
    provider transport."""
    mut_meta = _require_single_mutation(baseline, mutation)
    fetch = fetch or _default_fetch

    b_dec, b_status, b_hdrs, b_body, b_req = _execute(
        campaign, technique, host, baseline, intensity, fetch)
    m_dec, m_status, m_hdrs, m_body, m_req = _execute(
        campaign, technique, host, mutation, intensity, fetch)

    # The governing decision for the record: a blocking one wins (it's why nothing ran);
    # otherwise the mutation's verdict (the cross-account risk the test is about).
    gov = next((d for d in (b_dec, m_dec) if not d.allowed), m_dec)
    exp = campaign.save_experiment(Experiment(
        campaign_id=campaign.id, hypothesis=hypothesis, technique=technique, host=host,
        verdict=gov.verdict.value, verdict_reason=gov.reason,
        identity=baseline.identity.name, limits=gov.limits,
        mutation=mut_meta, status="RUNNING"))

    if not (b_dec.allowed and m_dec.allowed):
        exp.status = "EVALUATED"
        exp.classification = "inconclusive"          # blocked before it could establish anything
        campaign.save_experiment(exp)
        campaign.audit("differential_blocked", experiment=exp.id, technique=technique,
                       host=host, reason=gov.reason)
        return DiffResult(experiment_id=exp.id, technique=technique, host=host,
                          hypothesis=hypothesis, executed=False, decision=gov.verdict.value,
                          decision_reason=gov.reason, classification="inconclusive",
                          mutation=mut_meta)

    base_view, mut_view = normalize(b_status, b_hdrs, b_body), normalize(m_status, m_hdrs, m_body)
    cmp = compare(base_view, mut_view)
    classification = _classify(technique, mutation, base_view, mut_view, cmp)

    b_obs = campaign.save_observation(Observation(
        experiment_id=exp.id, request=b_req,
        response=_raw_response(b_status, b_hdrs, b_body)))
    m_obs = campaign.save_observation(Observation(
        experiment_id=exp.id, request=m_req,
        response=_raw_response(m_status, m_hdrs, m_body)))

    exp.baseline_obs = b_obs.id
    exp.classification = classification
    exp.status = "EVALUATED"
    campaign.save_experiment(exp)
    campaign.audit("differential_recorded", experiment=exp.id, technique=technique,
                   host=host, classification=classification,
                   authorization_outcome_changed=cmp["authorization_outcome_changed"])

    return DiffResult(
        experiment_id=exp.id, technique=technique, host=host, hypothesis=hypothesis,
        executed=True, decision=gov.verdict.value, decision_reason=gov.reason,
        classification=classification, mutation=mut_meta, baseline=base_view,
        mutation_view=mut_view, comparison=cmp, baseline_obs=b_obs.id, mutation_obs=m_obs.id)


def _raw_response(status: int, headers: dict, body: str) -> dict:
    """The immutable raw evidence stored on an Observation — capped body excerpt plus
    full length, alongside headers. Both the raw and the normalized view are kept (the
    spec's rule): the normalized view is on the Experiment's comparison, raw lives here."""
    h = {k.lower(): v for k, v in (headers or {}).items()}
    return {"status": status, "headers": h,
            "body_excerpt": (body or "")[:2048], "body_len": len(body or "")}


def demo() -> None:
    """Self-check (offline, injected transport): an IDOR-style cross-account differential
    where identity B reaches identity A's object is flagged suspicious; a properly denied
    one is secure; a real (non-researcher-owned) victim is never auto-executed; and two
    simultaneous changes are refused."""
    import os
    import tempfile
    from . import campaign as campaign_mod

    user_a = Identity(name="user_a", role="customer", researcher_owned=True,
                      credential_ref="A_TOK", auth_template="Bearer {}")
    user_b = Identity(name="user_b", role="customer", researcher_owned=True,
                      credential_ref="B_TOK")
    real_victim = Identity(name="victim", role="customer", researcher_owned=False)

    with tempfile.TemporaryDirectory() as tmp:
        os.environ["ARGUS_HOME"] = tmp
        os.environ["A_TOK"], os.environ["B_TOK"] = "tok-a", "tok-b"
        c = campaign_mod.create("Assets:\napi.acme.example\nRate: 5 requests/sec\n", name="Acme")

        # --- controlled mutation = identity only; same object (order_a, owned by A) ---
        base = Variant(user_a, method="POST", path="/api/orders/1/cancel",
                       resource="order_a", owner=user_a)       # A cancels own order
        mut = Variant(user_b, method="POST", path="/api/orders/1/cancel",
                      resource="order_a", owner=user_a)        # B cancels A's order

        # a transport where the server FAILS to enforce ownership: B also gets 200
        def leaky(method, url, headers, body):
            return 200, {"content-type": "application/json", "date": "now",
                         "x-request-id": "r-" + os.urandom(4).hex()}, '{"cancelled":true}'
        r = run(c, "differential_cross_account", "api.acme.example", base, mut,
                hypothesis="does cancel enforce order ownership?", fetch=leaky)
        assert r.executed and r.classification == "suspicious", (r.executed, r.classification)
        assert r.comparison["authorization_outcome_changed"] is False     # both 200
        assert r.mutation == {"axis": "identity", "baseline": "user_a", "mutation": "user_b",
                              "resource": "order_a", "resource_owner": "user_a"}, r.mutation
        # the auth secret is never written to the stored observation
        obs = {o["id"]: o for o in c.observations()}
        assert obs[r.mutation_obs]["request"]["headers"] == {"Authorization": "<redacted>"}
        assert "tok-b" not in (c.dir / "observations" / f"{r.mutation_obs}.json").read_text()

        # a server that DOES enforce: B is denied (403) -> authorization outcome changed -> secure
        def enforced(method, url, headers, body):
            status = 200 if "tok-a" == _tok(headers) else 403
            return status, {"content-type": "application/json"}, "{}"
        r2 = run(c, "differential_cross_account", "api.acme.example", base, mut,
                 hypothesis="…", fetch=enforced)
        assert r2.executed and r2.classification == "secure", r2.classification
        assert r2.comparison["access"] == ["granted", "denied"]

        # --- safety: a REAL victim's object is never auto-executed ---
        base_v = Variant(user_a, path="/api/orders/9", resource="order_v", owner=real_victim)
        mut_v = Variant(user_b, path="/api/orders/9", resource="order_v", owner=real_victim)
        fired = []
        r3 = run(c, "differential_cross_account", "api.acme.example", base_v, mut_v,
                 fetch=lambda *a: (fired.append(1) or (200, {}, "")))
        assert not r3.executed and fired == [], "a non-researcher-owned object was touched!"
        assert r3.decision == Verdict.HUMAN_APPROVAL.value and r3.classification == "inconclusive"

        # --- the gate is per-request: a forbidden technique never sends ---
        # (out-of-scope host is denied for BOTH requests, so nothing is sent)
        oos_b = Variant(user_a, path="/x", resource="r", owner=user_a)
        oos_m = Variant(user_b, path="/x", resource="r", owner=user_a)
        hits = []
        r4 = run(c, "differential_cross_account", "evil.other.example", oos_b, oos_m,
                 fetch=lambda *a: (hits.append(1) or (200, {}, "")))
        assert not r4.executed and hits == [] and "out of scope" in r4.decision_reason

        # --- uncontrolled change (identity AND path) is refused ---
        try:
            run(c, "differential_cross_account", "api.acme.example", base,
                Variant(user_b, method="POST", path="/api/orders/2/cancel",
                        resource="order_a", owner=user_a))
            raise AssertionError("two-axis mutation accepted")
        except ValueError as e:
            assert "exactly ONE" in str(e)

        # --- noise scrubbing: identical bodies with different uuids/timestamps match ---
        n1 = normalize(200, {"date": "d1"}, '{"id":"550e8400-e29b-41d4-a716-446655440000","t":"2026-01-01T00:00:00Z"}')
        n2 = normalize(200, {"date": "d2"}, '{"id":"550e8400-e29b-41d4-a716-446655449999","t":"2026-09-09T12:00:00Z"}')
        assert n1["body_normalized"] == n2["body_normalized"]
        assert not compare(n1, n2)["body_changed"]

        del os.environ["A_TOK"], os.environ["B_TOK"]
    del os.environ["ARGUS_HOME"]
    print("differential demo passed")


def _tok(headers: dict) -> str:
    """Pull the raw token out of a 'Bearer <tok>' auth header, for the demo transport."""
    v = headers.get("Authorization", "")
    return v.split(" ", 1)[1] if " " in v else v


if __name__ == "__main__":
    demo()
