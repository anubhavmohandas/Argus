"""Traffic knowledge — teach ARGUS what the application actually looks like.

The first research-automation vertical slice, and deliberately NOT vulnerability testing:
before ARGUS can reason about authorization or ownership it must know which authenticated
endpoints have actually been observed, which parameters exist, and which identity used
them. This module turns one researcher-controlled captured request into durable knowledge.

The architectural split is the SAME one the rule engine draws between an Observation and
the graph:

    CapturedRequest   the raw request, exactly as captured — EVIDENCE, immutable
          |
    RequestTemplate   GET /users/123 + GET /users/456  ->  GET /users/{id}
                      — INTERPRETATION / index, upserted as more traffic arrives

The raw request is evidence; the endpoint template is an interpretation of it. They are
stored separately so a wrong generalization never corrupts the record of what was seen.

Secrets never enter the durable corpus. Sensitive request headers (Authorization, Cookie,
…) and sensitive query values (token, api_key, …) are redacted BEFORE anything is written
to disk; the authenticated context is referenced through a Session's credential-ref, never
copied here. Parameter NAMES are interpretation and are kept; parameter VALUES are evidence
and are only ever stored inside the capped, redacted capture body/url.

occam: a single conservative path-template heuristic (numeric / uuid / long-hex / mongo-id
segments -> {id}); it does NOT try to learn route shapes statistically. The trigger to make
it smarter is a real false-generalization a researcher hits, not a guess that one exists.
"""
from __future__ import annotations

import datetime as _dt
import re
import uuid
from dataclasses import asdict, dataclass, field
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from . import campaign as campaign_mod, session as session_mod

_write = campaign_mod._write_private        # one owner-only JSON write discipline, reused
_load_all = campaign_mod._load_all

_BODY_CAP = 4096                            # capped excerpt, same spirit as Observation

# Sensitive header NAMES (lower-cased) whose VALUE is redacted before persistence. A closed
# set: this is a security boundary, so it is explicit, not a heuristic that might miss one.
_SENSITIVE_HEADERS = frozenset({
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "api-key", "x-auth-token", "x-csrf-token", "x-xsrf-token",
    "authentication", "x-amz-security-token", "x-access-token",
})
# Sensitive query/body PARAM NAMES whose VALUE is redacted (the name is still kept — knowing
# a `token` param exists is useful; its value must never be stored).
_SENSITIVE_PARAMS = frozenset({
    "token", "access_token", "refresh_token", "id_token", "api_key", "apikey",
    "key", "secret", "password", "passwd", "pwd", "sig", "signature",
    "session", "sessionid", "sid", "auth", "code",
})
_REDACTED = "<redacted>"

# What marks a path segment as a variable (an id) rather than a route name. Conservative on
# purpose — over-generalizing collapses distinct routes into one false endpoint.
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
_HEXID = re.compile(r"[0-9a-f]{12,}", re.I)     # long hex blob (incl. 24-char mongo id)


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


# --- the records ----------------------------------------------------------
@dataclass
class CapturedRequest:
    """One captured request — immutable evidence. Secrets are already redacted when this is
    built; it is the record of what was observed, never edited after capture."""
    method: str
    scheme: str
    host: str
    path: str
    url: str                                # redacted (sensitive query values stripped)
    headers: dict                           # redacted (sensitive header values stripped)
    body_excerpt: str
    body_len: int
    identity: str = ""
    session_id: str = ""
    response_status: int | None = None
    response_content_type: str = ""
    source: str = "manual"
    id: str = field(default_factory=lambda: f"cap-{uuid.uuid4().hex[:12]}")
    captured_at: str = field(default_factory=_now)


@dataclass
class Endpoint:
    """The interpretation of captured requests to one normalized route — an index, upserted
    as traffic arrives. Carries NAMES and references, never raw values or secrets."""
    method: str
    scheme: str
    host: str
    path_template: str
    id: str                                 # stable fingerprint of (method, host, path_template)
    query_params: list = field(default_factory=list)
    body_params: list = field(default_factory=list)
    content_types: list = field(default_factory=list)
    identities: list = field(default_factory=list)
    session_ids: list = field(default_factory=list)
    auth: str = "unknown"                   # "required" | "none" | "unknown"
    response_classes: list = field(default_factory=list)   # "2xx" | "4xx" | ...
    sample_capture_ids: list = field(default_factory=list)  # evidence pointers (capped)
    obs_count: int = 0
    created_at: str = field(default_factory=_now)
    last_seen: str = field(default_factory=_now)


# --- normalization --------------------------------------------------------
def _is_variable(seg: str) -> bool:
    if not seg:
        return False
    if seg.isdigit():
        return True
    if _UUID.fullmatch(seg):
        return True
    if _HEXID.fullmatch(seg):
        return True
    return False


def normalize_path(path: str) -> str:
    """GET /users/123/orders/4 -> /users/{id}/orders/{id}. Variable segments only
    (numeric / uuid / long-hex); route names are left exactly as captured."""
    if not path:
        return "/"
    parts = path.split("/")
    return "/".join("{id}" if _is_variable(p) else p for p in parts) or "/"


def _fingerprint(method: str, host: str, template: str) -> str:
    import hashlib
    h = hashlib.sha1(f"{method} {host} {template}".encode()).hexdigest()[:12]
    return f"ep-{h}"


# --- redaction (the security boundary — explicit, before any disk write) --
def _redact_headers(headers: dict) -> dict:
    return {k: (_REDACTED if k.lower() in _SENSITIVE_HEADERS else v) for k, v in headers.items()}


def _redact_url(url: str) -> str:
    """Strip sensitive query VALUES (token=..., api_key=...) from the stored url; keep the
    param names so the shape is still visible."""
    s = urlsplit(url)
    if not s.query:
        return url
    pairs = [(k, _REDACTED if k.lower() in _SENSITIVE_PARAMS else v)
             for k, v in parse_qsl(s.query, keep_blank_values=True)]
    q = "&".join(f"{k}={v}" for k, v in pairs)
    return urlunsplit((s.scheme, s.netloc, s.path, q, s.fragment))


def _redact_body(body: str, content_type: str) -> str:
    """Redact sensitive PARAM VALUES in a stored body (password/token/…), so a request body
    is durable evidence without carrying a secret. Form and JSON bodies are redacted by key
    (JSON recursively); an opaque body is kept verbatim (no key structure to redact by)."""
    ct = (content_type or "").lower()
    if "application/x-www-form-urlencoded" in ct:
        pairs = [(k, _REDACTED if k.lower() in _SENSITIVE_PARAMS else v)
                 for k, v in parse_qsl(body, keep_blank_values=True)]
        return "&".join(f"{k}={v}" for k, v in pairs)
    if ("json" in ct or not ct) and body.strip()[:1] in ("{", "["):
        import json

        def walk(o):
            if isinstance(o, dict):
                return {k: (_REDACTED if str(k).lower() in _SENSITIVE_PARAMS else walk(v))
                        for k, v in o.items()}
            if isinstance(o, list):
                return [walk(v) for v in o]
            return o
        try:
            return json.dumps(walk(json.loads(body)))
        except ValueError:
            pass
    return body


def _header(headers: dict, name: str) -> str:
    for k, v in headers.items():
        if k.lower() == name:
            return v
    return ""


def _has_auth(headers: dict, session_id: str) -> bool:
    if session_id:
        return True
    return any(k.lower() in _SENSITIVE_HEADERS for k in headers)


def _param_names(query: str) -> list:
    return sorted({k for k, _ in parse_qsl(query, keep_blank_values=True)})


def _body_param_names(body: str, content_type: str) -> list:
    """Param NAMES only — values are evidence (kept in the capped capture body), names are
    interpretation (kept here). Handles form-encoded and flat JSON objects; anything else
    contributes no names (the raw body is still the evidence)."""
    ct = (content_type or "").lower()
    if "application/x-www-form-urlencoded" in ct:
        return sorted({k for k, _ in parse_qsl(body, keep_blank_values=True)})
    # JSON when the content type says so, OR when it is absent but the body plainly is a
    # JSON object (a pasted request often has no Content-Type) — never for other types.
    if ("json" in ct or not ct) and body.strip().startswith("{"):
        import json
        try:
            obj = json.loads(body)
            if isinstance(obj, dict):
                return sorted(str(k) for k in obj)
        except ValueError:
            pass
    return []


def _merge(dst: list, items) -> list:
    """Order-stable set-union: keep existing order, append genuinely new values."""
    seen = set(dst)
    for it in items:
        if it and it not in seen:
            dst.append(it)
            seen.add(it)
    return dst


# --- capture: one request -> evidence + an upserted interpretation --------
def capture(campaign, *, method: str, url: str, headers: dict | None = None, body: str = "",
            identity: str = "", session_id: str = "", response: dict | None = None,
            source: str = "manual") -> tuple[CapturedRequest, Endpoint]:
    """Turn one captured request into durable knowledge: persist the redacted raw request
    (evidence) and upsert the normalized endpoint it belongs to (interpretation). Links the
    identity/session; stamps the session's last_seen. Returns (capture, endpoint)."""
    headers = headers or {}
    response = response or {}
    method = method.upper().strip() or "GET"
    s = urlsplit(url)
    scheme = s.scheme or "https"
    host = s.netloc.lower()
    path = s.path or "/"
    content_type = _header(headers, "content-type")

    cap = CapturedRequest(
        method=method, scheme=scheme, host=host, path=path,
        url=_redact_url(url), headers=_redact_headers(headers),
        body_excerpt=_redact_body(body, content_type)[:_BODY_CAP], body_len=len(body),
        identity=identity, session_id=session_id,
        response_status=response.get("status"),
        response_content_type=str(response.get("content_type", "")),
        source=source)
    _save_capture(campaign, cap)

    template = normalize_path(path)
    ep = _upsert_endpoint(
        campaign, method=method, scheme=scheme, host=host, template=template,
        query_params=_param_names(s.query), body_params=_body_param_names(body, content_type),
        content_type=content_type, identity=identity, session_id=session_id,
        had_auth=_has_auth(headers, session_id),
        response_status=response.get("status"), cap_id=cap.id)

    if session_id:
        session_mod.touch(campaign, session_id)
    campaign.audit("traffic_captured", capture=cap.id, endpoint=ep.id, method=method,
                   host=host, path_template=template, identity=identity, session=session_id)
    return cap, ep


def _dir(campaign, name: str):
    d = campaign.dir / name
    d.mkdir(parents=True, exist_ok=True)
    return d


def _save_capture(campaign, cap: CapturedRequest) -> None:
    _write(_dir(campaign, "captures") / f"{cap.id}.json", asdict(cap))


def _status_class(status) -> str:
    try:
        return f"{int(status) // 100}xx"
    except (TypeError, ValueError):
        return ""


def _upsert_endpoint(campaign, *, method, scheme, host, template, query_params, body_params,
                     content_type, identity, session_id, had_auth, response_status, cap_id) -> Endpoint:
    ep_id = _fingerprint(method, host, template)
    path = _dir(campaign, "endpoints") / f"{ep_id}.json"
    if path.exists():
        import json
        ep = Endpoint(**json.loads(path.read_text()))
    else:
        ep = Endpoint(method=method, scheme=scheme, host=host, path_template=template, id=ep_id)

    _merge(ep.query_params, query_params)
    _merge(ep.body_params, body_params)
    _merge(ep.content_types, [content_type] if content_type else [])
    _merge(ep.identities, [identity] if identity else [])
    _merge(ep.session_ids, [session_id] if session_id else [])
    _merge(ep.response_classes, [_status_class(response_status)] if response_status else [])
    if len(ep.sample_capture_ids) < 10:        # a bounded window of evidence pointers
        ep.sample_capture_ids.append(cap_id)
    ep.obs_count += 1
    # auth is sticky: once a request on this route carried auth, the route is treated as
    # auth-required; a route only ever seen anonymously is "none"; untouched stays "unknown".
    if had_auth or ep.auth == "required":
        ep.auth = "required"
    elif ep.auth == "unknown":
        ep.auth = "none"
    ep.last_seen = _now()
    _write(path, asdict(ep))
    return ep


# --- read model (what the API / UI consumes) ------------------------------
def endpoints(campaign) -> list[dict]:
    """The endpoint catalog, newest-activity first — the SURFACE the UI renders."""
    rows = _load_all(_dir(campaign, "endpoints"))
    return sorted(rows, key=lambda e: e.get("last_seen", ""), reverse=True)


def captures(campaign) -> list[dict]:
    return _load_all(_dir(campaign, "captures"))


def endpoint(campaign, ep_id: str) -> dict | None:
    rows = {e["id"]: e for e in endpoints(campaign)}
    return rows.get(ep_id)


def captures_for(campaign, ep_id: str) -> list[dict]:
    """The evidence behind one endpoint — the captures whose normalized route matches it."""
    ep = endpoint(campaign, ep_id)
    if ep is None:
        return []
    out = []
    for c in captures(campaign):
        if (c.get("method") == ep["method"] and c.get("host") == ep["host"]
                and normalize_path(c.get("path", "")) == ep["path_template"]):
            out.append(c)
    return out


# --- HAR import: the first realistic researcher ingestion source ----------
def import_har(campaign, har: dict, *, identity: str = "", session_id: str = "",
               source: str = "har") -> list[Endpoint]:
    """Ingest a browser-exported HAR. Each entry's request becomes a CapturedRequest +
    endpoint upsert, exactly as a single capture would — so one real browsing session turns
    into a durable endpoint catalog. Entries without a usable request are skipped, not fatal."""
    out: list[Endpoint] = []
    for entry in (har.get("log", {}) or {}).get("entries", []) or []:
        req = entry.get("request") or {}
        url = req.get("url")
        if not url:
            continue
        headers = {h.get("name", ""): h.get("value", "") for h in req.get("headers", []) or []
                   if h.get("name")}
        post = req.get("postData") or {}
        body = post.get("text") or ""
        # HAR carries the body's content type on postData, not always as a header — use it
        # so JSON/form body params are still extracted when no Content-Type header is present.
        if post.get("mimeType") and not _header(headers, "content-type"):
            headers["Content-Type"] = post["mimeType"]
        resp = entry.get("response") or {}
        _, ep = capture(
            campaign, method=req.get("method", "GET"), url=url, headers=headers, body=body,
            identity=identity, session_id=session_id, source=source,
            response={"status": resp.get("status"),
                      "content_type": (resp.get("content") or {}).get("mimeType", "")})
        out.append(ep)
    return out


def demo() -> None:
    """Self-check (offline, no network): two captures of /api/orders/{id} as different
    identities collapse to ONE endpoint with both identities and params recorded; a secret
    in the Authorization header and a ?token= value never reach disk; the raw capture stays
    separate evidence. A HAR import produces the same durable endpoints."""
    import os
    import tempfile
    from . import campaign as cmod
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["ARGUS_HOME"] = tmp
        c = cmod.create("In scope:\napi.acme.example\n", name="acme")

        capture(c, method="GET", url="https://api.acme.example/api/orders/123?token=supersecret&fields=all",
                headers={"Authorization": "Bearer supersecret", "Content-Type": "application/json"},
                identity="user_a", response={"status": 200})
        cap2, ep = capture(c, method="GET", url="https://api.acme.example/api/orders/456",
                           headers={"Cookie": "session=abc"}, identity="user_b",
                           response={"status": 403})

        eps = endpoints(c)
        assert len(eps) == 1, eps                        # 123 and 456 collapsed to {id}
        e = eps[0]
        assert e["path_template"] == "/api/orders/{id}"
        assert set(e["identities"]) == {"user_a", "user_b"}
        assert "fields" in e["query_params"]
        assert e["auth"] == "required" and set(e["response_classes"]) == {"2xx", "4xx"}
        assert e["obs_count"] == 2

        # the secret never reached disk — not the token value, not the bearer
        corpus = "".join((c.dir / "captures" / f).read_text()
                         for f in os.listdir(c.dir / "captures"))
        assert "supersecret" not in corpus and "session=abc" not in corpus
        assert "<redacted>" in corpus
        # evidence (raw capture) is a separate record from the interpretation (endpoint)
        assert len(captures(c)) == 2
        assert captures_for(c, e["id"])[0]["method"] == "GET"

        # HAR import produces the same durable endpoints
        har = {"log": {"entries": [
            {"request": {"method": "POST", "url": "https://api.acme.example/api/orders/9/cancel",
                         "headers": [{"name": "Authorization", "value": "Bearer x"}],
                         "postData": {"text": "{\"reason\":\"fraud\"}"}},
             "response": {"status": 204, "content": {"mimeType": "application/json"}}}]}}
        import_har(c, har, identity="user_a")
        cancel = next(x for x in endpoints(c) if x["path_template"].endswith("/cancel"))
        assert cancel["method"] == "POST" and "reason" in cancel["body_params"]
    del os.environ["ARGUS_HOME"]
    print("traffic demo passed")


if __name__ == "__main__":
    demo()
