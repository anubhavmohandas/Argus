"""Resource / object knowledge — the second research-memory layer.

Authorization bugs are rarely identity × endpoint alone; they are identity × action ×
RESOURCE × ownership × boundary. Before ARGUS can reason about a boundary it must know
which objects the captured traffic actually referenced. This module gives it two things,
kept deliberately separate:

    resource CANDIDATE   mined from captured traffic — a PROJECTION, rebuilt on demand,
                         carrying provenance (where it was seen) + a confidence, never a
                         claim. Absence of a candidate is not a claim either.

    ownership ASSERTION  DURABLE, operator-entered trusted metadata: "resource ord_123 is
                         an order owned by customer_a, researcher-controlled". This is the
                         only thing that may mark a resource researcher-controlled.

The security invariant (the spec's hard rule): researcher_controlled is NEVER inferred.
An inferred ownership is stored with ownership_status=INFERRED and can never satisfy the
cross-account execution predicate — only an explicit CONFIRMED assertion can. A resource
with no assertion has an UNKNOWN owner, and unknown is a normal, first-class state, never
a warning.

occam: candidates are mined from the request locations whose evidence is actually persisted
in the capture — PATH parameters, QUERY parameters, and the redacted request BODY. All
three are NAME-GATED: a value becomes a candidate only when it sits under a field whose name
is an object reference (a path collection segment, or an `*_id`/`id`/`orderId` field), never
because it merely looks like a uuid/int. RESPONSE-field and Location-header mining remain the
marked upgrade path — they are gated not on taste but on evidence: the capture model does not
yet persist sanitized response bodies/headers, so there is nothing to mine. Lift that gate by
extending the capture record (and its redaction boundary), not by guessing. Ownership
assertions persist in one ownership.json, exactly as identities.json.
"""
from __future__ import annotations

import datetime as _dt
import json
import re
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from . import traffic

# A prefixed object id: a short lowercase prefix, an underscore, then a body that MUST
# contain a digit (ord_123, inv_918, cus_ab12) — never a plain word like api_key. This is
# the resource layer's own provenance heuristic, intentionally BROADER than the route
# normalizer (which keeps prefixed ids literal) but still high-precision: a path segment
# matching it is almost always an object reference.
_PREFIXED_ID = re.compile(r"[a-z][a-z0-9]*_[0-9a-zA-Z]*[0-9][0-9a-zA-Z]*")

OWNERSHIP_STATES = ("CONFIRMED", "INFERRED")
# where a candidate came from — a closed vocab so provenance is never a free-text guess.
CANDIDATE_SOURCES = ("path parameter", "query parameter", "request body")

# A field NAME that denotes an object reference: bare `id`/`uuid`/`guid`, snake `order_id`,
# or camel `orderId`. The `_` / case boundary is REQUIRED (so `valid`, `android`, `rapid` are
# not swept in). This is the query/body analogue of the path-collection convention: the name,
# not the value, is what makes a candidate — a lone uuid under `page` is never a resource.
_SNAKE_ID = re.compile(r"(?:([a-z0-9]+)_)?(?:id|uuid|guid)")
_CAMEL_ID = re.compile(r"([a-z][a-z0-9]*)(?:Id|Uuid|Guid|UUID|GUID)")


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


# --- durable ownership assertion ------------------------------------------
@dataclass(frozen=True)
class Ownership:
    """An explicit ownership assertion about a resource. `researcher_controlled` is trusted
    metadata the operator (or an ARGUS-created resource) sets — it is NEVER inferred. An
    INFERRED assertion is forced non-controlled: a guess can never authorize cross-account
    execution; only a CONFIRMED assertion can."""
    resource_type: str
    resource_value: str
    owner_identity: str = ""
    tenant: str = ""
    researcher_controlled: bool = False
    ownership_status: str = "CONFIRMED"         # CONFIRMED | INFERRED
    confidence: float = 1.0                     # 0..1
    source: str = "operator"                    # operator | created | inferred
    note: str = ""
    id: str = field(default_factory=lambda: f"own-{uuid.uuid4().hex[:12]}")
    created_at: str = field(default_factory=_now)

    def __post_init__(self):
        if not self.resource_value.strip():
            raise ValueError("ownership assertion needs a resource_value")
        if self.ownership_status not in OWNERSHIP_STATES:
            raise ValueError(f"bad ownership_status {self.ownership_status!r}")
        if not (0.0 <= float(self.confidence) <= 1.0):
            raise ValueError("confidence must be in [0,1]")
        # the invariant: an inferred ownership can never be researcher-controlled.
        if self.ownership_status == "INFERRED" and self.researcher_controlled:
            object.__setattr__(self, "researcher_controlled", False)

    def controlled_for_crossaccount(self) -> bool:
        """The ONLY ownership state that may make a cross-account test approval-free:
        an explicit, CONFIRMED, researcher-controlled assertion. An inference never does."""
        return self.researcher_controlled and self.ownership_status == "CONFIRMED"


def _key(resource_type: str, resource_value: str) -> str:
    return f"{resource_type}\u0000{resource_value}"


def _path(campaign) -> Path:
    return campaign.dir / "ownership.json"


def _read(campaign) -> list[dict]:
    p = _path(campaign)
    return json.loads(p.read_text()) if p.exists() else []


def assert_ownership(campaign, own: Ownership) -> Ownership:
    """Declare (or replace, by resource type+value) an ownership assertion. Persisted
    owner-only, audited. The newest assertion for a (type,value) wins."""
    by_key = {_key(d["resource_type"], d["resource_value"]): d for d in _read(campaign)}
    by_key[_key(own.resource_type, own.resource_value)] = asdict(own)
    p = _path(campaign)
    p.touch(mode=0o600)
    p.write_text(json.dumps(list(by_key.values()), indent=2))
    campaign.audit("ownership_asserted", resource_type=own.resource_type,
                   resource_value=own.resource_value, owner=own.owner_identity,
                   researcher_controlled=own.researcher_controlled,
                   ownership_status=own.ownership_status)
    return own


def ownerships(campaign) -> list[Ownership]:
    return [Ownership(**d) for d in _read(campaign)]


def ownership_for(campaign, resource_type: str, resource_value: str) -> Ownership | None:
    k = _key(resource_type, resource_value)
    for d in _read(campaign):
        if _key(d["resource_type"], d["resource_value"]) == k:
            return Ownership(**d)
    return None


# --- candidate extraction (projection over captured traffic) --------------
def _singular(seg: str) -> str:
    """orders -> order, companies -> company, addresses -> address. Conservative; the raw
    segment is always retained so a wrong guess is visible and recoverable."""
    s = seg.lower()
    if s.endswith("ies") and len(s) > 3:
        return s[:-3] + "y"
    if s.endswith(("ses", "xes", "zes", "ches", "shes")):
        return s[:-2]
    if s.endswith("s") and not s.endswith("ss") and len(s) > 1:
        return s[:-1]
    return s


def _is_resource_id(seg: str) -> bool:
    """A path segment that is an object reference: a numeric / uuid / long-hex id (as the
    route normalizer sees it) OR a prefixed id (ord_123). Not a plain route name."""
    return traffic._is_variable(seg) or bool(_PREFIXED_ID.fullmatch(seg))


def _looks_like_collection(seg: str) -> bool:
    # a collection name is alphabetic-ish and not a version/opaque route token
    return bool(seg) and seg.replace("_", "").replace("-", "").isalpha() and len(seg) > 2 \
        and seg.lower() not in ("api", "www")


def _path_candidates(cap: dict) -> list[dict]:
    """Variable path segments as resource references. The preceding collection segment names
    the type (orders/123 -> order), which stays UNKNOWN for an opaque/variable predecessor —
    an opaque id never hallucinates a type."""
    path = cap.get("path", "") or ""
    parts = path.split("/")
    out = []
    for i, seg in enumerate(parts):
        if not _is_resource_id(seg):
            continue
        prev = parts[i - 1] if i > 0 else ""
        if _looks_like_collection(prev):
            rtype = _singular(prev)
            field_name, confidence = f"{rtype}_id", "medium"
        else:
            rtype, field_name, confidence = "unknown", "", "low"
        out.append({
            "value": seg, "resource_type": rtype, "field": field_name,
            "raw_segment": prev, "source": "path parameter", "confidence": confidence,
        })
    return out


def _id_field_prefix(key: str) -> str | None:
    """Classify a param/field NAME. Returns the type-naming prefix for an object-reference
    field (`order_id`->'order', `orderId`->'order'), "" for a bare `id`/`uuid`/`guid` (an
    object ref whose type the name does not give), or None if the name is not a reference."""
    m = _SNAKE_ID.fullmatch(key.lower())
    if m:
        return m.group(1) or ""
    m = _CAMEL_ID.fullmatch(key)
    if m:
        return m.group(1)
    return None


def _ref_candidate(key: str, value, source: str) -> dict | None:
    """A (name, value) pair becomes a candidate only when the NAME is an object reference and
    the VALUE is id-shaped (and not a redacted secret). Type comes from the name prefix; a
    bare `id` stays type 'unknown' — an opaque reference never hallucinates a type."""
    prefix = _id_field_prefix(key)
    if prefix is None:
        return None
    val = str(value).strip()
    if not val or val == traffic._REDACTED or not _is_resource_id(val):
        return None
    if prefix:
        return {"value": val, "resource_type": _singular(prefix), "field": key,
                "raw_segment": key, "source": source, "confidence": "medium"}
    return {"value": val, "resource_type": "unknown", "field": key,
            "raw_segment": key, "source": source, "confidence": "low"}


def _query_candidates(cap: dict) -> list[dict]:
    """Object references in the (redacted) query string: ?order_id=ord_1 -> order ord_1.
    Redacted sensitive values are already stripped and are skipped by _ref_candidate."""
    q = urlsplit(cap.get("url", "") or "").query
    out = []
    for k, v in parse_qsl(q, keep_blank_values=True):
        c = _ref_candidate(k, v, "query parameter")
        if c:
            out.append(c)
    return out


def _walk_scalars(obj, _depth: int = 0):
    """Yield (key, scalar) for every scalar under a named key in a JSON value. Recurses dicts
    and dicts-in-lists; bodies are already capped at capture, so no explicit size guard."""
    if _depth > 6:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                yield from _walk_scalars(v, _depth + 1)
            else:
                yield str(k), v
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_scalars(v, _depth + 1)


def _body_candidates(cap: dict) -> list[dict]:
    """Object references in the (redacted) request body — JSON object/array fields, or form
    keys. Interpretation only; the body excerpt itself remains the evidence of record."""
    body = (cap.get("body_excerpt", "") or "").strip()
    if not body:
        return []
    out = []
    if body[:1] in ("{", "["):
        try:
            obj = json.loads(body)
        except ValueError:
            return []                       # truncated/opaque body -> no candidates, no guess
        for k, v in _walk_scalars(obj):
            c = _ref_candidate(k, v, "request body")
            if c:
                out.append(c)
    else:
        for k, v in parse_qsl(body, keep_blank_values=True):
            c = _ref_candidate(k, v, "request body")
            if c:
                out.append(c)
    return out


def candidates(campaign) -> list[dict]:
    """All resource candidates mined from captured traffic, aggregated by (type, value).
    A projection: read-only, rebuilt on demand, provenance + confidence retained. Secrets
    never appear — path segments are identifiers, not credentials."""
    agg: dict[tuple[str, str], dict] = {}
    for cap in traffic.captures(campaign):
        ep_id = traffic._fingerprint(
            cap.get("method", ""), cap.get("host", ""),
            traffic.normalize_path(cap.get("path", "")))
        for cand in _path_candidates(cap) + _query_candidates(cap) + _body_candidates(cap):
            key = (cand["resource_type"], cand["value"])
            row = agg.get(key)
            if row is None:
                row = agg[key] = {
                    "resource_type": cand["resource_type"], "value": cand["value"],
                    "fields": [], "sources": [], "confidence": cand["confidence"],
                    "endpoint_refs": [], "capture_refs": [], "observations": 0,
                    "first_seen": "", "last_seen": "",
                }
            if cand["field"] and cand["field"] not in row["fields"]:
                row["fields"].append(cand["field"])
            if cand["source"] not in row["sources"]:
                row["sources"].append(cand["source"])
            # keep the strongest confidence seen for this resource
            row["confidence"] = _max_conf(row["confidence"], cand["confidence"])
            if ep_id and ep_id not in row["endpoint_refs"]:
                row["endpoint_refs"].append(ep_id)
            cid = cap.get("id", "")
            if cid and len(row["capture_refs"]) < 10:
                row["capture_refs"].append(cid)
            row["observations"] += 1
            ts = cap.get("captured_at", "")
            if ts and (not row["first_seen"] or ts < row["first_seen"]):
                row["first_seen"] = ts
            if ts > row["last_seen"]:
                row["last_seen"] = ts
    return sorted(agg.values(), key=lambda r: (r["resource_type"], r["value"]))


_CONF_RANK = {"low": 0, "medium": 1, "high": 2}


def _max_conf(a: str, b: str) -> str:
    return a if _CONF_RANK.get(a, 0) >= _CONF_RANK.get(b, 0) else b


# --- merged read model (candidates overlaid with ownership assertions) ----
def resources(campaign) -> list[dict]:
    """The Resources surface: every observed candidate, overlaid with its ownership
    assertion when one exists. A resource with no assertion has owner UNKNOWN and is NOT
    researcher-controlled — unknown is a normal state, never a warning or a guess."""
    owned = {_key(o.resource_type, o.resource_value): o for o in ownerships(campaign)}
    out = []
    for cand in candidates(campaign):
        o = owned.pop(_key(cand["resource_type"], cand["value"]), None)
        out.append(_merge_row(cand, o))
    # ownership assertions about resources never seen in traffic (e.g. ARGUS-created) still
    # surface — honest about objects the operator declared but no capture referenced yet.
    for o in owned.values():
        out.append(_merge_row(None, o))
    return out


def _merge_row(cand: dict | None, o: Ownership | None) -> dict:
    base = cand or {"resource_type": o.resource_type, "value": o.resource_value,
                    "fields": [], "sources": [], "confidence": "", "endpoint_refs": [],
                    "capture_refs": [], "observations": 0, "first_seen": "", "last_seen": ""}
    return {
        **base,
        "observed": cand is not None,
        "owner_identity": o.owner_identity if o else "",
        "tenant": o.tenant if o else "",
        "researcher_controlled": bool(o.researcher_controlled) if o else False,
        "ownership_status": o.ownership_status if o else "",      # "" = unknown
        "ownership_confidence": float(o.confidence) if o else None,
        "ownership_source": o.source if o else "",
        "ownership_note": o.note if o else "",
        "owner_known": bool(o and o.owner_identity),
    }


def demo() -> None:
    """Self-check (offline): path params become candidates with provenance + a type inferred
    from the collection segment; an opaque id stays type 'unknown'; a resource with no
    assertion is UNKNOWN owner and NOT researcher-controlled; an explicit CONFIRMED
    assertion marks it controlled; an INFERRED assertion can never be controlled."""
    import os
    import tempfile
    from . import campaign as cmod
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["ARGUS_HOME"] = tmp
        c = cmod.create("In scope:\napi.acme.example\n", name="acme")

        traffic.capture(c, method="POST",
                        url="https://api.acme.example/api/orders/ord_123/cancel",
                        headers={"Authorization": "Bearer s"}, identity="customer_a",
                        response={"status": 204})
        traffic.capture(c, method="GET",
                        url="https://api.acme.example/api/507f1f77bcf86cd799439011",
                        identity="customer_a", response={"status": 200})

        cands = {(x["resource_type"], x["value"]): x for x in candidates(c)}
        order = cands[("order", "ord_123")]
        assert order["fields"] == ["order_id"]
        assert order["sources"] == ["path parameter"] and order["confidence"] == "medium"
        # an opaque id with no collection segment infers NO type — unknown stays unknown
        assert ("unknown", "507f1f77bcf86cd799439011") in cands

        # query + body mining (Resource Discovery V2), all NAME-gated:
        traffic.capture(c, method="GET",
                        url="https://api.acme.example/api/search?order_id=ord_55&page=2&token=sek",
                        identity="customer_a", response={"status": 200})
        traffic.capture(c, method="POST", url="https://api.acme.example/api/transfer",
                        headers={"Content-Type": "application/json"},
                        body='{"invoice_id":"inv_9","amount":100,"note":"valid","order":{"id":"ord_77"}}',
                        identity="customer_a", response={"status": 200})
        cands = {(x["resource_type"], x["value"]): x for x in candidates(c)}
        # query: order_id value is mined as an order; page=2 is NOT (name is not a reference);
        # the redacted token value is skipped.
        q = cands[("order", "ord_55")]
        assert "query parameter" in q["sources"] and q["confidence"] == "medium"
        assert ("unknown", "2") not in cands and ("order", "2") not in cands
        assert all(v != "<redacted>" for (_t, v) in cands)
        # body: invoice_id -> invoice; amount/note never swept in; a bare nested `id` keeps
        # its value but stays type unknown (the name gives no type).
        assert "request body" in cands[("invoice", "inv_9")]["sources"]
        assert not any(v == "100" or v == "valid" for (_t, v) in cands)
        assert ("unknown", "ord_77") in cands

        # no assertion => unknown owner, never researcher-controlled
        rows = {(r["resource_type"], r["value"]): r for r in resources(c)}
        assert rows[("order", "ord_123")]["ownership_status"] == ""
        assert rows[("order", "ord_123")]["researcher_controlled"] is False
        assert rows[("order", "ord_123")]["owner_known"] is False

        # explicit CONFIRMED controlled assertion
        assert_ownership(c, Ownership(resource_type="order", resource_value="ord_123",
                                      owner_identity="customer_a", tenant="tenant_a",
                                      researcher_controlled=True))
        r = {(x["resource_type"], x["value"]): x for x in resources(c)}[("order", "ord_123")]
        assert r["researcher_controlled"] and r["owner_identity"] == "customer_a"
        assert ownership_for(c, "order", "ord_123").controlled_for_crossaccount()

        # an INFERRED assertion is forced non-controlled and cannot authorize cross-account
        inf = Ownership(resource_type="order", resource_value="ord_999",
                        owner_identity="customer_b", researcher_controlled=True,
                        ownership_status="INFERRED", confidence=0.72, source="inferred")
        assert inf.researcher_controlled is False
        assert not inf.controlled_for_crossaccount()

        # a pasted empty value / bad status is rejected at the boundary
        for bad in (lambda: Ownership(resource_type="order", resource_value="  "),
                    lambda: Ownership(resource_type="o", resource_value="x", ownership_status="MAYBE")):
            try:
                bad()
                raise AssertionError("bad ownership accepted")
            except ValueError:
                pass
    del os.environ["ARGUS_HOME"]
    print("resource demo passed")


if __name__ == "__main__":
    demo()
