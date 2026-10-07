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

occam: candidates are mined from PATH PARAMETERS only — the one traffic location where the
REST convention gives real provenance (a variable segment IS an object reference, and the
preceding collection segment names its type). Query/body/Location mining is the marked
upgrade path, gated on a real case where a path param is not enough, not a guess that one
exists. Ownership assertions persist in one ownership.json, exactly as identities.json.
"""
from __future__ import annotations

import datetime as _dt
import json
import re
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import traffic

# A prefixed object id: a short lowercase prefix, an underscore, then a body that MUST
# contain a digit (ord_123, inv_918, cus_ab12) — never a plain word like api_key. This is
# the resource layer's own provenance heuristic, intentionally BROADER than the route
# normalizer (which keeps prefixed ids literal) but still high-precision: a path segment
# matching it is almost always an object reference.
_PREFIXED_ID = re.compile(r"[a-z][a-z0-9]*_[0-9a-zA-Z]*[0-9][0-9a-zA-Z]*")

OWNERSHIP_STATES = ("CONFIRMED", "INFERRED")
# where a candidate came from — a closed vocab so provenance is never a free-text guess.
CANDIDATE_SOURCES = ("path parameter",)


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


def candidates(campaign) -> list[dict]:
    """All resource candidates mined from captured traffic, aggregated by (type, value).
    A projection: read-only, rebuilt on demand, provenance + confidence retained. Secrets
    never appear — path segments are identifiers, not credentials."""
    agg: dict[tuple[str, str], dict] = {}
    for cap in traffic.captures(campaign):
        ep_id = traffic._fingerprint(
            cap.get("method", ""), cap.get("host", ""),
            traffic.normalize_path(cap.get("path", "")))
        for cand in _path_candidates(cap):
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
