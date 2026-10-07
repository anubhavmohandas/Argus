"""Identity × Endpoint matrix — the first research-memory projection.

A deterministic READ MODEL over traffic ARGUS already captured. It answers one
question an expert hunter keeps in their head and ARGUS so far did not:

    for each normalized endpoint, which identities have actually been observed
    using it — and which have NOT?

It is a projection, never a new source of truth. The traffic store (captures =
evidence, endpoints = interpretation) remains authoritative; this recomputes from
it on demand. Nothing here touches a target, mutates a request, or reaches a
security conclusion. A cell carries EVIDENCE (counts, timestamps, sessions,
response classes, capture refs), not a verdict.

The one semantic that must never blur:

    observed      a capture by this identity on this endpoint exists
    unobserved    the endpoint is known, this identity has no capture on it

Absence of traffic is a research opportunity, NEVER "denied" / "unauthorized" /
"vulnerable". The column for an identity it was never observed from is ○, not red.

occam: computed from the capture list in one pass, indexed by (endpoint_id,
identity) — O(captures), not O(endpoints × captures × identities). No new files;
the matrix is derived, so it is rebuilt rather than persisted. The trigger to
persist it is a query that measurably needs an index, not a guess that one does.
"""
from __future__ import annotations

from . import identity as identity_mod, traffic

# Empty capture identity ("") is the unauthenticated dimension — mapped to the
# canonical ANONYMOUS identity name, never a fabricated Identity record.
ANON = identity_mod.ANONYMOUS.name          # "anonymous"
_SAMPLE_CAP = 5                             # bounded capture-ref window per cell


def _endpoint_id(cap: dict) -> str:
    """The endpoint a capture belongs to — the SAME fingerprint traffic.py stores
    endpoints under, so cells land exactly on existing endpoint rows."""
    return traffic._fingerprint(
        cap.get("method", ""), cap.get("host", ""),
        traffic.normalize_path(cap.get("path", "")))


def _ident_key(cap: dict) -> str:
    return (cap.get("identity") or "").strip() or ANON


def build(campaign) -> dict:
    """The full matrix projection for one campaign: identities (columns), endpoints
    (rows), observed cells, a research-coverage summary, and deterministic gaps.

    Only OBSERVED cells are emitted — the UI builds the grid as endpoints × identities
    and renders a missing cell as unobserved (○). This keeps the payload a projection,
    not thousands of raw captures.
    """
    endpoints = traffic.endpoints(campaign)                 # already newest-first
    caps = traffic.captures(campaign)

    # columns: declared identities first (stable order), then any identity that only
    # appears in captures (observed-but-undeclared), then anonymous if any anon traffic.
    declared = identity_mod.identities(campaign)
    declared_by_name = {i.name: i for i in declared}
    cols: list[str] = [i.name for i in declared]

    # one pass over captures -> cell accumulators keyed (endpoint_id, identity)
    cells: dict[tuple[str, str], dict] = {}
    for cap in caps:
        ep_id = _endpoint_id(cap)
        ikey = _ident_key(cap)
        if ikey not in declared_by_name and ikey not in cols:
            cols.append(ikey)                               # observed-only identity column
        cell = cells.get((ep_id, ikey))
        if cell is None:
            cell = cells[(ep_id, ikey)] = {
                "endpoint_id": ep_id, "identity": ikey, "observed": True,
                "request_count": 0, "first_seen": "", "last_seen": "",
                "sessions": [], "response_status_classes": [], "sample_capture_refs": [],
            }
        cell["request_count"] += 1
        ts = cap.get("captured_at", "")
        if ts and (not cell["first_seen"] or ts < cell["first_seen"]):
            cell["first_seen"] = ts
        if ts > cell["last_seen"]:
            cell["last_seen"] = ts
        sid = cap.get("session_id") or ""
        if sid and sid not in cell["sessions"]:
            cell["sessions"].append(sid)
        rc = traffic._status_class(cap.get("response_status"))
        if rc and rc not in cell["response_status_classes"]:
            cell["response_status_classes"].append(rc)
        if len(cell["sample_capture_refs"]) < _SAMPLE_CAP:
            cell["sample_capture_refs"].append(cap.get("id", ""))

    # identity column metadata — declared fields when known, else observed-only.
    identities = [_identity_col(name, declared_by_name, cells) for name in cols]

    ep_rows = [_endpoint_row(e, cells, cols) for e in endpoints]
    summary = _summary(ep_rows, cols, len(cells))
    gaps = _gaps(ep_rows)

    return {
        "campaign_id": campaign.id,
        "identities": identities,
        "endpoints": ep_rows,
        "cells": sorted(cells.values(), key=lambda c: (c["endpoint_id"], c["identity"])),
        "summary": summary,
        "gaps": gaps,
    }


def _identity_col(name, declared_by_name, cells) -> dict:
    ident = declared_by_name.get(name)
    if ident is None and name == ANON:
        ident = identity_mod.ANONYMOUS
    # endpoints this identity was observed on, and its activity window
    seen = [c for (ep_id, ik), c in cells.items() if ik == name]
    firsts = [c["first_seen"] for c in seen if c["first_seen"]]
    lasts = [c["last_seen"] for c in seen if c["last_seen"]]
    return {
        "name": name,
        "role": ident.role if ident else "",
        "tenant": ident.tenant if ident else "",
        "researcher_owned": bool(ident.researcher_owned) if ident else False,
        "declared": ident is not None and name in declared_by_name,
        "is_anonymous": name == ANON,
        "endpoints_observed": len({c["endpoint_id"] for c in seen}),
        "first_seen": min(firsts) if firsts else "",
        "last_seen": max(lasts) if lasts else "",
    }


def _endpoint_row(e: dict, cells, cols) -> dict:
    ep_id = e["id"]
    observed = [ik for ik in cols if (ep_id, ik) in cells]
    auth_observed = [ik for ik in observed if ik != ANON]
    return {
        "id": ep_id,
        "method": e.get("method", ""),
        "host": e.get("host", ""),
        "path_template": e.get("path_template", ""),
        "auth": e.get("auth", "unknown"),
        "obs_count": e.get("obs_count", 0),
        "query_params": e.get("query_params", []),
        "body_params": e.get("body_params", []),
        "response_classes": e.get("response_classes", []),
        "last_seen": e.get("last_seen", ""),
        "identities_observed": observed,                    # order follows the columns
        "anonymous_observed": ANON in observed,
        "authenticated_observed": bool(auth_observed),
    }


def _summary(ep_rows, cols, observed_cells) -> dict:
    n_ep, n_id = len(ep_rows), len(cols)
    possible = n_ep * n_id
    multi = sum(1 for r in ep_rows if len(r["identities_observed"]) >= 2)
    single = sum(1 for r in ep_rows if len(r["identities_observed"]) == 1)
    anon_only = sum(1 for r in ep_rows
                    if r["anonymous_observed"] and not r["authenticated_observed"])
    auth_only = sum(1 for r in ep_rows
                    if r["authenticated_observed"] and not r["anonymous_observed"])
    no_auth = sum(1 for r in ep_rows if not r["authenticated_observed"])
    return {
        "endpoints": n_ep,
        "identities": n_id,
        "possible_cells": possible,            # denominator = endpoints × identities
        "observed_cells": observed_cells,
        "unobserved_cells": max(0, possible - observed_cells),
        "multi_identity_endpoints": multi,
        "single_identity_endpoints": single,
        "anonymous_only_endpoints": anon_only,
        "authenticated_only_endpoints": auth_only,
        "endpoints_no_authenticated_observation": no_auth,
        # research coverage — NOT a security score. 90% covered != 90% secure.
        "research_coverage_pct": round(100 * observed_cells / possible) if possible else 0,
        "coverage_denominator": "endpoints x identities",
    }


def _gaps(ep_rows) -> list[dict]:
    """Deterministic endpoint-level research gaps — missing EVIDENCE, never findings.
    Per-cell ○ gaps are the matrix itself; these are the classifications worth a queue.
    One primary classification per endpoint (quality over volume — no per-cell noise)."""
    out = []
    for r in ep_rows:
        obs = r["identities_observed"]
        if not obs:
            continue
        if not r["authenticated_observed"]:                 # anon-only (or truly none)
            gtype, reason = "ANONYMOUS_ONLY", "only anonymous traffic observed; no authenticated identity"
        elif len(obs) == 1:
            gtype, reason = "ONLY_ONE_IDENTITY_OBSERVED", f"observed only as {obs[0]}; no comparison identity"
        else:
            continue                                        # multi-identity: already covered
        out.append({
            "endpoint_id": r["id"], "method": r["method"], "path_template": r["path_template"],
            "gap_type": gtype, "observed_identities": obs, "reason": reason,
            "status": "OPEN",
        })
    return out


def demo() -> None:
    """Self-check (offline, no network): two identities on /api/orders/{id} collapse to
    one endpoint row with two observed cells; 20 requests by one identity => one cell with
    count 20 (not 20 rows); an endpoint unseen by an identity is UNOBSERVED (absent from
    cells), never denied/vulnerable; anonymous traffic is a distinct column; the matrix is
    deterministic across rebuilds; no secret reaches the projection."""
    import os
    import tempfile
    from . import campaign as cmod, identity as imod
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["ARGUS_HOME"] = tmp
        c = cmod.create("In scope:\napi.acme.example\n", name="acme")
        imod.register(c, imod.Identity(name="user_a", role="customer", researcher_owned=True))
        imod.register(c, imod.Identity(name="user_b", role="customer", researcher_owned=True))

        base = "https://api.acme.example/api/orders"
        for i in range(20):                                 # 20 requests, one identity
            traffic.capture(c, method="GET", url=f"{base}/{i}",
                            headers={"Authorization": "Bearer supersecret"},
                            identity="user_a", response={"status": 200})
        traffic.capture(c, method="GET", url=f"{base}/999",
                        headers={"Cookie": "session=abc"}, identity="user_b",
                        response={"status": 403})
        # an action seen only as user_a -> single authenticated identity (a gap)
        traffic.capture(c, method="POST", url=f"{base}/7/cancel",
                        headers={"Authorization": "Bearer supersecret"},
                        identity="user_a", response={"status": 204})
        # anonymous hit on a different endpoint
        traffic.capture(c, method="GET", url="https://api.acme.example/api/health",
                        response={"status": 200})

        m = build(c)
        orders = next(r for r in m["endpoints"] if r["path_template"] == "/api/orders/{id}")
        a = next(cell for cell in m["cells"]
                 if cell["endpoint_id"] == orders["id"] and cell["identity"] == "user_a")
        assert a["request_count"] == 20, a                  # one cell, count 20 — not 20 rows
        assert set(orders["identities_observed"]) == {"user_a", "user_b"}

        # user_b never hit /api/health -> UNOBSERVED (absent from cells), NOT denied/vulnerable
        health = next(r for r in m["endpoints"] if r["path_template"] == "/api/health")
        assert "user_b" not in health["identities_observed"]
        assert all(not (cell["endpoint_id"] == health["id"] and cell["identity"] == "user_b")
                   for cell in m["cells"])
        assert health["anonymous_observed"] and not health["authenticated_observed"]

        # anonymous is its own column; declared identities carry role
        names = {col["name"] for col in m["identities"]}
        assert {"user_a", "user_b", ANON} <= names
        assert next(col for col in m["identities"] if col["name"] == "user_a")["role"] == "customer"

        # summary is honest research coverage, not a security score
        s = m["summary"]
        assert s["endpoints"] == 3 and s["observed_cells"] == 4
        assert s["coverage_denominator"] == "endpoints x identities"

        # gaps classify opportunities, never findings
        gtypes = {g["gap_type"] for g in m["gaps"]}
        assert "ONLY_ONE_IDENTITY_OBSERVED" in gtypes   # cancel: only user_a
        assert "ANONYMOUS_ONLY" in gtypes               # health
        assert all(g["status"] == "OPEN" for g in m["gaps"])

        # deterministic across rebuilds
        assert build(c) == m
        # no secret in the projection
        blob = str(m)
        assert "supersecret" not in blob and "session=abc" not in blob
    del os.environ["ARGUS_HOME"]
    print("matrix demo passed")


if __name__ == "__main__":
    demo()
