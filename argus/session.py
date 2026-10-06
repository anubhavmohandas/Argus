"""Sessions — a researcher-controlled authenticated context a capture belongs to.

A Session answers "who was this traffic captured as, and against what origin". It is
metadata ABOUT an authenticated context, never the context's secret: like an Identity,
it references a credential by ENV-VAR NAME, resolved at use time, so a pasted token is
rejected at the boundary instead of being written to disk. Secrets never enter the
durable research corpus — not here, not in a CapturedRequest, not in an endpoint
template, not in the audit log.

A Session optionally names a declared Identity (the account it acts as); the two are
distinct on purpose — one identity may hold several sessions (a re-login, a second
device), and the ownership/authorization decisions can_test makes read the Identity,
not the Session. This module is pure data + persistence, mirroring identity.py exactly.
"""
from __future__ import annotations

import datetime as _dt
import json
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .identity import _ENV_NAME       # same boundary rule: a credential is a var NAME, not a secret

SESSION_STATES = ("active", "expired", "revoked")
SESSION_SOURCES = ("manual", "har", "paste", "proxy", "browser")


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


@dataclass(frozen=True)
class Session:
    """An authenticated context. `credential_ref` is an ENV VAR NAME (never a secret);
    `identity` is the name of a declared Identity this session acts as (or "")."""
    id: str = field(default_factory=lambda: f"sess-{uuid.uuid4().hex[:12]}")
    identity: str = ""              # name of a declared Identity, or "" (anonymous/unknown)
    base_origin: str = ""           # scheme://host this session is scoped to
    auth_mechanism: str = ""        # "bearer" | "cookie" | "api_key" | "" — metadata only
    credential_ref: str = ""        # ENV VAR NAME holding the secret — never the secret itself
    status: str = "active"
    source: str = "manual"
    created_at: str = field(default_factory=_now)
    last_seen: str = field(default_factory=_now)

    def __post_init__(self):
        if self.credential_ref and not _ENV_NAME.fullmatch(self.credential_ref):
            raise ValueError(
                f"credential_ref {self.credential_ref!r} must be an ENV VAR NAME, not a secret value")
        if self.status not in SESSION_STATES:
            raise ValueError(f"bad session status {self.status!r}")
        if self.source not in SESSION_SOURCES:
            raise ValueError(f"bad session source {self.source!r}")


# --- persistence (single file in the campaign dir; secret stays in the environment) ---
# occam: one sessions.json rewritten per change, exactly as identities.json. A capture
# touches last_seen, so a very high capture volume would rewrite this file a lot — the
# trigger to split into per-session files, not a guess that it will.
def _path(campaign) -> Path:
    return campaign.dir / "sessions.json"


def _read(campaign) -> list[dict]:
    p = _path(campaign)
    return json.loads(p.read_text()) if p.exists() else []


def _write(campaign, records: list[dict]) -> None:
    p = _path(campaign)
    p.touch(mode=0o600)
    p.write_text(json.dumps(records, indent=2))


def register(campaign, session: Session) -> Session:
    """Declare (or replace, by id) a session. Persists only the credential REFERENCE."""
    by_id = {d["id"]: d for d in _read(campaign)}
    by_id[session.id] = asdict(session)
    _write(campaign, list(by_id.values()))
    campaign.audit("session_registered", session=session.id, identity=session.identity,
                   origin=session.base_origin, mechanism=session.auth_mechanism)
    return session


def touch(campaign, session_id: str) -> None:
    """Stamp last_seen when a capture arrives on a session. No-op for an unknown id."""
    recs = _read(campaign)
    hit = False
    for d in recs:
        if d["id"] == session_id:
            d["last_seen"] = _now()
            hit = True
    if hit:
        _write(campaign, recs)


def sessions(campaign) -> list[Session]:
    return [Session(**d) for d in _read(campaign)]


def get(campaign, session_id: str) -> Session | None:
    for s in sessions(campaign):
        if s.id == session_id:
            return s
    return None


def demo() -> None:
    import os
    import tempfile
    from . import campaign as campaign_mod
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["ARGUS_HOME"] = tmp
        c = campaign_mod.create("In scope:\napi.acme.example\n", name="acme")
        s = register(c, Session(identity="user_a", base_origin="https://api.acme.example",
                                 auth_mechanism="bearer", credential_ref="ACME_USER_A_TOKEN",
                                 source="har"))
        got = get(c, s.id)
        assert got and got.identity == "user_a" and got.credential_ref == "ACME_USER_A_TOKEN"
        # the credential REFERENCE is a var name — the secret is never on disk
        assert "ACME_USER_A_TOKEN" in _path(c).read_text()
        touch(c, s.id)
        assert get(c, s.id).last_seen >= s.created_at
        # a pasted secret as credential_ref is rejected at the boundary
        try:
            Session(credential_ref="eyJhbG real.token.value")
            raise AssertionError("secret accepted as credential_ref")
        except ValueError:
            pass
        # closed status/source vocab
        for bad in (lambda: Session(status="BOGUS"), lambda: Session(source="telepathy")):
            try:
                bad()
                raise AssertionError("bad vocab accepted")
            except ValueError:
                pass
    del os.environ["ARGUS_HOME"]
    print("session demo passed")


if __name__ == "__main__":
    demo()
