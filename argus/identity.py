"""Identities — the authorized test accounts a campaign may act as.

ARGUS owns identities as DATA (the ARGUS/NYX split). The one security property that
matters: `researcher_owned` is True ONLY for accounts the researcher controls and
the program authorizes. can_test's cross-account row reads exactly this — reaching
identity V's object as someone else is approval-free ONLY when V is a
researcher-owned test account, so a differential test never touches a real user's
data without a human saying so. An identity is never auto-created from discovery;
the operator declares it.

Credentials are a REFERENCE, never a stored secret: an identity holds the *name* of
an environment variable, resolved at use time, so a campaign file never contains a
password or token. `credential_ref` is validated to be an env-var name precisely so
a pasted secret is rejected at the boundary instead of being written to disk.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path

_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


@dataclass(frozen=True)
class Identity:
    name: str                       # "user_a", "merchant_a", "anonymous"
    role: str = ""                  # customer / merchant / admin / ...
    researcher_owned: bool = False  # True ONLY for the researcher's own authorized test accounts
    credential_ref: str = ""        # ENV VAR NAME holding the secret — never the secret itself
    tenant: str = ""
    # How the resolved secret becomes a request header. The default is a bearer
    # token; a cookie/API-key auth is the real-world calibration knob: set
    # auth_header="Cookie", auth_template="session={}" (or "X-API-Key", "{}").
    auth_header: str = "Authorization"
    auth_template: str = "Bearer {}"

    def __post_init__(self):
        if self.credential_ref and not _ENV_NAME.fullmatch(self.credential_ref):
            raise ValueError(
                f"credential_ref {self.credential_ref!r} must be an ENV VAR NAME, not a secret value")
        if "{}" not in self.auth_template:
            raise ValueError(f"auth_template {self.auth_template!r} must contain '{{}}' for the secret")

    def resolve_credential(self) -> str | None:
        """The secret, read from the environment at use time. None if unset — a
        missing credential is 'unauthenticated', never a stored fallback."""
        return os.environ.get(self.credential_ref) if self.credential_ref else None

    def auth_headers(self) -> dict[str, str]:
        """The request header(s) that authenticate AS this identity, resolved at use
        time. Empty when no credential is set — that is the unauthenticated baseline
        (anonymous), never a silent fallback to someone else's session."""
        tok = self.resolve_credential()
        return {self.auth_header: self.auth_template.format(tok)} if tok else {}


# The unauthenticated baseline. Owned (it's no one's account) and credential-free:
# anonymous-vs-authenticated is the safest differential there is.
ANONYMOUS = Identity(name="anonymous", researcher_owned=True)


def both_researcher_owned(a: Identity, b: Identity) -> bool:
    """The cross-account safety predicate: a differential test between a and b is
    approval-free only when BOTH are the researcher's own authorized test accounts."""
    return bool(a.researcher_owned and b.researcher_owned)


# --- persistence (inside the campaign dir; secret stays in the environment) ---
def _path(campaign) -> Path:
    return campaign.dir / "identities.json"


def _read(campaign) -> list[dict]:
    p = _path(campaign)
    return json.loads(p.read_text()) if p.exists() else []


def register(campaign, identity: Identity) -> Identity:
    """Declare (or replace, by name) a test identity for a campaign. Persists only
    the reference, never a resolved secret; audits the declaration."""
    by_name = {d["name"]: d for d in _read(campaign)}
    by_name[identity.name] = asdict(identity)        # credential_ref is a var name, safe to store
    p = _path(campaign)
    p.touch(mode=0o600)
    p.write_text(json.dumps(list(by_name.values()), indent=2))
    campaign.audit("identity_registered", name=identity.name, role=identity.role,
                   researcher_owned=identity.researcher_owned)
    return identity


def identities(campaign) -> list[Identity]:
    return [Identity(**d) for d in _read(campaign)]


def get(campaign, name: str) -> Identity | None:
    for i in identities(campaign):
        if i.name == name:
            return i
    return None


def demo() -> None:
    import tempfile
    from . import campaign as campaign_mod
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["ARGUS_HOME"] = tmp
        c = campaign_mod.create("Assets:\napi.acme.example\n", name="Acme")
        register(c, Identity(name="user_a", role="customer", researcher_owned=True,
                             credential_ref="ACME_USER_A_TOKEN"))
        register(c, Identity(name="user_b", role="customer", researcher_owned=True))
        got = get(c, "user_a")
        assert got.researcher_owned and got.credential_ref == "ACME_USER_A_TOKEN"
        assert got.resolve_credential() is None          # env unset => unauthenticated, no fallback
        os.environ["ACME_USER_A_TOKEN"] = "secret-xyz"
        assert get(c, "user_a").resolve_credential() == "secret-xyz"
        del os.environ["ACME_USER_A_TOKEN"]
        # the secret is never on disk — only the var name is
        assert "secret-xyz" not in _path(c).read_text()
        assert both_researcher_owned(get(c, "user_a"), get(c, "user_b"))
        assert both_researcher_owned(ANONYMOUS, get(c, "user_a"))
        # a pasted secret as credential_ref is rejected at the boundary
        try:
            Identity(name="bad", credential_ref="eyJ0eXAiOiJKV1Q. real.token")
            raise AssertionError("secret accepted as credential_ref")
        except ValueError:
            pass
    del os.environ["ARGUS_HOME"]
    print("identity demo passed")


if __name__ == "__main__":
    demo()
