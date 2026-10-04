"""Test identities — ownership flag + credentials-as-reference (never stored)."""
import os

import pytest

from argus import campaign, identity, policy, scope
from argus.identity import ANONYMOUS, Identity
from argus.policy import Verdict


def test_identity_demo():
    identity.demo()


def test_credential_ref_rejects_a_pasted_secret():
    Identity(name="ok", credential_ref="ACME_TOKEN")        # valid env-var name
    with pytest.raises(ValueError):
        Identity(name="bad", credential_ref="ghp_longrealsecret value")


def test_cross_account_gate_reads_victim_ownership():
    pol = policy.EngagementPolicy(scope=scope.Scope(include=["acme.example"], exclude=[]))
    owned_victim = Identity(name="user_b", researcher_owned=True)
    real_victim = Identity(name="real_user", researcher_owned=False)
    # targeting your own test account's object: allowed, bounded
    d = pol.can_test("api.acme.example", "differential_cross_account", account=owned_victim)
    assert d.verdict is Verdict.ALLOW_WITH_LIMITS and d.limits["single_object"] is True
    # targeting a real user's object: needs human approval
    d2 = pol.can_test("api.acme.example", "differential_cross_account", account=real_victim)
    assert d2.verdict is Verdict.HUMAN_APPROVAL
    assert ANONYMOUS.researcher_owned      # anon baseline is always safe to act as


def test_registration_persists_reference_not_secret(tmp_path):
    os.environ["ARGUS_HOME"] = str(tmp_path)
    try:
        c = campaign.create("Assets:\napi.acme.example\n", name="Acme")
        identity.register(c, Identity(name="user_a", researcher_owned=True,
                                      credential_ref="ACME_USER_A_TOKEN"))
        on_disk = (c.dir / "identities.json").read_text()
        assert "ACME_USER_A_TOKEN" in on_disk          # the reference is stored
        os.environ["ACME_USER_A_TOKEN"] = "secret"
        assert identity.get(c, "user_a").resolve_credential() == "secret"
        assert "secret" not in (c.dir / "identities.json").read_text()   # the value is not
        del os.environ["ACME_USER_A_TOKEN"]
        assert any(a["event"] == "identity_registered" for a in c.audit_trail())
    finally:
        del os.environ["ARGUS_HOME"]
