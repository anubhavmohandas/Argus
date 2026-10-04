"""Campaign persistence spine — experiments/observations at the center + audit."""
import json
import os

from argus import campaign


def test_campaign_demo_self_check():
    campaign.demo()                      # asserts provenance, reload, closed vocab


def test_audit_is_append_only(tmp_path):
    os.environ["ARGUS_HOME"] = str(tmp_path)
    try:
        c = campaign.create("Assets:\napi.acme.example\n", name="Acme")
        before = (c.dir / "audit.jsonl").read_text()
        c.audit("policy_decision", host="api.acme.example", verdict="DENY")
        after = (c.dir / "audit.jsonl").read_text()
        assert after.startswith(before)          # earlier lines are never rewritten
        assert after.endswith("\n") and len(c.audit_trail()) == 2
        # every line is independently valid JSON (replayable)
        for ln in after.splitlines():
            assert json.loads(ln)["ts"]
        assert c.id in campaign.listing()
    finally:
        del os.environ["ARGUS_HOME"]
