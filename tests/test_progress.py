"""CampaignProgress primitive + the control-plane read API.

The operator UI's live progress bar needs a durable, honest work-unit model: a
percentage that reflects VERIFIED completed work (never elapsed time), readable by
a separate process (the web API). These tests pin that contract.
"""
import importlib.util
import os
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _server():
    """Load web/server.py by path (it's a script, not a package module)."""
    spec = importlib.util.spec_from_file_location("argus_web_server", REPO / "web" / "server.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _probe_worker(t, cc):
    return ({"request": {"method": "GET", "url": f"https://{t.host}/", "headers": {}, "body": ""},
             "response": {"status": 200}}, "")


def test_orchestrator_progress_is_verified_work_not_time():
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["ARGUS_HOME"] = tmp
        from argus import campaign as cmod, orchestrator as omod

        c = cmod.create("Assets:\n*.acme.example\nRate: 2 requests/sec\n", name="Acme")
        orch = omod.Orchestrator(c)
        orch.register_worker("http_probe", _probe_worker)

        allowed = orch.propose(omod.Task(campaign_id=c.id, technique="http_probe",
                                         host="api.acme.example", hypothesis="up?"))
        orch.propose(omod.Task(campaign_id=c.id, technique="http_probe", host="evil.other.example"))
        orch.propose(omod.Task(campaign_id=c.id, technique="state_change", host="api.acme.example"))

        p = orch.progress()
        assert p["planned"] == 3
        assert p["queued"] == 1 and p["denied"] == 1 and p["approval_required"] == 1
        assert p["blocked"] == 0                                  # no dependency-blocked tasks
        assert p["percentage"] == 0 and p["completed"] == 0      # nothing verified yet
        assert p["state"] == "WAITING"

        orch.run()
        p = orch.progress()
        assert p["completed"] == 1 and p["percentage"] == 33     # 1 of 3 verified
        assert p["state"] == "BLOCKED"                           # risky task still awaiting approval
        assert p["last_completed"] == allowed.id

        # durable: a *separate* load (as the web API does) sees the same snapshot
        snap = cmod.load(c.id).progress()
        assert snap["source"] == "orchestrator"
        assert snap["completed"] == 1 and snap["percentage"] == 33
        del os.environ["ARGUS_HOME"]


def test_progress_derived_fallback_is_honest():
    """A campaign never run through the orchestrator has no snapshot; progress is
    derived from persisted experiments and labelled as such."""
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["ARGUS_HOME"] = tmp
        from argus import campaign as cmod
        from argus.campaign import Experiment

        c = cmod.create("Assets:\napi.acme.example\n", name="Acme")
        c.save_experiment(Experiment(campaign_id=c.id, hypothesis="x", technique="http_probe",
                                     host="api.acme.example", verdict="ALLOW", verdict_reason="",
                                     status="EVALUATED"))
        p = c.progress()
        assert p["source"] == "derived"
        assert p["planned"] == 1 and p["completed"] == 1 and p["percentage"] == 100
        del os.environ["ARGUS_HOME"]


def test_api_read_helpers_and_traversal_guard():
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["ARGUS_HOME"] = tmp
        from argus import campaign as cmod

        c = cmod.create("Assets:\napi.acme.example\nRate: 3 requests/sec\n", name="Acme")
        srv = _server()

        summary = srv._campaigns_summary()
        assert any(x["id"] == c.id for x in summary)
        assert all("progress" in x for x in summary)

        detail = srv._campaign_detail(c.id)
        assert detail is not None
        assert detail["id"] == c.id
        for key in ("policy", "progress", "experiments", "observations", "findings", "audit"):
            assert key in detail, key

        # a client-supplied id is validated against the listing before any path use
        assert srv._campaign_detail("../../etc/passwd") is None
        assert srv._campaign_detail("no-such-campaign") is None
        del os.environ["ARGUS_HOME"]


if __name__ == "__main__":
    test_orchestrator_progress_is_verified_work_not_time()
    test_progress_derived_fallback_is_honest()
    test_api_read_helpers_and_traversal_guard()
    print("progress tests passed")
