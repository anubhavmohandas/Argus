"""The `argus campaign` pipeline, driven through the real CLI entrypoint.

Proves the terminal flow wires up and stays safe: an out-of-scope diff never executes,
and a suspicious one promotes a finding that renders a report — all via main(argv).
"""
import os

import pytest

from argus import differential
from argus.cli import main


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_HOME", str(tmp_path))
    monkeypatch.setenv("A_TOK", "tok-a")
    monkeypatch.setenv("B_TOK", "tok-b")
    return tmp_path


def _new_campaign(tmp_path):
    f = tmp_path / "prog.txt"
    f.write_text("Assets:\napi.acme.example\nRate: 5 requests/sec\n")
    # capture the printed id
    import io
    import contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        assert main(["campaign", "new", str(f), "--name", "Acme"]) == 0
    return buf.getvalue().strip()


def test_new_identity_and_safe_gating(home, capsys):
    cid = _new_campaign(home)
    assert cid.startswith("acme-")
    assert main(["campaign", "identity", cid, "user_a", "--owned", "--cred", "A_TOK"]) == 0
    assert main(["campaign", "identity", cid, "user_b", "--owned", "--cred", "B_TOK"]) == 0
    capsys.readouterr()
    # out-of-scope host: parked, never executed
    main(["campaign", "diff", cid, "evil.example", "--baseline", "user_a", "--mutation", "user_b"])
    out = capsys.readouterr().out
    assert "not executed" in out and "DENY" in out


def test_cli_diff_routes_through_the_orchestrator(home, capsys):
    # The active CLI diff must PROPOSE a Task to the orchestrator, not call the runner
    # directly. The orchestrator is the only path that writes task_proposed + a
    # policy_decision to the audit trail, so their presence proves it was not bypassed —
    # and the DENY proves the parent task was gated, not just the per-request backstop.
    from argus import campaign as cmod
    cid = _new_campaign(home)
    main(["campaign", "identity", cid, "user_a", "--owned", "--cred", "A_TOK"])
    main(["campaign", "identity", cid, "user_b", "--owned", "--cred", "B_TOK"])
    capsys.readouterr()
    main(["campaign", "diff", cid, "evil.example", "--baseline", "user_a", "--mutation", "user_b"])
    events = [a["event"] for a in cmod.load(cid).audit_trail()]
    assert "task_proposed" in events          # went through orchestrator.propose
    assert "policy_decision" in events        # the parent task was gated by can_test


def test_pasted_secret_rejected_at_cli(home, capsys):
    cid = _new_campaign(home)
    rc = main(["campaign", "identity", cid, "bad", "--cred", "not a varname"])
    assert rc == 2
    assert "ENV VAR NAME" in capsys.readouterr().err


def test_suspicious_flow_promotes_and_reports(home, capsys, monkeypatch):
    cid = _new_campaign(home)
    main(["campaign", "identity", cid, "user_a", "--owned", "--cred", "A_TOK"])
    main(["campaign", "identity", cid, "user_b", "--owned", "--cred", "B_TOK"])
    capsys.readouterr()
    # inject a leaky server: B reaches A's object
    monkeypatch.setattr(differential, "_default_fetch",
                        lambda m, u, h, b: (200, {"content-type": "application/json"}, "{}"))
    main(["campaign", "diff", cid, "api.acme.example", "--baseline", "user_a",
          "--mutation", "user_b", "--path", "/api/orders/1/cancel", "--method", "POST",
          "--resource", "order_1", "--trials", "2"])
    out = capsys.readouterr().out
    assert "suspicious" in out and "finding find-" in out
    assert "REPRODUCED" in out                       # 2 trials, stable leak

    # the finding is listed and a report renders
    main(["campaign", "list", cid])
    listing = capsys.readouterr().out
    assert "REPRODUCIBLE" in listing
    fid = next(w for w in listing.split() if w.startswith("find-"))
    assert main(["campaign", "report", cid, fid]) == 0
    report_md = capsys.readouterr().out
    assert report_md.startswith("# ") and "## Evidence" in report_md


def test_show_projections_and_validate(home, capsys, monkeypatch):
    # CLI parity: every read-only projection the web exposes prints from the terminal,
    # and `validate` runs the earned lifecycle. Reuse the suspicious flow to earn a finding.
    cid = _new_campaign(home)
    main(["campaign", "identity", cid, "user_a", "--owned", "--cred", "A_TOK"])
    main(["campaign", "identity", cid, "user_b", "--owned", "--cred", "B_TOK"])
    monkeypatch.setattr(differential, "_default_fetch",
                        lambda m, u, h, b: (200, {"content-type": "application/json"}, "{}"))
    main(["campaign", "diff", cid, "api.acme.example", "--baseline", "user_a",
          "--mutation", "user_b", "--path", "/api/orders/1/cancel", "--method", "POST",
          "--resource", "order_1", "--trials", "2"])
    capsys.readouterr()

    for view in ("matrix", "resources", "coverage", "priority", "intel",
                 "proposals", "clusters", "triage", "endpoints"):
        assert main(["campaign", "show", cid, view]) == 0, view
        assert capsys.readouterr().out                       # a view never prints nothing

    # --json is the exact server payload: parseable, non-empty
    import json
    assert main(["campaign", "show", cid, "coverage", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["campaign_id"] == cid

    main(["campaign", "list", cid])
    fid = next(w for w in capsys.readouterr().out.split() if w.startswith("find-"))
    assert main(["campaign", "validate", cid, fid]) == 0
    assert "reached" in capsys.readouterr().out

    assert main(["campaign", "validate", cid, "find-nope"]) == 2  # unknown finding, clean exit


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
