"""Campaign persistence — experiments and observations at the center, not findings.

The spec's one critical database idea: record what *didn't* become a vulnerability
too, so the system can reason over the whole search, not just the hits. So the
durable unit here is the Experiment (a bounded, authorized test) and its
Observations (the immutable request/response it produced) — a Finding is a later
interpretation layered on top, never the root record.

Mirrors store.py's discipline exactly: JSON under $ARGUS_HOME, stdlib only,
owner-only files (a campaign maps someone else's infrastructure). A campaign is a
directory; its audit log is append-only JSONL so every authorization decision and
state change is replayable after the fact. SQLite lands when a query needs it.

Provenance is the invariant (the spec's hard rule): an Experiment records WHY it
ran (hypothesis), WHICH policy verdict allowed it, WHICH identity executed it, and
WHAT it observed. Nothing here reasons — interpretation is NYX's job; this records,
faithfully enough to audit and reproduce, what ARGUS actually did.

occam: flat JSON + append-only JSONL, no ORM, no migrations — the same call the
author already made in store.py ("SQLite lands when a query needs it"). A query
that needs indexing is the trigger to change this, not a guess that it will.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import re
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import policy as policy_mod

_SLUG_RE = re.compile(r"[^a-z0-9._-]+")


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def _id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def _root() -> Path:
    """Where campaigns live. Owner-only, same rule as store._home: a campaign is a
    map of someone else's infrastructure plus the tests run against it."""
    base = os.environ.get("ARGUS_HOME") or os.path.join(os.path.expanduser("~"), ".argus")
    d = Path(base) / "campaigns"
    d.mkdir(parents=True, exist_ok=True)
    d.chmod(0o700)
    return d


def _write_private(path: Path, data: dict) -> None:
    path.touch(mode=0o600)                      # owner-only BEFORE any data lands
    path.write_text(json.dumps(data, indent=2))


# --- the records ----------------------------------------------------------
# Status vocab is the spec's finding-candidate lifecycle, applied to experiments:
# the string set is closed on purpose so a typo can't invent a state.
EXPERIMENT_STATES = (
    "CREATED", "POLICY_CHECKED", "DENIED", "APPROVAL_REQUIRED",
    "QUEUED", "RUNNING", "COMPLETED", "FAILED", "EVALUATED",
)
CLASSIFICATIONS = ("", "secure", "suspicious", "inconclusive", "vulnerable")


@dataclass
class Observation:
    """One immutable request/response an experiment produced. The raw record: it is
    never edited after capture — interpretation lives on the Experiment, not here.
    occam: body stored as a capped excerpt + full-length note; secret redaction is
    the evidence slice's job and plugs in at capture time."""
    experiment_id: str
    request: dict                               # {method, url, headers, body}
    response: dict                              # {status, headers, body_excerpt, body_len}
    id: str = field(default_factory=lambda: _id("obs"))
    captured_at: str = field(default_factory=_now)


@dataclass
class Experiment:
    """A bounded, authorized test. Carries its full provenance so a reviewer can
    answer every 'why' without re-running anything."""
    campaign_id: str
    hypothesis: str                             # WHY — the question this tests
    technique: str                             # WHAT kind of action
    host: str
    verdict: str                               # WHICH policy decision allowed/blocked it
    verdict_reason: str
    identity: str = ""                         # WHICH identity executed it ("" = anonymous)
    limits: dict | None = None                 # the clamp an ALLOW_WITH_LIMITS imposed
    mutation: dict | None = None               # WHAT changed from baseline (differential runner fills this)
    baseline_obs: str = ""                     # id of the baseline Observation, if any
    status: str = "CREATED"
    classification: str = ""                   # WHY classified so — secure/suspicious/...
    id: str = field(default_factory=lambda: _id("exp"))
    created_at: str = field(default_factory=_now)

    def __post_init__(self):
        if self.status not in EXPERIMENT_STATES:
            raise ValueError(f"bad experiment status {self.status!r}")
        if self.classification not in CLASSIFICATIONS:
            raise ValueError(f"bad classification {self.classification!r}")


# --- the campaign: a directory + an append-only audit log -----------------
class Campaign:
    def __init__(self, cid: str, program_text: str):
        self.id = cid
        self.program_text = program_text
        self.policy = policy_mod.compile(program_text)   # deterministic recompile
        self.created_at = _now()

    @property
    def dir(self) -> Path:
        d = _root() / self.id
        (d / "experiments").mkdir(parents=True, exist_ok=True)
        (d / "observations").mkdir(parents=True, exist_ok=True)
        d.chmod(0o700)
        return d

    # --- audit: append-only, one JSON object per line ---------------------
    def audit(self, event: str, **data) -> None:
        """Append one immutable audit line. Every authorization decision and state
        transition goes here; the file is only ever opened for append, never
        rewritten, so the trail cannot be silently edited."""
        line = json.dumps({"ts": _now(), "event": event, **data}, sort_keys=True)
        path = self.dir / "audit.jsonl"
        if not path.exists():
            path.touch(mode=0o600)
        with path.open("a") as f:
            f.write(line + "\n")

    def audit_trail(self) -> list[dict]:
        path = self.dir / "audit.jsonl"
        if not path.exists():
            return []
        return [json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()]

    # --- records ----------------------------------------------------------
    def save_experiment(self, exp: Experiment) -> Experiment:
        _write_private(self.dir / "experiments" / f"{exp.id}.json", asdict(exp))
        return exp

    def save_observation(self, obs: Observation) -> Observation:
        _write_private(self.dir / "observations" / f"{obs.id}.json", asdict(obs))
        return obs

    def experiments(self) -> list[dict]:
        return _load_all(self.dir / "experiments")

    def observations(self) -> list[dict]:
        return _load_all(self.dir / "observations")

    def _persist(self) -> None:
        _write_private(self.dir / "campaign.json",
                       {"id": self.id, "program_text": self.program_text,
                        "created_at": self.created_at, "policy": self.policy.to_dict()})


def _load_all(d: Path) -> list[dict]:
    out = []
    for fp in sorted(d.glob("*.json")):
        try:
            out.append(json.loads(fp.read_text()))
        except (OSError, ValueError):
            continue        # a corrupt record must not break the campaign
    return out


def create(program_text: str, name: str = "") -> Campaign:
    """Open a new campaign from a program page. The slug is the operator's name for
    it (or 'campaign'); the id adds a short uuid so two runs never collide."""
    slug = _SLUG_RE.sub("_", name.strip().lower()) or "campaign"
    c = Campaign(f"{slug}-{uuid.uuid4().hex[:8]}", program_text)
    c._persist()
    c.audit("campaign_created", campaign=c.id,
            in_scope=c.policy.scope.include_patterns(),
            out_of_scope=c.policy.scope.exclude_patterns())
    return c


def load(cid: str) -> Campaign:
    rec = json.loads((_root() / cid / "campaign.json").read_text())
    c = Campaign(rec["id"], rec["program_text"])
    c.created_at = rec.get("created_at", c.created_at)
    return c


def listing() -> list[str]:
    return sorted(p.name for p in _root().iterdir() if (p / "campaign.json").exists())


def demo() -> None:
    """Self-check: a campaign records an experiment + observation with provenance,
    and the audit trail is append-only and replayable. Uses a temp ARGUS_HOME."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["ARGUS_HOME"] = tmp
        c = create("Assets:\napi.acme.example\nRate: 2 requests/sec\n", name="Acme")
        # a policy decision, recorded with its provenance
        d = c.policy.can_test("api.acme.example", "http_probe")
        exp = c.save_experiment(Experiment(
            campaign_id=c.id, hypothesis="is the API internet-facing?",
            technique="http_probe", host="api.acme.example",
            verdict=d.verdict.value, verdict_reason=d.reason, status="POLICY_CHECKED"))
        c.audit("policy_decision", experiment=exp.id, host=exp.host,
                technique=exp.technique, verdict=exp.verdict)
        c.save_observation(Observation(
            experiment_id=exp.id,
            request={"method": "GET", "url": "https://api.acme.example/", "headers": {}, "body": ""},
            response={"status": 200, "headers": {"server": "nginx"}, "body_excerpt": "<title>Acme</title>", "body_len": 19}))

        assert c.experiments()[0]["hypothesis"] == "is the API internet-facing?"
        assert c.experiments()[0]["verdict"] == "ALLOW"
        assert c.observations()[0]["experiment_id"] == exp.id
        trail = c.audit_trail()
        assert trail[0]["event"] == "campaign_created"
        assert trail[1]["event"] == "policy_decision" and trail[1]["verdict"] == "ALLOW"
        # reload is lossless (policy recompiles deterministically)
        assert load(c.id).policy.scope.allows("api.acme.example")
        # closed state/classification vocab
        try:
            Experiment(campaign_id=c.id, hypothesis="x", technique="t", host="h",
                       verdict="ALLOW", verdict_reason="", status="BOGUS")
            raise AssertionError("bad status accepted")
        except ValueError:
            pass
    del os.environ["ARGUS_HOME"]
    print("campaign demo passed")


if __name__ == "__main__":
    demo()
