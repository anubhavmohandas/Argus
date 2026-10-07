#!/usr/bin/env python3
"""
Argus web API — stdlib only, zero runtime dependencies.

Honors Argus's prime principle (GOAL.md): "No new runtime dependency for
anything stdlib can do." This is a thin HTTP + Server-Sent-Events layer over
the existing `argus` CLI engine. It does not reimplement any recon logic — it
spawns `python3 -m argus pivot <seed> --json <flags>`, streams the engine's
own `[argus]` status lines live to the browser, and hands back the final
node/edge/finding graph as JSON.

Run from the repo root (the parent of this `web/` dir):

    python3 web/server.py                 # serves API on 127.0.0.1:8787
    python3 web/server.py --port 9000
    python3 web/server.py --host 0.0.0.0  # expose on LAN (see the warning below)

The React frontend (web/frontend) talks to this. In dev, Vite proxies /api to
this server; in prod, run `npm run build` and this server also serves the built
static files from web/frontend/dist.

SECURITY
- Binds to 127.0.0.1 by default. Argus itself can send active traffic at the
  --probe/--scan tiers, so only expose this beyond localhost on a network you
  control and against targets you are authorized to test.
- The seed is passed to the engine as a subprocess argv element (never through a
  shell), so it cannot inject commands. The engagement level is checked against
  a fixed allowlist. Argus's own SSRF guard still runs before every outbound
  request — this layer does not weaken it.
"""
from __future__ import annotations

import argparse
import json
import os
import queue
import shlex
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

REPO_ROOT = Path(__file__).resolve().parent.parent
FRONTEND_DIST = Path(__file__).resolve().parent / "frontend" / "dist"

# Serializes campaign WRITES (create / identity / task decisions) so two concurrent
# HTTP threads never interleave rewrites of one campaign's durable task table.
# occam: one global lock — campaigns are single-operator; swap for a per-campaign lock
# only if the API ever serves enough concurrent writers for this to be a bottleneck.
_WRITE_LOCK = threading.Lock()

# Engagement level -> engine flags. Mirrors the CLI interactive menu in
# argus/cli.py so the web UI and the terminal stay in lockstep.
LEVELS: dict[str, list[str]] = {
    "passive":     [],                                  # public sources only, never touches target
    "active":      ["--probe", "--cve"],                # connect to hosts + live CVEs
    "active-plus": ["--probe-paths", "--cve"],          # + request admin / sensitive paths
    "full":        ["--probe-paths", "--scan", "--cve"],# + TCP port scan (loudest)
}

# Modules exposed to the UI (run via `argus run <name> <target>`), allowlisted
# on purpose — the UI cannot run an arbitrary module name. Grouped so the UI can
# render a "secret recon" panel and a "utility" panel separately.
SECRET_MODULES = {"postman_dork", "github_dork", "github_org", "jsmap"}
UTILITY_MODULES = {"ip", "phone", "username", "secrets", "dns", "rdap", "subdomains", "wayback"}
ALLOWED_MODULES = SECRET_MODULES | UTILITY_MODULES

_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js":   "application/javascript; charset=utf-8",
    ".css":  "text/css; charset=utf-8",
    ".svg":  "image/svg+xml",
    ".json": "application/json; charset=utf-8",
    ".ico":  "image/x-icon",
    ".png":  "image/png",
    ".woff2": "font/woff2",
    ".map":  "application/json",
}


def _sanitize_seed(seed: str) -> str:
    seed = (seed or "").strip()
    if not seed or len(seed) > 255:
        raise ValueError("seed must be 1-255 characters")
    # No control chars / whitespace inside a seed. It is passed as an argv
    # element (no shell), so this is belt-and-braces, not the only guard.
    if any(ord(c) < 0x20 for c in seed) or " " in seed:
        raise ValueError("seed contains illegal characters")
    return seed


def _build_argv(seed: str, level: str, opts: dict) -> list[str]:
    if level not in LEVELS:
        raise ValueError(f"unknown engagement level: {level!r}")
    # /api/stream is the PASSIVE public-discovery path only. Active engagement must run as
    # a campaign through the coordinator (POST /api/campaign/{id}/pivot) so it is durable,
    # controllable, and approval-gated — there is no second web-active execution engine.
    # Defence-in-depth: the GET handler already rejects this; this is the last chokepoint.
    if level != "passive":
        raise ValueError("active engagement must run as a campaign "
                         "(POST /api/campaign/{id}/pivot); /api/stream is passive only")
    argv = [sys.executable, "-m", "argus", "pivot", seed, "--json", *LEVELS[level]]

    def _int_flag(name: str, key: str, lo: int, hi: int):
        if key in opts and opts[key] not in (None, ""):
            try:
                v = int(opts[key])
            except (TypeError, ValueError):
                raise ValueError(f"{key} must be an integer")
            if not (lo <= v <= hi):
                raise ValueError(f"{key} out of range [{lo},{hi}]")
            argv.extend([name, str(v)])

    _int_flag("--depth", "depth", 1, 5)
    _int_flag("--max", "max", 1, 500)
    _int_flag("--deep", "deep", 0, 50)

    ports = opts.get("ports")
    if ports:
        # allow digits, commas, dashes only (e.g. "1-1024" or "22,80,443")
        if not all(c.isdigit() or c in ",-" for c in str(ports)):
            raise ValueError("ports spec invalid")
        argv.extend(["--ports", str(ports)])
    return argv


def _run_stream(seed: str, level: str, opts: dict):
    """Generator yielding (event_name, data_obj) tuples for an SSE stream."""
    try:
        argv = _build_argv(seed, level, opts)
    except ValueError as e:
        yield "error", {"message": str(e)}
        return

    yield "start", {
        "seed": seed,
        "level": level,
        "command": " ".join(shlex.quote(a) for a in argv[2:]),  # hide python path
        "ts": time.time(),
    }

    env = dict(os.environ)
    env.setdefault("PYTHONUNBUFFERED", "1")
    try:
        proc = subprocess.Popen(
            argv,
            cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            bufsize=1,
        )
    except OSError as e:
        yield "error", {"message": f"failed to launch engine: {e}"}
        return

    q: "queue.Queue[tuple[str, str]]" = queue.Queue()

    def _pump(stream, tag):
        for line in iter(stream.readline, ""):
            q.put((tag, line.rstrip("\n")))
        stream.close()
        q.put((tag, None))  # sentinel

    t_out = threading.Thread(target=_pump, args=(proc.stdout, "out"), daemon=True)
    t_err = threading.Thread(target=_pump, args=(proc.stderr, "err"), daemon=True)
    t_out.start()
    t_err.start()

    stdout_buf: list[str] = []
    done = 0
    while done < 2:
        tag, line = q.get()
        if line is None:
            done += 1
            continue
        if tag == "err":
            # engine prints `[argus] ...` status lines to stderr — stream them live
            if line.strip():
                yield "status", {"line": line}
        else:
            stdout_buf.append(line)

    proc.wait()
    raw = "\n".join(stdout_buf).strip()
    if proc.returncode != 0 and not raw:
        yield "error", {"message": f"engine exited with code {proc.returncode}"}
        return
    try:
        graph = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        yield "error", {"message": "could not parse engine JSON output", "raw": raw[:2000]}
        return
    yield "result", graph
    yield "done", {"returncode": proc.returncode, "ts": time.time()}


def _run_module_stream(name: str, target: str):
    """SSE generator for `argus run <module> <target> --json` (a findings array)."""
    if name not in ALLOWED_MODULES:
        yield "error", {"message": f"unknown or disallowed module: {name!r}"}
        return
    try:
        seed = _sanitize_seed(target)
    except ValueError as e:
        yield "error", {"message": str(e)}
        return
    argv = [sys.executable, "-m", "argus", "run", name, seed, "--json"]
    yield "start", {"module": name, "target": seed, "ts": time.time()}

    env = dict(os.environ)
    env.setdefault("PYTHONUNBUFFERED", "1")
    try:
        proc = subprocess.Popen(argv, cwd=str(REPO_ROOT), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, env=env, bufsize=1)
    except OSError as e:
        yield "error", {"message": f"failed to launch engine: {e}"}
        return

    q: "queue.Queue[tuple[str, str]]" = queue.Queue()

    def _pump(stream, tag):
        for line in iter(stream.readline, ""):
            q.put((tag, line.rstrip("\n")))
        stream.close()
        q.put((tag, None))

    threading.Thread(target=_pump, args=(proc.stdout, "out"), daemon=True).start()
    threading.Thread(target=_pump, args=(proc.stderr, "err"), daemon=True).start()

    stdout_buf: list[str] = []
    done = 0
    while done < 2:
        tag, line = q.get()
        if line is None:
            done += 1
            continue
        if tag == "err":
            if line.strip():
                yield "status", {"line": line}
        else:
            stdout_buf.append(line)

    proc.wait()
    raw = "\n".join(stdout_buf).strip()
    try:
        findings = json.loads(raw) if raw else []
    except json.JSONDecodeError:
        yield "error", {"message": "could not parse engine JSON output", "raw": raw[:2000]}
        return
    yield "result", {"findings": findings}
    yield "done", {"returncode": proc.returncode, "ts": time.time()}


# --- control-plane read layer --------------------------------------------
# The campaign/finding modules persist everything under $ARGUS_HOME as owner-only
# JSON; these helpers READ that durable state and shape it for the UI. They import
# the domain modules directly (no subprocess) because this path touches no target,
# runs no provider, and never calls can_test — it only reports what already happened.
# Anything that triggers active work still goes through the CLI/orchestrator gate.
def _domain():
    """Import the argus control-plane modules, ensuring the repo root is importable
    when this file is run directly as `python3 web/server.py` (cwd would be web/)."""
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    from argus import campaign as campaign_mod, finding as finding_mod
    return campaign_mod, finding_mod


def _campaigns_summary() -> list[dict]:
    campaign_mod, _ = _domain()
    out = []
    for cid in campaign_mod.listing():
        try:
            c = campaign_mod.load(cid)
        except (OSError, ValueError, KeyError):
            continue
        out.append({"id": c.id, "created_at": c.created_at, "progress": c.progress()})
    return out


def _campaign_detail(cid: str) -> dict | None:
    """Full read model for one campaign, or None if `cid` isn't a known campaign.
    cid is validated against the authoritative listing — it is NEVER interpolated
    into a path before that check, so a traversal id ('../x') cannot escape the
    campaigns root."""
    campaign_mod, finding_mod = _domain()
    if cid not in set(campaign_mod.listing()):
        return None
    c = campaign_mod.load(cid)
    identity_mod = _identity_mod()
    return {
        "id": c.id,
        "created_at": c.created_at,
        "program_text": c.program_text,
        "policy": c.policy.to_dict(),
        "progress": c.progress(),
        "experiments": c.experiments(),
        "observations": c.observations(),
        "findings": finding_mod.findings(c),
        "tasks": c.tasks(),                   # durable orchestrator task table (the UI queue)
        "approvals": c.approvals(),           # pending + resolved human decisions
        "identities": [{"name": i.name, "role": i.role,
                        "researcher_owned": i.researcher_owned, "tenant": i.tenant,
                        "has_credential": bool(i.credential_ref)}   # never echo the ref itself
                       for i in identity_mod.identities(c)],
        "audit": c.audit_trail()[-200:],      # tail; full trail is on disk
    }


def _identity_mod():
    _domain()                                 # ensures REPO_ROOT on sys.path
    from argus import identity as identity_mod
    return identity_mod


def _coordinator(c):
    """This campaign's single run coordinator (one per id, process-wide). All execution
    mutations route through it so the durable task table has exactly one writer."""
    _domain()                                 # ensures REPO_ROOT on sys.path
    from argus import run as run_mod
    return run_mod.coordinator_for(c)


# engagement level -> (probe, probe_paths, scan, cve) for the background pivot. Mirrors the
# LEVELS flag map so the UI, the terminal, and the background run stay in lockstep. The UI
# picks a level; it can never name a provider or technique directly.
_PIVOT_TIERS: dict[str, tuple[bool, bool, bool, bool]] = {
    "passive":     (False, False, False, False),
    "active":      (True,  False, False, True),
    "active-plus": (False, True,  False, True),
    "full":        (False, True,  True,  True),
}


def _pivot_budget(body: dict):
    """Build a bounded discovery Budget from operator-controlled integers, same ranges as
    the CLI's --depth/--max/--deep. Out-of-range or non-integer input is a 400, not a clamp."""
    from argus.pivot import Budget

    def val(key: str, lo: int, hi: int, default: int) -> int:
        v = body.get(key)
        if v in (None, ""):
            return default
        try:
            v = int(v)
        except (TypeError, ValueError):
            raise ValueError(f"{key} must be an integer")
        if not (lo <= v <= hi):
            raise ValueError(f"{key} out of range [{lo},{hi}]")
        return v

    return Budget(max_depth=val("depth", 1, 5, 2),
                  max_entities=val("max", 1, 500, 40),
                  expand_subdomains=val("deep", 0, 50, 0))


def _pivot_ports(body: dict) -> str | None:
    ports = body.get("ports")
    if not ports:
        return None
    s = str(ports)
    if not all(ch.isdigit() or ch in ",-" for ch in s):
        raise ValueError("ports spec invalid")
    return s


def _campaign_seed(c) -> str:
    """A concrete host to seed background discovery from, taken from the campaign's own
    scope — never an arbitrary target. A wildcard include (`*.acme.example`) seeds its apex
    for DISCOVERY only; active probes are still gated by can_test against the real scope."""
    for pat in c.policy.scope.include_patterns():
        h = pat.strip().lstrip("*").lstrip(".").rstrip(".").lower()
        if h and "/" not in h and " " not in h:
            return h
    return ""


# --- structured campaign events (Phase 3) ---------------------------------
# The event stream is built from the campaign's PERSISTED, append-only audit log
# (campaign/audit.jsonl) — NOT from forwarded stderr. Each audit record maps to one or
# more structured events in a stable vocabulary the UI consumes. The mapping is lossless:
# anything without a specific mapping is still emitted as `argus.<raw_event>`.
_EVENT_MAP = {
    "campaign_created": "campaign.created",
    "task_proposed": "task.proposed",
    "task_cancelled": "task.cancelled",
    "task_retry": "task.retry",
    "recovered_interrupted": "task.retry",
    "no_worker": "task.failed",
    "human_approved": "approval.approved",
    "human_denied": "approval.denied",
    "approval_overruled_by_policy": "policy.deny",
    "finding_promoted": "finding.promoted",
    "finding_transition": "finding.transition",
    "identity_registered": "identity.registered",
    "differential_recorded": "experiment.completed",
    "differential_blocked": "policy.deny",
    "run_recovered": "campaign.run.recovered",
    "reproducibility_check": "reproduction.checked",
}
_VERDICT_EVENT = {
    "ALLOW": "policy.allow", "ALLOW_WITH_LIMITS": "policy.limit",
    "DENY": "policy.deny", "HUMAN_APPROVAL": "policy.approval_required",
}


def _structured_events(rec: dict, seq: int):
    """Yield (event_name, data) for one audit record. `seq` is the record's line index,
    echoed back so a client can resume with ?since=<seq+1>. A policy_decision fans out
    into its verdict event plus the lifecycle event that verdict implies (queued /
    approval requested), so the UI's queue + approval panels update from one record."""
    data = dict(rec, seq=seq)
    ev = rec.get("event", "")
    if ev == "run_transition":
        # the coordinator is the authority for run activity: one event per state, so the
        # UI drives its execution rail from run state, NOT from "are there queued tasks".
        yield f"campaign.run.{str(rec.get('state', '')).lower()}", data
        return
    if ev == "policy_decision":
        verdict = rec.get("verdict", "")
        yield _VERDICT_EVENT.get(verdict, "policy.decision"), data
        if verdict in ("ALLOW", "ALLOW_WITH_LIMITS"):
            yield "task.queued", data
        elif verdict == "HUMAN_APPROVAL":
            yield "approval.requested", data
        return
    if ev == "experiment_recorded":
        yield "task.completed", data
        yield "experiment.created", data
        return
    yield _EVENT_MAP.get(ev, f"argus.{ev}"), data


class Handler(BaseHTTPRequestHandler):
    server_version = "ArgusWeb/0.1"

    # quieter logs
    def log_message(self, fmt, *args):
        sys.stderr.write("[web] %s - %s\n" % (self.address_string(), fmt % args))

    def _send_json(self, obj, code=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _sse_event(self, event: str, data: dict):
        payload = f"event: {event}\ndata: {json.dumps(data)}\n\n"
        self.wfile.write(payload.encode("utf-8"))
        self.wfile.flush()

    # --- request-body helpers (trust boundary — every read is bounded + guarded) ---
    def _raw_body(self, cap: int = 1_000_000) -> bytes | None:
        """Read the request body, bounded. None (and a 400 already sent) if missing or
        over `cap` — a client must never make the server allocate unboundedly."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > cap:
            self._send_json({"error": f"request body must be 1 byte - {cap} bytes"}, code=400)
            return None
        return self.rfile.read(length)

    def _json_body(self, cap: int = 1_000_000) -> dict | None:
        """Parse a bounded JSON object body, or send a 400 and return None."""
        raw = self._raw_body(cap)
        if raw is None:
            return None
        try:
            obj = json.loads(raw.decode("utf-8", "replace"))
        except json.JSONDecodeError:
            self._send_json({"error": "body is not valid JSON"}, code=400)
            return None
        if not isinstance(obj, dict):
            self._send_json({"error": "body must be a JSON object"}, code=400)
            return None
        return obj

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/api/policy":
            return self._post_policy()
        if path == "/api/campaigns":
            return self._post_create_campaign()
        # /api/campaign/{id}/... remote-control endpoints. Execution mutations (pivot,
        # pause/resume/stop, task decisions) route through the per-campaign coordinator,
        # which owns mutation ordering on its single thread — NO global lock around those,
        # so one campaign's long run never blocks another campaign's HTTP writes. Identity
        # registration touches campaign files outside the task table, so it keeps the lock.
        parts = path.strip("/").split("/")       # ['api','campaign','{id}', ...]
        if len(parts) >= 4 and parts[0] == "api" and parts[1] == "campaign":
            return self._post_campaign(parts[2], parts[3:])
        self._send_json({"error": "not found"}, code=404)

    def _post_policy(self):
        # Compile a pasted program page into the engagement contract. Pure parse —
        # deterministic, no network, touches no target — so it is safe to accept a body.
        raw = self._raw_body()
        if raw is None:
            return
        text = raw.decode("utf-8", "replace")
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "argus", "policy", "inspect", "-", "--json"],
                cwd=str(REPO_ROOT), input=text, capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired) as e:
            self._send_json({"error": f"compile failed: {e}"}, code=500)
            return
        if proc.returncode != 0:
            self._send_json({"error": proc.stderr.strip() or "compile failed"}, code=500)
            return
        try:
            self._send_json(json.loads(proc.stdout))
        except json.JSONDecodeError:
            self._send_json({"error": "could not parse compiler output"}, code=500)

    def _post_create_campaign(self):
        """POST /api/campaigns — open a campaign from a pasted program page. Frozen
        policy is compiled in-process; no target is touched by creating one."""
        body = self._json_body()
        if body is None:
            return
        text = (body.get("program_text") or "").strip()
        if not text:
            self._send_json({"error": "program_text is required"}, code=400)
            return
        campaign_mod, _ = _domain()
        try:
            with _WRITE_LOCK:
                c = campaign_mod.create(text, name=str(body.get("name") or ""))
        except Exception as e:                      # noqa: BLE001 — report, don't crash the server
            self._send_json({"error": f"could not create campaign: {e}"}, code=500)
            return
        self._send_json({"id": c.id, "created_at": c.created_at,
                         "policy": c.policy.to_dict(), "progress": c.progress()}, code=201)

    def _post_campaign(self, cid: str, rest: list[str]):
        """Dispatch /api/campaign/{id}/... POSTs. Every branch ends at a domain /
        coordinator method — never at a provider. cid is validated against the
        authoritative listing BEFORE any path is built from it (no traversal)."""
        campaign_mod, _ = _domain()
        if cid not in set(campaign_mod.listing()):
            self._send_json({"error": f"no campaign {cid!r}"}, code=404)
            return
        c = campaign_mod.load(cid)

        if rest == ["identities"]:
            with _WRITE_LOCK:                     # not task-table work — keep the simple lock
                return self._register_identity(c)
        if rest == ["sessions"]:
            with _WRITE_LOCK:
                return self._register_session(c)
        if rest == ["traffic"]:
            with _WRITE_LOCK:                     # capture upserts endpoint files — serialize
                return self._ingest_traffic(c)
        if rest == ["resources", "ownership"]:
            with _WRITE_LOCK:                     # rewrites ownership.json — serialize
                return self._assert_ownership(c)
        if rest == ["pivot"]:
            return self._start_pivot(c)
        if rest and rest[0] in ("pause", "resume", "stop") and len(rest) == 1:
            return self._run_control(c, rest[0])
        # /findings/{finding}/reproduce
        if len(rest) == 3 and rest[0] == "findings" and rest[2] == "reproduce":
            return self._reproduce_finding(c, rest[1])
        # /tasks/{task}/{action}
        if len(rest) == 3 and rest[0] == "tasks" and rest[2] in ("approve", "deny", "cancel"):
            return self._task_decision(c, rest[1], rest[2])
        # /gaps/{gap}/queue — run a research gap's proposal through the coordinator
        if len(rest) == 3 and rest[0] == "gaps" and rest[2] == "queue":
            return self._queue_gap(c, rest[1])
        self._send_json({"error": "not found"}, code=404)

    def _register_identity(self, c):
        """POST /api/campaign/{id}/identities — declare an authorized test identity.
        Identity.__post_init__ rejects a pasted secret as credential_ref at the boundary."""
        body = self._json_body()
        if body is None:
            return
        name = (body.get("name") or "").strip()
        if not name:
            self._send_json({"error": "identity name is required"}, code=400)
            return
        identity_mod = _identity_mod()
        try:
            ident = identity_mod.register(c, identity_mod.Identity(
                name=name, role=str(body.get("role") or ""),
                researcher_owned=bool(body.get("researcher_owned", False)),
                credential_ref=str(body.get("credential_ref") or ""),
                tenant=str(body.get("tenant") or "")))
        except ValueError as e:                     # bad credential_ref / auth_template
            self._send_json({"error": str(e)}, code=400)
            return
        self._send_json({"name": ident.name, "role": ident.role,
                         "researcher_owned": ident.researcher_owned,
                         "has_credential": bool(ident.credential_ref)}, code=201)

    def _register_session(self, c):
        """POST /api/campaign/{id}/sessions — declare a researcher-controlled authenticated
        context. Session.__post_init__ rejects a pasted secret as credential_ref (it must be
        an env-var NAME), and a bad status/source, at the boundary."""
        body = self._json_body()
        if body is None:
            return
        from argus import session as session_mod
        try:
            s = session_mod.register(c, session_mod.Session(
                identity=str(body.get("identity") or ""),
                base_origin=str(body.get("base_origin") or ""),
                auth_mechanism=str(body.get("auth_mechanism") or ""),
                credential_ref=str(body.get("credential_ref") or ""),
                source=str(body.get("source") or "manual")))
        except ValueError as e:
            self._send_json({"error": str(e)}, code=400)
            return
        # never echo the credential_ref value back; just confirm the reference exists
        self._send_json({"id": s.id, "identity": s.identity, "base_origin": s.base_origin,
                         "auth_mechanism": s.auth_mechanism,
                         "has_credential": bool(s.credential_ref), "source": s.source}, code=201)

    def _ingest_traffic(self, c):
        """POST /api/campaign/{id}/traffic — ingest researcher-captured traffic. Body is
        either {"har": {...}} (a browser export) or {"request": {method,url,headers,body,
        response}} (a single pasted/structured request), plus optional identity/session_id.
        Secrets are redacted in the domain layer BEFORE anything is persisted. Returns the
        endpoints touched so the UI can refresh its surface."""
        body = self._json_body(cap=8_000_000)     # a HAR can be large; still bounded
        if body is None:
            return
        from argus import session as session_mod, traffic
        identity = str(body.get("identity") or "")
        session_id = str(body.get("session_id") or "")
        if session_id and session_mod.get(c, session_id) is None:
            self._send_json({"error": f"unknown session {session_id!r}"}, code=400)
            return
        try:
            if isinstance(body.get("har"), dict):
                eps = traffic.import_har(c, body["har"], identity=identity,
                                         session_id=session_id, source="har")
                touched = len(eps)
            elif isinstance(body.get("request"), dict):
                req = body["request"]
                url = str(req.get("url") or "")
                if not url:
                    self._send_json({"error": "request.url is required"}, code=400)
                    return
                traffic.capture(
                    c, method=str(req.get("method") or "GET"), url=url,
                    headers=dict(req.get("headers") or {}), body=str(req.get("body") or ""),
                    identity=identity, session_id=session_id,
                    response=dict(req.get("response") or {}), source=str(req.get("source") or "paste"))
                touched = 1
            else:
                self._send_json({"error": "body must carry 'har' or 'request'"}, code=400)
                return
        except (ValueError, TypeError) as e:
            self._send_json({"error": f"could not ingest traffic: {e}"}, code=400)
            return
        self._send_json({"ingested": touched, "endpoints": traffic.endpoints(c)}, code=201)

    def _assert_ownership(self, c):
        """POST /api/campaign/{id}/resources/ownership — declare an EXPLICIT ownership
        assertion. Ownership.__post_init__ enforces the invariant at the boundary: an
        INFERRED assertion can never be researcher-controlled, and a bad status/confidence/
        empty value is a 400. researcher_controlled is trusted metadata, never inferred."""
        body = self._json_body()
        if body is None:
            return
        from argus import resource
        try:
            own = resource.assert_ownership(c, resource.Ownership(
                resource_type=str(body.get("resource_type") or "").strip(),
                resource_value=str(body.get("resource_value") or ""),
                owner_identity=str(body.get("owner_identity") or ""),
                tenant=str(body.get("tenant") or ""),
                researcher_controlled=bool(body.get("researcher_controlled", False)),
                ownership_status=str(body.get("ownership_status") or "CONFIRMED"),
                confidence=float(body.get("confidence", 1.0)),
                source=str(body.get("source") or "operator"),
                note=str(body.get("note") or "")))
        except (ValueError, TypeError) as e:
            self._send_json({"error": str(e)}, code=400)
            return
        self._send_json({"id": own.id, "resource_type": own.resource_type,
                         "resource_value": own.resource_value,
                         "researcher_controlled": own.researcher_controlled,
                         "ownership_status": own.ownership_status}, code=201)

    def _task_decision(self, c, task_id: str, action: str):
        """POST /api/campaign/{id}/tasks/{task}/{approve|deny|cancel} — human action on a
        parked task, routed through the campaign's coordinator so it is serialized with any
        live run (never a second Orchestrator racing the task table). approve() RE-RUNS
        can_test, so an API approval can never walk a scope/forbidden DENY back to the
        queue — the coordinator does not weaken that invariant."""
        co = _coordinator(c)
        if task_id not in co.orch.tasks:
            self._send_json({"error": f"no task {task_id!r} in campaign"}, code=404)
            return
        body = self._json_body() or {}
        by = str(body.get("by") or "web-operator").strip() or "web-operator"
        note = str(body.get("note") or "")
        fn = {"approve": co.approve, "deny": co.deny, "cancel": co.cancel}[action]
        try:
            t = fn(task_id, by, note)                 # applied on the coordinator's single thread
        except ValueError as e:                       # wrong state, or policy re-check denied
            self._send_json({"error": str(e)}, code=409)
            return
        self._send_json({"task": t.to_record(), "run": co.snapshot()})

    def _start_pivot(self, c):
        """POST /api/campaign/{id}/pivot — start a REAL background research run bound to
        this campaign. The body carries only bounded, operator-controlled configuration
        (engagement level + budgets + ports); it can NEVER name a provider or function.
        UI intent is translated into the known research planner. Returns immediately with
        the run snapshot — SSE (/events) carries discovery, tasks, and progress."""
        body = self._json_body() or {}
        level = str(body.get("level") or "passive")
        if level not in _PIVOT_TIERS:
            self._send_json({"error": f"unknown engagement level: {level!r}"}, code=400)
            return
        try:
            budget = _pivot_budget(body)
            ports = _pivot_ports(body)
        except ValueError as e:
            self._send_json({"error": str(e)}, code=400)
            return
        # the seed is the campaign's own scope, not an arbitrary target: derive it from the
        # program so a background pivot cannot be aimed outside the engagement.
        seed = _campaign_seed(c)
        if not seed:
            self._send_json({"error": "campaign has no concrete in-scope seed to pivot from"},
                            code=409)
            return
        from argus import research
        probe, probe_paths, scan, cve = _PIVOT_TIERS[level]
        tiers = research.tiers_for(probe, probe_paths, scan)
        planner, on_complete = research.background_pivot(
            seed, budget=budget, tiers=tiers, ports=ports, cve=cve)
        co = _coordinator(c)
        snap = co.start(planner=planner, on_complete=on_complete)
        self._send_json({"run": snap, "seed": seed, "level": level}, code=202)

    def _reproduce_finding(self, c, finding_id: str):
        """POST /api/campaign/{id}/findings/{fid}/reproduce — re-run a finding's controlled
        differential through the SAME coordinator (not a separate engine). Returns 202 with
        the run snapshot; the reproducibility verdict + finding advance arrive via SSE.
        409 if a run is already active (one execution owner per campaign) or the finding has
        no re-runnable differential."""
        body = self._json_body() or {}
        try:
            trials = int(body.get("trials") or 2)
        except (TypeError, ValueError):
            self._send_json({"error": "trials must be an integer"}, code=400)
            return
        if not (1 <= trials <= 10):
            self._send_json({"error": "trials out of range [1,10]"}, code=400)
            return
        co = _coordinator(c)
        if co.is_active():
            self._send_json({"error": "a run is already active; stop it before reproducing"},
                            code=409)
            return
        from argus import reproduce
        try:
            planner, on_complete = reproduce.background_verify(c, finding_id, trials=trials)
        except ValueError as e:
            self._send_json({"error": str(e)}, code=409)
            return
        snap = co.start(planner=planner, on_complete=on_complete)
        self._send_json({"run": snap, "finding": finding_id, "trials": trials}, code=202)

    def _queue_gap(self, c, gap_id: str):
        """POST /api/campaign/{id}/gaps/{gap}/queue — run a ResearchGap's experiment proposal
        through the SAME coordinator as a pivot (one execution owner). The proposal is a plan;
        this hands its differential Task to the coordinator, which re-gates it via can_test and
        drives the EXISTING differential runner. 202 with the run snapshot + the proposal; the
        knowledge update (gap RESOLVED/TESTED + any FindingCandidate) arrives via SSE/reconcile.
        409 if a run is already active (one owner) or the gap is not a derivable OPEN gap."""
        co = _coordinator(c)
        if co.is_active():
            self._send_json({"error": "a run is already active; stop it before queueing a gap"},
                            code=409)
            return
        from argus import proposal
        try:
            planner, on_complete, prop = proposal.background_queue(c, gap_id)
        except ValueError as e:
            self._send_json({"error": str(e)}, code=409)
            return
        snap = co.start(planner=planner, on_complete=on_complete)
        self._send_json({"run": snap, "gap_id": gap_id, "proposal": prop}, code=202)

    def _run_control(self, c, action: str):
        """POST /api/campaign/{id}/{pause|resume|stop} — thin controller over the
        coordinator. Returns the run snapshot; the operation itself is applied on the
        coordinator's single thread, so it never races a live run."""
        co = _coordinator(c)
        snap = {"pause": co.pause, "resume": co.resume, "stop": co.stop}[action]()
        self._send_json({"run": snap})

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/health":
            self._send_json({"ok": True, "levels": list(LEVELS),
                             "modules": sorted(SECRET_MODULES),
                             "utility_modules": sorted(UTILITY_MODULES),
                             "github_token": bool(os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"))})
            return

        if path == "/api/stream":
            qs = parse_qs(parsed.query)
            try:
                seed = _sanitize_seed(qs.get("seed", [""])[0])
            except ValueError as e:
                self._send_json({"error": str(e)}, code=400)
                return
            level = qs.get("level", ["passive"])[0]
            # passive discovery only — active engagement is a coordinator-owned campaign.
            # Reject before the SSE headers so the client gets a clean 400, not a stream.
            if level != "passive":
                self._send_json({"error": "active engagement must run as a campaign "
                                 "(POST /api/campaign/{id}/pivot); /api/stream is passive only"},
                                code=400)
                return
            opts = {
                "depth": qs.get("depth", [None])[0],
                "max": qs.get("max", [None])[0],
                "deep": qs.get("deep", [None])[0],
                "ports": qs.get("ports", [None])[0],
            }
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            try:
                for event, data in _run_stream(seed, level, opts):
                    self._sse_event(event, data)
            except (BrokenPipeError, ConnectionResetError):
                pass  # client navigated away
            return

        if path == "/api/module":
            qs = parse_qs(parsed.query)
            name = qs.get("name", [""])[0]
            target = qs.get("target", [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            try:
                for event, data in _run_module_stream(name, target):
                    self._sse_event(event, data)
            except (BrokenPipeError, ConnectionResetError):
                pass
            return

        if path == "/api/campaigns":
            try:
                self._send_json({"campaigns": _campaigns_summary()})
            except Exception as e:                      # noqa: BLE001 — read path, report not crash
                self._send_json({"error": f"could not list campaigns: {e}"}, code=500)
            return

        if path == "/api/campaign":
            cid = parse_qs(parsed.query).get("id", [""])[0]
            if not cid:
                self._send_json({"error": "missing campaign id"}, code=400)
                return
            try:
                detail = _campaign_detail(cid)
            except Exception as e:                      # noqa: BLE001
                self._send_json({"error": f"could not load campaign: {e}"}, code=500)
                return
            if detail is None:
                self._send_json({"error": f"no campaign {cid!r}"}, code=404)
                return
            self._send_json(detail)
            return

        # structured campaign event stream (Phase 3): /api/campaign/{id}/events
        parts = path.strip("/").split("/")
        if len(parts) == 4 and parts[:2] == ["api", "campaign"] and parts[3] == "events":
            return self._campaign_events(parts[2], parse_qs(parsed.query))

        # durable graph projection: /api/campaign/{id}/surface — the engine's
        # {graph, investigation} shape, so the UI's normalize() renders a live campaign
        # exactly as it renders a CLI pivot. Reads the durable projection, never a run's
        # in-memory graph; a disconnect or restart cannot lose it.
        if len(parts) == 4 and parts[:2] == ["api", "campaign"] and parts[3] == "surface":
            return self._campaign_surface(parts[2])

        # observed application surface: /api/campaign/{id}/endpoints — the durable endpoint
        # catalog + sessions. ?ep={id} returns one endpoint with its evidence (captures).
        if len(parts) == 4 and parts[:2] == ["api", "campaign"] and parts[3] == "endpoints":
            return self._campaign_endpoints(parts[2], parse_qs(parsed.query))

        # identity x endpoint research matrix: /api/campaign/{id}/matrix — a deterministic
        # read model over the campaign's captured traffic. Observed vs unobserved coverage,
        # NEVER a security verdict; the UI renders truth from this, not from raw captures.
        if len(parts) == 4 and parts[:2] == ["api", "campaign"] and parts[3] == "matrix":
            return self._campaign_matrix(parts[2])

        # resource / object knowledge: /api/campaign/{id}/resources — candidates mined from
        # captured traffic, overlaid with explicit ownership assertions. Unknown owner is a
        # normal state; researcher_controlled is only ever set by an explicit assertion.
        if len(parts) == 4 and parts[:2] == ["api", "campaign"] and parts[3] == "resources":
            return self._campaign_resources(parts[2])

        # ownership-aware authorization coverage: /api/campaign/{id}/coverage — structured
        # ResearchGaps (missing evidence, never findings) + a deterministic summary.
        if len(parts) == 4 and parts[:2] == ["api", "campaign"] and parts[3] == "coverage":
            return self._campaign_coverage(parts[2])

        # research-priority engine: /api/campaign/{id}/priority (ranked gaps) and
        # /api/campaign/{id}/intel (Command Center research intelligence). Both DERIVED
        # research state — never execution progress, never a security score.
        if len(parts) == 4 and parts[:2] == ["api", "campaign"] and parts[3] in ("priority", "intel"):
            return self._campaign_priority(parts[2], parts[3])

        # experiment proposals: /api/campaign/{id}/proposals — a PLAN per ranked gap. A plan
        # never executes; POST /gaps/{gap}/queue runs it through the coordinator.
        if len(parts) == 4 and parts[:2] == ["api", "campaign"] and parts[3] == "proposals":
            return self._campaign_proposals(parts[2])

        # otherwise: static frontend
        self._serve_static(path)

    def _campaign_surface(self, cid: str):
        """GET /api/campaign/{id}/surface — the durable graph projection. cid is validated
        against the authoritative listing before any path is built from it (no traversal)."""
        campaign_mod, _ = _domain()
        if cid not in set(campaign_mod.listing()):
            self._send_json({"error": f"no campaign {cid!r}"}, code=404)
            return
        try:
            self._send_json(campaign_mod.load(cid).surface())
        except Exception as e:                      # noqa: BLE001 — read path, report not crash
            self._send_json({"error": f"could not load surface: {e}"}, code=500)

    def _campaign_endpoints(self, cid: str, qs: dict):
        """GET /api/campaign/{id}/endpoints — the observed endpoint catalog + sessions.
        ?ep={id} returns one endpoint and its captures (the inspector). cid validated
        against the listing before any path is built (no traversal)."""
        campaign_mod, _ = _domain()
        if cid not in set(campaign_mod.listing()):
            self._send_json({"error": f"no campaign {cid!r}"}, code=404)
            return
        from argus import session as session_mod, traffic
        c = campaign_mod.load(cid)
        ep_id = (qs.get("ep", [""])[0] or "").strip()
        try:
            if ep_id:
                ep = traffic.endpoint(c, ep_id)
                if ep is None:
                    self._send_json({"error": f"no endpoint {ep_id!r}"}, code=404)
                    return
                self._send_json({"endpoint": ep, "captures": traffic.captures_for(c, ep_id)})
                return
            sessions = [{"id": s.id, "identity": s.identity, "base_origin": s.base_origin,
                         "auth_mechanism": s.auth_mechanism, "status": s.status,
                         "source": s.source, "last_seen": s.last_seen,
                         "has_credential": bool(s.credential_ref)}   # never the ref value
                        for s in session_mod.sessions(c)]
            self._send_json({"endpoints": traffic.endpoints(c), "sessions": sessions})
        except Exception as e:                      # noqa: BLE001 — read path, report not crash
            self._send_json({"error": f"could not load endpoints: {e}"}, code=500)

    def _campaign_matrix(self, cid: str):
        """GET /api/campaign/{id}/matrix — the identity x endpoint research matrix, derived
        from captured traffic. cid validated against the listing before any path is built
        (no traversal). Read-only: building the matrix touches no target and stores nothing."""
        campaign_mod, _ = _domain()
        if cid not in set(campaign_mod.listing()):
            self._send_json({"error": f"no campaign {cid!r}"}, code=404)
            return
        from argus import matrix
        try:
            self._send_json(matrix.build(campaign_mod.load(cid)))
        except Exception as e:                      # noqa: BLE001 — read path, report not crash
            self._send_json({"error": f"could not build matrix: {e}"}, code=500)

    def _campaign_resources(self, cid: str):
        """GET /api/campaign/{id}/resources — observed resource candidates overlaid with
        ownership assertions. cid validated against the listing (no traversal). Read-only."""
        campaign_mod, _ = _domain()
        if cid not in set(campaign_mod.listing()):
            self._send_json({"error": f"no campaign {cid!r}"}, code=404)
            return
        from argus import resource
        try:
            c = campaign_mod.load(cid)
            self._send_json({"campaign_id": cid, "resources": resource.resources(c)})
        except Exception as e:                      # noqa: BLE001 — read path, report not crash
            self._send_json({"error": f"could not load resources: {e}"}, code=500)

    def _campaign_coverage(self, cid: str):
        """GET /api/campaign/{id}/coverage — ownership-aware ResearchGaps + summary. cid
        validated against the listing (no traversal). Read-only: deriving gaps touches no
        target and stores nothing."""
        campaign_mod, _ = _domain()
        if cid not in set(campaign_mod.listing()):
            self._send_json({"error": f"no campaign {cid!r}"}, code=404)
            return
        from argus import coverage
        try:
            self._send_json(coverage.build(campaign_mod.load(cid)))
        except Exception as e:                      # noqa: BLE001 — read path, report not crash
            self._send_json({"error": f"could not build coverage: {e}"}, code=500)

    def _campaign_priority(self, cid: str, kind: str):
        """GET /api/campaign/{id}/priority — ranked OPEN gaps; /intel — Command Center
        research intelligence (coverage counts + the highest-value unexplored boundary).
        Both read-only, both DERIVED research state kept separate from execution progress."""
        campaign_mod, _ = _domain()
        if cid not in set(campaign_mod.listing()):
            self._send_json({"error": f"no campaign {cid!r}"}, code=404)
            return
        from argus import priority
        try:
            c = campaign_mod.load(cid)
            if kind == "intel":
                self._send_json(priority.intel(c))
            else:
                self._send_json({"campaign_id": cid, "ranked": priority.rank(c)})
        except Exception as e:                      # noqa: BLE001 — read path, report not crash
            self._send_json({"error": f"could not build {kind}: {e}"}, code=500)

    def _campaign_proposals(self, cid: str):
        """GET /api/campaign/{id}/proposals — an ExperimentProposal per ranked OPEN gap. A
        proposal is a PLAN: building it sends no request. cid validated against the listing."""
        campaign_mod, _ = _domain()
        if cid not in set(campaign_mod.listing()):
            self._send_json({"error": f"no campaign {cid!r}"}, code=404)
            return
        from argus import proposal
        try:
            self._send_json({"campaign_id": cid, "proposals": proposal.proposals(campaign_mod.load(cid))})
        except Exception as e:                      # noqa: BLE001 — read path, report not crash
            self._send_json({"error": f"could not build proposals: {e}"}, code=500)

    def _campaign_events(self, cid: str, qs: dict):
        """SSE stream of one campaign's structured events, replayed from its durable audit
        log then tailed live. `?since=N` resumes after record N; `?once=1` replays current
        events + a progress snapshot and closes (no tail) — deterministic for clients that
        only want the backlog. The audit log is the source of truth, so a reconnect with
        ?since= never loses or double-counts an event."""
        campaign_mod, _ = _domain()
        if cid not in set(campaign_mod.listing()):
            self._send_json({"error": f"no campaign {cid!r}"}, code=404)
            return
        c = campaign_mod.load(cid)
        try:
            since = max(0, int((qs.get("since", ["0"])[0]) or 0))
        except ValueError:
            since = 0
        once = (qs.get("once", ["0"])[0]) in ("1", "true", "yes")

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        # a one-shot replay must CLOSE so the client sees EOF (SSE carries no
        # Content-Length); a live tail stays open.
        self.send_header("Connection", "close" if once else "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        if once:
            self.close_connection = True

        def emit_new(n_seen: int) -> int:
            trail = c.audit_trail()
            for seq in range(n_seen, len(trail)):
                for event, data in _structured_events(trail[seq], seq):
                    self._sse_event(event, data)
            return len(trail)

        try:
            seen = emit_new(since)
            self._sse_event("campaign.progress", c.progress())
            if once:
                return
            # live tail: emit new audit records as they land, with a periodic progress
            # refresh + heartbeat so proxies and the client keep the connection open.
            idle = 0
            while True:
                time.sleep(0.5)
                before = seen
                seen = emit_new(seen)
                idle = 0 if seen != before else idle + 1
                if idle % 4 == 0:                      # every ~2s of quiet
                    self._sse_event("campaign.progress", c.progress())
                    self.wfile.write(b": heartbeat\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass  # client navigated away

    def _serve_static(self, path: str):
        if not FRONTEND_DIST.is_dir():
            self._send_json(
                {"error": "frontend not built",
                 "hint": "cd web/frontend && npm install && npm run build"},
                code=404)
            return
        rel = path.lstrip("/") or "index.html"
        target = (FRONTEND_DIST / rel).resolve()
        # prevent path traversal outside dist
        if not str(target).startswith(str(FRONTEND_DIST.resolve())):
            self._send_json({"error": "forbidden"}, code=403)
            return
        if not target.is_file():
            target = FRONTEND_DIST / "index.html"  # SPA fallback
        if not target.is_file():
            self._send_json({"error": "not found"}, code=404)
            return
        ctype = _CONTENT_TYPES.get(target.suffix, "application/octet-stream")
        data = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main():
    ap = argparse.ArgumentParser(description="Argus web API (stdlib SSE over the argus engine)")
    ap.add_argument("--host", default="127.0.0.1", help="bind host (default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=8787, help="bind port (default 8787)")
    args = ap.parse_args()

    if args.host not in ("127.0.0.1", "localhost"):
        sys.stderr.write(
            "[web] WARNING: binding to %s exposes Argus beyond localhost. "
            "Only do this on a network you control and against authorized targets.\n"
            % args.host)

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    sys.stderr.write(f"[web] Argus API on http://{args.host}:{args.port}  (engine: {REPO_ROOT})\n")
    if not FRONTEND_DIST.is_dir():
        sys.stderr.write("[web] frontend/dist not found — run `cd web/frontend && npm install && npm run build` "
                         "to serve the UI from here, or use `npm run dev` for hot reload.\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\n[web] shutting down\n")
        httpd.shutdown()


if __name__ == "__main__":
    main()
