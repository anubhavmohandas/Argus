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
        # /api/campaign/{id}/... remote-control endpoints — all IN-PROCESS domain calls,
        # serialized so two writers never corrupt one campaign's durable task table.
        parts = path.strip("/").split("/")       # ['api','campaign','{id}', ...]
        if len(parts) >= 4 and parts[0] == "api" and parts[1] == "campaign":
            cid, rest = parts[2], parts[3:]
            with _WRITE_LOCK:
                return self._post_campaign(cid, rest)
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
        orchestrator method — never at a provider. cid is validated against the
        authoritative listing BEFORE any path is built from it (no traversal)."""
        campaign_mod, _ = _domain()
        if cid not in set(campaign_mod.listing()):
            self._send_json({"error": f"no campaign {cid!r}"}, code=404)
            return
        c = campaign_mod.load(cid)

        if rest == ["identities"]:
            return self._register_identity(c)
        # /tasks/{task}/{action}
        if len(rest) == 3 and rest[0] == "tasks" and rest[2] in ("approve", "deny", "cancel"):
            return self._task_decision(c, rest[1], rest[2])
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

    def _task_decision(self, c, task_id: str, action: str):
        """POST /api/campaign/{id}/tasks/{task}/{approve|deny|cancel} — human action on a
        parked task, straight through the Orchestrator. approve() RE-RUNS can_test, so an
        API approval can never walk a scope/forbidden DENY back to the queue."""
        from argus.orchestrator import Orchestrator
        orch = Orchestrator(c)                       # adopts this campaign's durable task table
        if task_id not in orch.tasks:
            self._send_json({"error": f"no task {task_id!r} in campaign"}, code=404)
            return
        body = self._json_body() or {}
        by = str(body.get("by") or "web-operator").strip() or "web-operator"
        note = str(body.get("note") or "")
        fn = {"approve": orch.approve, "deny": orch.deny, "cancel": orch.cancel}[action]
        try:
            t = fn(task_id, by, note)
        except ValueError as e:                      # wrong state, or policy re-check denied
            self._send_json({"error": str(e)}, code=409)
            return
        self._send_json({"task": t.to_record()})

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

        # otherwise: static frontend
        self._serve_static(path)

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
