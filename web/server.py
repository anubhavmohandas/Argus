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

        # otherwise: static frontend
        self._serve_static(path)

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
