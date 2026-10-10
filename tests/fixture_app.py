"""A deliberately small, test-OWNED local application — ARGUS's integration proving ground.

The golden E2E tests drive the whole research loop against this, never an internet target.
It binds to 127.0.0.1 on an ephemeral port and serves two routes that differ ONLY in their
authorization, so the SAME controlled cross-account differential classifies one as suspicious
and the other as secure:

    GET /api/orders/{id}         VULNERABLE — any authenticated user reads any order (no
                                 owner check). user_b reaching user_a's order => suspicious.
    GET /api/secure-orders/{id}  SECURE — only the owner reads the order; a non-owner gets
                                 403. user_b denied => the correct secure outcome.

Both require authentication (anonymous => 401), so they also model the anonymous boundary.
Tokens map to users; order "1" is owned by user_a. No secrets, no state mutation, no network
egress — it is a fixture, deliberately not a framework.
"""
from __future__ import annotations

import contextlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Bearer token -> the user it authenticates as. The E2E sets the matching identity
# credential_refs to these same values via env vars.
_TOKENS = {"tok-a": "user_a", "tok-b": "user_b"}
# order id -> record (owner + a little data to return)
_ORDERS = {"1": {"order_id": "1", "owner": "user_a", "total": 42, "item": "widget"}}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *_a):          # keep the test output quiet
        pass

    def _user(self) -> str | None:
        auth = self.headers.get("Authorization", "")
        tok = auth[7:] if auth.startswith("Bearer ") else ""
        return _TOKENS.get(tok)

    def do_GET(self):                    # noqa: N802 (http.server contract)
        path = self.path.split("?", 1)[0]
        user = self._user()
        for prefix, owner_checked in (("/api/orders/", False), ("/api/secure-orders/", True)):
            if path.startswith(prefix):
                oid = path[len(prefix):]
                if user is None:
                    return self._send(401, {"error": "authentication required"})
                order = _ORDERS.get(oid)
                if order is None:
                    return self._send(404, {"error": "not found"})
                if owner_checked and order["owner"] != user:
                    return self._send(403, {"error": "forbidden"})
                return self._send(200, order)       # VULN route: returns regardless of owner
        return self._send(404, {"error": "no such route"})

    def _send(self, status: int, obj: dict) -> None:
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextlib.contextmanager
def running_app():
    """Run the fixture on 127.0.0.1:<ephemeral> for the duration of the `with` block;
    yields the port. Threaded + daemon so it never outlives the test."""
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()
        t.join(timeout=2)


if __name__ == "__main__":              # tiny manual check: the two routes behave as designed
    import urllib.request

    def _get(port, path, tok):
        req = urllib.request.Request(f"http://127.0.0.1:{port}{path}",
                                     headers={"Authorization": f"Bearer {tok}"} if tok else {})
        try:
            with urllib.request.urlopen(req, timeout=3) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code

    with running_app() as port:
        assert _get(port, "/api/orders/1", "tok-a") == 200          # owner
        assert _get(port, "/api/orders/1", "tok-b") == 200          # VULN: non-owner allowed
        assert _get(port, "/api/orders/1", None) == 401             # anonymous denied
        assert _get(port, "/api/secure-orders/1", "tok-a") == 200   # owner
        assert _get(port, "/api/secure-orders/1", "tok-b") == 403   # SECURE: non-owner denied
    print("fixture app self-check passed")
