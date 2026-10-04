#!/bin/bash
# Argus (Linux) — pulls latest code, launches the web API, opens the UI.
# Run from a terminal, or mark executable and double-click (most file managers
# will offer "Run"). Close the terminal / Ctrl-C to stop Argus.
cd "$(dirname "$0")" || exit 1

URL="http://127.0.0.1:8787"

# 1. Fetch the latest code (fast-forward only — never clobbers local work).
if [ -d .git ]; then
  echo "Updating to latest code…"
  git pull --ff-only || echo "git pull skipped — running current code."
fi

# 2. Stop any server already holding the port, so we run the code we just pulled.
pids=$(lsof -ti tcp:8787 2>/dev/null)
[ -n "$pids" ] && { echo "Restarting server…"; kill $pids 2>/dev/null; sleep 1; }

[ -f .venv/bin/activate ] && source .venv/bin/activate

# 3. Open the browser once the server answers, then hand this window to it.
( for _ in $(seq 1 40); do
    curl -s -o /dev/null "$URL/api/health" && { xdg-open "$URL" >/dev/null 2>&1; break; }
    sleep 0.3
  done ) &

echo "Argus web starting at $URL  —  close this window / Ctrl-C to stop it."
exec python3 web/server.py
