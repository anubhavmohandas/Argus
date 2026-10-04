#!/bin/bash
# Argus — double-click to launch the web API and open the UI in your browser.
# macOS runs this in Terminal on double-click. Close the window to stop Argus.
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

# Open the browser as soon as the server answers, then hand this window to it.
( for _ in $(seq 1 40); do
    curl -s -o /dev/null "$URL/api/health" && { open "$URL"; break; }
    sleep 0.3
  done ) &

echo "Argus web starting at $URL  —  close this window to stop it."
exec python3 web/server.py
