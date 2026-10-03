#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo
echo "ReconVision macOS auto-run"
echo "=========================="
echo

command -v go >/dev/null 2>&1 || {
  echo "[ERROR] Go was not found in PATH. Install with: brew install go"
  exit 1
}

command -v npm >/dev/null 2>&1 || {
  echo "[ERROR] npm was not found in PATH. Install with: brew install node"
  exit 1
}

CHROME_PATH="${CHROME_PATH:-}"
if [ -z "$CHROME_PATH" ] && [ -x "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" ]; then
  CHROME_PATH="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
fi
if [ -z "$CHROME_PATH" ] && [ -x "/Applications/Chromium.app/Contents/MacOS/Chromium" ]; then
  CHROME_PATH="/Applications/Chromium.app/Contents/MacOS/Chromium"
fi

if [ -z "$CHROME_PATH" ]; then
  echo "[WARN] Google Chrome/Chromium was not found in /Applications."
  echo "       The app can start, but screenshots may fail until Chrome is installed."
else
  export CHROME_PATH
  echo "Browser engine: $CHROME_PATH"
fi

if [ -f ".env" ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

if [ -n "${URLSCAN_API_KEY:-}" ]; then
  echo "URLScan pivot: key loaded from environment or .env"
else
  echo "URLScan pivot: set URLSCAN_API_KEY in .env to enable campaign pivots"
fi

if [ -n "${OPENAI_API_KEY:-}" ]; then
  echo "AI domain analysis: OpenAI key loaded from environment or .env"
else
  echo "AI domain analysis: optional OPENAI_API_KEY in .env enables selected-domain analysis"
fi

echo
echo "[1/4] Installing frontend dependencies..."
cd frontend
if [ -f package-lock.json ]; then
  npm ci
else
  npm install
fi

echo
echo "[2/4] Building frontend..."
npm run build

echo
echo "[3/4] Preparing backend static files..."
cd ..
rm -rf backend/static
mkdir -p backend/static
cp -R frontend/dist/. backend/static/

echo
echo "[4/4] Starting ReconVision backend..."
export PORT="${PORT:-8080}"

if command -v lsof >/dev/null 2>&1; then
  OLD_PIDS="$(lsof -ti tcp:"$PORT" || true)"
  if [ -n "$OLD_PIDS" ]; then
    echo "Stopping old backend on port $PORT..."
    kill $OLD_PIDS 2>/dev/null || true
    sleep 1
  fi
fi

cd backend
go run . &
BACKEND_PID=$!
cd ..

echo
echo "Waiting for http://localhost:$PORT ..."
for _ in $(seq 1 60); do
  if curl -fsS "http://localhost:$PORT/api/health" >/dev/null 2>&1; then
    open "http://localhost:$PORT"
    echo
    echo "ReconVision is running at http://localhost:$PORT"
    echo "Press Ctrl+C in this terminal to stop it."
    wait "$BACKEND_PID"
    exit 0
  fi
  sleep 2
done

echo "[ERROR] Server did not become ready. Stopping backend."
kill "$BACKEND_PID" 2>/dev/null || true
exit 1
