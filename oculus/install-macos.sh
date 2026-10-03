#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo
echo "ReconVision macOS installer"
echo "==========================="
echo

if ! command -v brew >/dev/null 2>&1; then
  echo "[ERROR] Homebrew is required for automatic install."
  echo "Install it from https://brew.sh, then run:"
  echo "  bash install-macos.sh"
  exit 1
fi

if ! command -v go >/dev/null 2>&1; then
  echo "Installing Go..."
  brew install go
else
  echo "Go is already installed."
fi

if ! command -v npm >/dev/null 2>&1; then
  echo "Installing Node.js..."
  brew install node
else
  echo "Node.js/npm is already installed."
fi

if [ ! -x "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" ] && [ ! -x "/Applications/Chromium.app/Contents/MacOS/Chromium" ]; then
  echo "Installing Google Chrome..."
  brew install --cask google-chrome
else
  echo "Chrome or Chromium is already installed."
fi

if [ ! -f ".env" ]; then
  cp ".env.example" ".env"
  echo "Created .env from .env.example. Add URLSCAN_API_KEY and OPENAI_API_KEY if needed."
fi

echo
echo "Installing frontend dependencies..."
cd frontend
if [ -f package-lock.json ]; then
  npm ci
else
  npm install
fi

echo
echo "Downloading backend dependencies..."
cd ../backend
go mod download

cd ..
chmod +x run-macos.sh install-macos.sh

echo
echo "Installer finished. Start ReconVision with:"
echo "  ./run-macos.sh"
