@echo off
REM Argus (Windows) — pulls latest code, launches the web API, opens the UI.
REM Double-click in Explorer. Close this window to stop Argus.
cd /d "%~dp0"

set "URL=http://127.0.0.1:8787"

REM 1. Fetch the latest code (fast-forward only — never clobbers local work).
if exist ".git" (
  echo Updating to latest code...
  git pull --ff-only || echo git pull skipped - running current code.
)

REM 2. Stop any server already holding the port, so we run the code we just pulled.
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :8787 ^| findstr LISTENING') do taskkill /F /PID %%a >nul 2>&1

if exist ".venv\Scripts\activate.bat" call ".venv\Scripts\activate.bat"

REM 3. Open the browser after a short delay, then hand this window to the server.
start "Argus browser" /min cmd /c "ping -n 3 127.0.0.1 >nul & start %URL%"

echo Argus web starting at %URL%  -  close this window to stop it.
python web\server.py
