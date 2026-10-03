@echo off
setlocal EnableExtensions

cd /d "%~dp0"

echo.
echo ReconVision Windows 10 / 11 auto-run
echo ====================================
echo.

where go >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Go was not found in PATH.
  echo Install Go 1.26 or newer, then run this file again.
  echo https://go.dev/dl/
  pause
  exit /b 1
)

where npm >nul 2>nul
if errorlevel 1 (
  echo [ERROR] npm was not found in PATH.
  echo Install Node.js 20 or newer, then run this file again.
  echo https://nodejs.org/
  pause
  exit /b 1
)

set "CHROME_PATH="
if exist "%ProgramFiles%\Google\Chrome\Application\chrome.exe" set "CHROME_PATH=%ProgramFiles%\Google\Chrome\Application\chrome.exe"
if not defined CHROME_PATH if exist "%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe" set "CHROME_PATH=%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"
if not defined CHROME_PATH if exist "%LocalAppData%\Google\Chrome\Application\chrome.exe" set "CHROME_PATH=%LocalAppData%\Google\Chrome\Application\chrome.exe"
if not defined CHROME_PATH if exist "%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe" set "CHROME_PATH=%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"
if not defined CHROME_PATH if exist "%ProgramFiles%\Microsoft\Edge\Application\msedge.exe" set "CHROME_PATH=%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"

if not defined CHROME_PATH (
  echo [WARN] Chrome or Edge was not found in the common Windows locations.
  echo The app can still start, but screenshots may fail until Chrome/Edge is installed.
) else (
  echo Browser engine: %CHROME_PATH%
)

if exist "%~dp0.env" (
  for /f "usebackq tokens=1,* delims==" %%A in ("%~dp0.env") do (
    if /i "%%A"=="URLSCAN_API_KEY" set "URLSCAN_API_KEY=%%B"
    if /i "%%A"=="OPENAI_API_KEY" set "OPENAI_API_KEY=%%B"
    if /i "%%A"=="OPENAI_MODEL" set "OPENAI_MODEL=%%B"
  )
)

if defined URLSCAN_API_KEY (
  echo URLScan pivot: key loaded from environment or .env
) else (
  echo URLScan pivot: set URLSCAN_API_KEY in .env to enable campaign pivots
)

if defined OPENAI_API_KEY (
  echo AI domain analysis: OpenAI key loaded from environment or .env
) else (
  echo AI domain analysis: optional OPENAI_API_KEY in .env enables selected-domain analysis
)

echo.
echo [1/4] Installing frontend dependencies...
cd /d "%~dp0frontend"
if exist package-lock.json (
  call npm ci
) else (
  call npm install
)
if errorlevel 1 (
  echo.
  echo [ERROR] Frontend dependency install failed.
  pause
  exit /b 1
)

echo.
echo [2/4] Building frontend...
call npm run build
if errorlevel 1 (
  echo.
  echo [ERROR] Frontend build failed.
  pause
  exit /b 1
)

echo.
echo [3/4] Preparing backend static files...
cd /d "%~dp0"
if exist "backend\static" rmdir /s /q "backend\static"
xcopy "frontend\dist" "backend\static\" /e /i /y >nul
if errorlevel 1 (
  echo.
  echo [ERROR] Failed to copy frontend build into backend\static.
  pause
  exit /b 1
)

echo.
echo [4/4] Starting ReconVision backend...
cd /d "%~dp0backend"
if not defined PORT set "PORT=8080"

echo Checking for old backend on port %PORT%...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='SilentlyContinue'; $port=[int]$env:PORT; $listeners=Get-NetTCPConnection -LocalPort $port -State Listen; foreach ($listener in $listeners) { $owner=$listener.OwningProcess; $proc=Get-Process -Id $owner; $cmd=(Get-CimInstance Win32_Process -Filter \"ProcessId=$owner\").CommandLine; if ($proc.ProcessName -match 'go|reconvision|main' -or $cmd -match 'reconvision|go run \.') { Write-Host ('Stopping old ReconVision backend PID ' + $owner); Stop-Process -Id $owner -Force } }" 2>nul
timeout /t 1 /nobreak >nul

for /f %%P in ('powershell -NoProfile -ExecutionPolicy Bypass -Command "$start=[int]$env:PORT; for ($p=$start; $p -le $start+30; $p++) { if (-not (Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue)) { Write-Host $p; exit 0 } }; Write-Host $start"') do set "PORT=%%P"

echo Backend port: %PORT%
start "ReconVision Backend" cmd /k "set PORT=%PORT%&& go run ."

echo.
echo Waiting for http://localhost:%PORT% ...
set "READY="
for /l %%i in (1,1,60) do (
  powershell -NoProfile -ExecutionPolicy Bypass -Command "try { $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 http://localhost:%PORT%/api/health; if ($r.StatusCode -ge 200 -and $r.StatusCode -lt 500) { exit 0 } } catch {}; exit 1" >nul 2>nul
  if not errorlevel 1 (
    set "READY=1"
    goto ready
  )
  timeout /t 2 /nobreak >nul
)

:ready
if not defined READY (
  echo.
  echo [WARN] Server did not become ready yet.
  echo Check the "ReconVision Backend" window for errors.
  pause
  exit /b 1
)

start "" "http://localhost:%PORT%"

echo.
echo ReconVision is running at http://localhost:%PORT%
echo Close the "ReconVision Backend" command window to stop it.
echo.
pause
