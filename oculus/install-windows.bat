@echo off
setlocal EnableExtensions

cd /d "%~dp0"

echo.
echo ReconVision Windows 10 / 11 installer
echo =====================================
echo.

where winget >nul 2>nul
if errorlevel 1 (
  echo [WARN] winget was not found.
  echo Install these manually, then run run.bat:
  echo   - Go 1.26 or newer: https://go.dev/dl/
  echo   - Node.js 20 or newer: https://nodejs.org/
  echo   - Google Chrome or Microsoft Edge
  pause
  exit /b 1
)

where go >nul 2>nul
if errorlevel 1 (
  echo Installing Go...
  winget install --id GoLang.Go --source winget --accept-package-agreements --accept-source-agreements
) else (
  echo Go is already installed.
)

where npm >nul 2>nul
if errorlevel 1 (
  echo Installing Node.js LTS...
  winget install --id OpenJS.NodeJS.LTS --source winget --accept-package-agreements --accept-source-agreements
) else (
  echo Node.js/npm is already installed.
)

set "HAS_BROWSER="
if exist "%ProgramFiles%\Google\Chrome\Application\chrome.exe" set "HAS_BROWSER=1"
if exist "%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe" set "HAS_BROWSER=1"
if exist "%LocalAppData%\Google\Chrome\Application\chrome.exe" set "HAS_BROWSER=1"
if exist "%ProgramFiles%\Microsoft\Edge\Application\msedge.exe" set "HAS_BROWSER=1"
if exist "%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe" set "HAS_BROWSER=1"

if not defined HAS_BROWSER (
  echo Installing Google Chrome...
  winget install --id Google.Chrome --source winget --accept-package-agreements --accept-source-agreements
) else (
  echo Chrome or Edge is already installed.
)

if not exist ".env" (
  copy ".env.example" ".env" >nul
  echo Created .env from .env.example. Add URLSCAN_API_KEY and OPENAI_API_KEY if needed.
)

echo.
echo Installing frontend dependencies...
cd /d "%~dp0frontend"
if exist package-lock.json (
  call npm ci
) else (
  call npm install
)
if errorlevel 1 (
  echo [ERROR] npm dependency install failed.
  pause
  exit /b 1
)

echo.
echo Downloading backend dependencies...
cd /d "%~dp0backend"
go mod download
if errorlevel 1 (
  echo [ERROR] Go dependency download failed.
  pause
  exit /b 1
)

echo.
echo Installer finished. Run run.bat to start ReconVision.
pause
