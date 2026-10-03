# ReconVision

> High-performance screenshot reconnaissance platform for bug bounty hunters.
> Inspired by EyeWitness — rebuilt for 16,000+ host datasets.

```
╔══════════════════════════════════════════════════════╗
║  ReconVision — Subdomain Screenshot Recon Platform  ║
║  Stack: Go backend · React/TS frontend · Chromium   ║
╚══════════════════════════════════════════════════════╝
```

**⚠️ For authorized security testing and bug bounty reconnaissance only.**

---

## Features

| Feature | Details |
|---------|---------|
| **Parallel Probing** | 150+ concurrent HTTP workers (httpx-style) |
| **Screenshot Engine** | Headless Chromium via chromedp, pooled workers |
| **Smart Pipeline** | Probe → filter dead hosts → screenshot live only |
| **Real-time UI** | SSE streaming — results appear as they're found |
| **Keyword Detection** | Auto-flags admin, login, dashboard, grafana, etc. |
| **Instant Filtering** | Status code, title, keyword, size, interesting flag |
| **Export** | CSV, JSON, Markdown, TXT |
| **Scale** | Tested to 20,000+ domains |

---

## Project Structure

```
reconvision/
├── backend/
│   ├── main.go                  # Entry point
│   ├── go.mod
│   ├── models/models.go         # Data structures
│   ├── store/store.go           # Thread-safe in-memory store
│   ├── scanner/
│   │   ├── prober.go            # HTTP probing engine (httpx-like)
│   │   ├── screenshotter.go     # chromedp screenshot capture
│   │   └── worker.go            # Worker pool orchestrator
│   └── api/
│       ├── handlers.go          # REST + SSE handlers
│       └── router.go            # chi router with CORS
├── frontend/
│   ├── src/
│   │   ├── App.tsx
│   │   ├── components/
│   │   │   ├── TopBar.tsx       # Upload, scan controls, export
│   │   │   ├── FilterPanel.tsx  # Left sidebar filters
│   │   │   ├── ResultGrid.tsx   # Screenshot grid
│   │   │   ├── ResultCard.tsx   # Individual result card
│   │   │   ├── ScanProgress.tsx # Progress bar + stats
│   │   │   └── MetadataPanel.tsx# Right panel detail view
│   │   ├── hooks/
│   │   │   ├── useScan.ts       # SSE scan management
│   │   │   └── useFilters.ts    # Client-side filtering
│   │   └── types/index.ts
│   ├── package.json
│   └── vite.config.ts
├── Dockerfile
├── docker-compose.yml
└── README.md
```

---

## Compatibility

ReconVision is compatible with:

| OS | Status | Launcher | Installer |
|----|--------|----------|-----------|
| Windows 10 | Supported | `run.bat` | `install-windows.bat` |
| Windows 11 | Supported | `run.bat` | `install-windows.bat` |
| macOS Intel / Apple Silicon | Supported | `./run-macos.sh` | `./install-macos.sh` |

No Docker is required for Windows or macOS. The local launchers build the frontend, copy it into the Go backend, load `.env`, start port `8080`, and open the browser.

---

## Installation

### Prerequisites

- **Go 1.26+**
- **Node.js 20+**
- **Chrome, Edge, or Chromium** (for screenshots)

### Windows 10 / Windows 11

```bat
install-windows.bat
run.bat
```

The installer uses `winget` to install Go, Node.js LTS, and Google Chrome if they are missing.

### macOS

```bash
chmod +x install-macos.sh run-macos.sh
./install-macos.sh
./run-macos.sh
```

The installer uses Homebrew to install Go, Node.js, and Google Chrome if they are missing.

### Optional API Keys

Create `.env` in the project root:

```env
URLSCAN_API_KEY=your_urlscan_key_here
OPENAI_API_KEY=your_openai_key_here
OPENAI_MODEL=gpt-5.6-sol
```

---

## Running Locally

### Windows 10 / Windows 11 Auto Run

```bat
run.bat
```

The launcher builds the React frontend, copies it into `backend/static`, starts the Go backend on port `8080`, and opens `http://localhost:8080`.

Optional URLScan campaign pivot:

```env
URLSCAN_API_KEY=your_key_here
```

Put that line in a local `.env` file at the project root. The key is loaded by `run.bat` and is ignored by Git.

### macOS Auto Run

```bash
./run-macos.sh
```

The launcher builds the React frontend, copies it into `backend/static`, starts the Go backend on port `8080`, and opens `http://localhost:8080`.

### 1. Backend

```bash
cd backend

# Download Go dependencies
go mod tidy

# Run the server (default port 8080)
go run main.go

# Custom port
go run main.go -port 9090
```

### 2. Frontend

```bash
cd frontend

# Install dependencies
npm install

# Start dev server (proxies /api to :8080)
npm run dev
```

Open **http://localhost:3000** in your browser.

---

## Running with Docker

### Production (single container, full stack)

```bash
# Build image
docker build -t reconvision .

# Run
docker run -d \
  --name reconvision \
  -p 8080:8080 \
  --shm-size=2g \
  reconvision
```

Open **http://localhost:8080** — frontend is served from the Go binary's static directory.

### Development (with HMR)

```bash
# Start backend + frontend dev server
docker compose --profile dev up

# Backend only (if running frontend locally)
docker compose up backend
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scan` | Start scan (async, returns jobId) |
| `POST` | `/api/scan/stream` | Start scan with SSE streaming |
| `GET`  | `/api/scan/:jobId` | Get full job results |
| `GET`  | `/api/scan/:jobId/progress` | Lightweight progress poll |
| `GET`  | `/api/scan/:jobId/export?format=csv` | Export results |
| `GET`  | `/api/urlscan/status` | Check whether URLScan pivot is configured |
| `POST` | `/api/urlscan/search` | Run a defensive URLScan search query |
| `POST` | `/api/urlscan/pivot` | Pivot a phishing campaign by domain, IP, ASN, brand, or hash |
| `GET`  | `/api/jobs` | List all jobs |
| `GET`  | `/api/health` | Health check |

### POST /api/scan/stream — Request Body

```json
{
  "domains": ["admin.example.com", "test.target.com"],
  "config": {
    "concurrency": 150,
    "screenWorkers": 6,
    "timeoutSeconds": 10,
    "screenshotMode": "viewport",
    "maxRetries": 1,
    "skipScreenshots": false,
    "onlyLive": false,
    "followRedirects": true
  }
}
```

### SSE Event Types

```
event: start     → { jobId: "job_abc123" }
event: result    → ScanResult object
event: progress  → { total, processed, live, errors }
event: done      → final stats
```

---

## Example Scan Workflow

### CLI — curl

```bash
# Start a scan with SSE and watch live results
curl -N -X POST http://localhost:8080/api/scan/stream \
  -H 'Content-Type: application/json' \
  -d '{
    "domains": ["admin.target.com","test.target.com","dev.target.com"],
    "config": {"concurrency": 100, "timeoutSeconds": 8, "skipScreenshots": false}
  }'
```

### Import from subfinder output

```bash
# Pipe subfinder → reconvision
subfinder -d target.com -silent > targets.txt

# POST via curl
curl -X POST http://localhost:8080/api/scan \
  -H 'Content-Type: application/json' \
  -d "{\"domains\": $(jq -Rs '[splits("\n")]|map(select(. != ""))' targets.txt), \"config\": {}}"
```

### UI Workflow

1. Click **TARGETS** → paste or import subdomains
2. (Optional) Click **CONFIG** → tune concurrency, timeout, screenshot mode
3. Click **▶ RUN SCAN**
4. Results stream in real-time as cards in the grid
5. Use the left panel to filter by status, keywords, size
6. Click a card to see full metadata in the right panel
7. Export as CSV/JSON/TXT/Markdown when done

---

## Performance Tuning Guide

### For 1k–5k domains

```json
{
  "concurrency": 100,
  "screenWorkers": 4,
  "timeoutSeconds": 10
}
```

### For 5k–16k domains

```json
{
  "concurrency": 200,
  "screenWorkers": 6,
  "timeoutSeconds": 8
}
```

### For 16k–50k domains

```json
{
  "concurrency": 300,
  "screenWorkers": 8,
  "timeoutSeconds": 6,
  "skipScreenshots": false
}
```

> **Probe-only mode** (`skipScreenshots: true`): Can hit 50k domains in under 3 minutes with concurrency 300.
>
> **Screenshot mode**: Each Chromium worker uses ~200MB RAM. 8 workers = ~1.6GB. Set `--shm-size=2g` in Docker.

### System Tuning (Linux)

```bash
# Increase open file descriptors
ulimit -n 65536

# Increase ephemeral port range
echo "1024 65535" > /proc/sys/net/ipv4/ip_local_port_range

# Reduce TIME_WAIT
echo "1" > /proc/sys/net/ipv4/tcp_tw_reuse
```

### Docker Resource Limits

```bash
docker run -d \
  --name reconvision \
  -p 8080:8080 \
  --shm-size=2g \
  --memory=8g \
  --cpus=4 \
  reconvision
```

---

## Filtering Cheatsheet

| Goal | Filter |
|------|--------|
| Admin panels | Keyword: `admin` + `panel` |
| Login pages | Keyword: `login` |
| Dev/staging | Keyword: `staging`, `dev` |
| Interesting status | Status: 401, 403 |
| Large responses | Size > 100000 |
| Redirects | Status: 301, 302 |
| Internal tools | Keywords: `grafana`, `jenkins`, `kibana` |

---

## Architecture Diagram

```
Input Domains (16k+)
        │
        ▼
  Deduplication
        │
        ▼
 ┌─────────────────┐
 │  Probe Workers  │  ← 150-300 goroutines
 │  (net/http)     │    HTTPS-first, HTTP fallback
 └────────┬────────┘    TLS skip, follow redirects
          │
    ┌─────┴──────┐
    │            │
  LIVE          DEAD
    │            │
    ▼            ▼
┌──────────┐  Store error
│Screenshot│  result
│ Workers  │  ← 4-8 chromedp instances
└────┬─────┘
     │
     ▼
Result Store → SSE → Frontend
```

---

## Known Limitations

- Screenshots require Chromium installed (handled by Dockerfile)
- Results stored in-memory — lost on restart (add SQLite persistence for production)
- No authentication — run behind a VPN/firewall in production
- Rate limiting is per-scan, not global (don't run multiple 50k scans simultaneously)

---

## Legal Notice

This tool is for **authorized security testing only**. Only scan targets you have explicit permission to test. Unauthorized scanning may violate the Computer Fraud and Abuse Act (CFAA) and equivalent laws in your jurisdiction.
