# ─────────────────────────────────────────────────────────
# Stage 1: Build frontend
# ─────────────────────────────────────────────────────────
FROM node:20-alpine AS frontend-builder

WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi

COPY frontend/ ./
RUN npm run build

# ─────────────────────────────────────────────────────────
# Stage 2: Build Go backend
# ─────────────────────────────────────────────────────────
FROM golang:1.21-bookworm AS backend-builder

WORKDIR /app/backend
COPY backend/go.mod backend/go.sum* ./
RUN go mod download

COPY backend/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /reconvision-server .

# ─────────────────────────────────────────────────────────
# Stage 3: Runtime — Debian + Chrome
# ─────────────────────────────────────────────────────────
FROM debian:bookworm-slim

# Install Chromium and dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium \
    ca-certificates \
    fonts-liberation \
    fonts-noto-color-emoji \
    libnss3 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libgbm1 \
    libgtk-3-0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxkbcommon0 \
    libxrandr2 \
    xdg-utils \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -r reconvision && useradd -r -g reconvision -d /app reconvision
WORKDIR /app

# Copy binary
COPY --from=backend-builder /reconvision-server ./reconvision-server

# Copy built frontend into static/ for serving
COPY --from=frontend-builder /app/frontend/dist ./static/

# Set Chrome path for chromedp
ENV CHROME_PATH=/usr/bin/chromium

# Screenshots output dir
RUN mkdir -p /app/screenshots && chown -R reconvision:reconvision /app

USER reconvision

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD wget -qO- http://localhost:8080/api/health || exit 1

ENTRYPOINT ["/app/reconvision-server"]
