# Argus web stack — multi-stage.
#   Stage 1 (node): build the React frontend → web/frontend/dist
#   Stage 2 (python): copy the argus engine + server.py + built dist, run it.
#
# Build from the REPO ROOT (so the argus/ package is in context):
#   docker build -f web/Dockerfile -t argus-web .
#   docker run --rm -p 8787:8787 -e GITHUB_TOKEN=ghp_xxx argus-web
#   open http://127.0.0.1:8787
#
# Notes:
# - The engine is stdlib-only, so there is nothing to pip install for it.
# - git is installed so the github_org module (commit-history scan) works.
# - The `phone` module's optional phonenumbers dep is NOT installed (keeps the
#   image small); install it yourself if you need phone intel.

# ---- Stage 1: build frontend ----
FROM node:20-slim AS frontend
WORKDIR /build
COPY web/frontend/package.json web/frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/frontend/ ./
RUN npm run build        # emits /build/dist

# ---- Stage 2: runtime ----
FROM python:3.12-slim AS runtime
# git: required by the github_org module to clone + scan commit history
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
# the argus engine (stdlib-only) and the web server
COPY argus/ ./argus/
COPY web/server.py ./web/server.py
# the built frontend, served by server.py from web/frontend/dist
COPY --from=frontend /build/dist ./web/frontend/dist

ENV PYTHONUNBUFFERED=1
EXPOSE 8787

# Bind to 0.0.0.0 so the port is reachable from the host; the engine's
# active tiers still require operator authorization in the UI.
CMD ["python", "web/server.py", "--host", "0.0.0.0", "--port", "8787"]
