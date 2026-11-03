#!/usr/bin/env bash
# Local dev launcher. Builds the sandbox image (if Docker is present) and starts
# the app. Works without Docker too — demo:* jobs replay synthetic traces.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
  python3 -m venv .venv
  .venv/bin/pip install -q --upgrade pip
  .venv/bin/pip install -q -r requirements.txt
fi

if command -v docker >/dev/null 2>&1 && docker version >/dev/null 2>&1; then
  if [ -z "$(docker images -q dc-sandbox:latest)" ]; then
    echo "==> Building sandbox image (first run)…"
    docker build -t dc-sandbox:latest sandbox
  fi
else
  echo "!! Docker not available — live detonation disabled, demo:* jobs still work."
fi

[ -f .env ] && export $(grep -v '^#' .env | xargs) || true
echo "==> http://127.0.0.1:${DC_PORT:-8000}"
exec .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port "${DC_PORT:-8000}"
