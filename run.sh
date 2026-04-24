#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi

source .venv/bin/activate
pip install -r requirements.txt

if command -v npm >/dev/null 2>&1; then
  (cd xpulse/frontend && npm install && npm run build)
fi

uvicorn api.server:app --host 0.0.0.0 --port "${BACKEND_PORT:-8000}" --reload

