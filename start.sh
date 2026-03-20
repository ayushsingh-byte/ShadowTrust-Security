#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$ROOT_DIR/backend"
FRONTEND_DIR="$ROOT_DIR/frontend"

BACKEND_HOST="${BACKEND_HOST:-0.0.0.0}"
BACKEND_PORT="${BACKEND_PORT:-8000}"
FRONTEND_HOST="${FRONTEND_HOST:-0.0.0.0}"
FRONTEND_PORT="${FRONTEND_PORT:-5500}"

cleanup() {
  echo "Stopping servers..."
  if [[ -n "${BACKEND_PID:-}" ]] && kill -0 "$BACKEND_PID" 2>/dev/null; then
    kill "$BACKEND_PID" 2>/dev/null || true
  fi
  if [[ -n "${FRONTEND_PID:-}" ]] && kill -0 "$FRONTEND_PID" 2>/dev/null; then
    kill "$FRONTEND_PID" 2>/dev/null || true
  fi
  if [[ -n "${MOBSF_PID:-}" ]] && kill -0 "$MOBSF_PID" 2>/dev/null; then
    kill "$MOBSF_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

ensure_backend_venv() {
  cd "$BACKEND_DIR"

  if [[ ! -x ".venv/bin/python" ]]; then
    echo "Creating backend venv..."

    if command -v python3.11 >/dev/null 2>&1; then
      python3.11 -m venv .venv
    elif [[ -x "/opt/homebrew/bin/python3.11" ]]; then
      /opt/homebrew/bin/python3.11 -m venv .venv
    else
      echo "ERROR: Python 3.11 not found. Install it (recommended) or create backend/.venv manually." >&2
      exit 1
    fi
  fi

  echo "Installing backend dependencies..."
  .venv/bin/python -m pip install -r requirements.txt >/dev/null
}

kill_port_if_in_use() {
  local port="$1"
  if command -v lsof >/dev/null 2>&1; then
    local pids
    pids="$(lsof -ti "tcp:${port}" 2>/dev/null || true)"
    if [[ -n "$pids" ]]; then
      echo "Port ${port} is already in use (PIDs: ${pids}). Killing them..."
      echo "$pids" | xargs kill -9 2>/dev/null || true
      sleep 1
    fi
  fi
}

MOBSF_PORT="${MOBSF_PORT:-5055}"

echo "Starting full backend + full frontend + MobSF service..."

kill_port_if_in_use "$BACKEND_PORT"
kill_port_if_in_use "$FRONTEND_PORT"
kill_port_if_in_use "$MOBSF_PORT"

# Backend
ensure_backend_venv
cd "$BACKEND_DIR"

# Load backend env if present
if [[ -f ".env" ]]; then
  set -a
  source ".env"
  set +a
fi

echo "Starting Backend (FastAPI) on http://localhost:${BACKEND_PORT} ..."
.venv/bin/python -m uvicorn app.main:app --host "$BACKEND_HOST" --port "$BACKEND_PORT" &
BACKEND_PID=$!

# MobSF Flask service
echo "Starting MobSF service on http://localhost:${MOBSF_PORT} ..."
.venv/bin/pip install flask flask-cors -q 2>/dev/null || true
.venv/bin/python -c "
from mobsf_service.app import app
from mobsf_service.config import SERVICE_HOST, SERVICE_PORT
app.run(host=SERVICE_HOST, port=SERVICE_PORT)
" &
MOBSF_PID=$!

# Frontend
cd "$FRONTEND_DIR"

echo "Starting Frontend (static server) on http://localhost:${FRONTEND_PORT} ..."
python3 -m http.server "$FRONTEND_PORT" --bind "$FRONTEND_HOST" &
FRONTEND_PID=$!

echo ""
echo "All services running:"
echo "  Backend:  http://localhost:${BACKEND_PORT}"
echo "  MobSF:    http://localhost:${MOBSF_PORT}"
echo "  Frontend: http://localhost:${FRONTEND_PORT}"
echo ""

wait "$BACKEND_PID" "$MOBSF_PID" "$FRONTEND_PID"
