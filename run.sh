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

free_port_or_fail() {
  local port="$1"
  if command -v lsof >/dev/null 2>&1; then
    local pids
    pids="$(lsof -ti "tcp:${port}" 2>/dev/null || true)"
    if [[ -n "$pids" ]]; then
      echo "ERROR: Port ${port} is already in use (PIDs: ${pids}). Stop that process and re-run." >&2
      exit 1
    fi
  fi
}

echo "Starting full backend + full frontend..."

free_port_or_fail "$BACKEND_PORT"
free_port_or_fail "$FRONTEND_PORT"

# Backend
ensure_backend_venv
cd "$BACKEND_DIR"

# Load backend env if present
if [[ -f ".env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source ".env"
  set +a
fi

echo "Starting Backend (FastAPI) on http://localhost:${BACKEND_PORT} ..."
.venv/bin/python -m uvicorn app.main:app --host "$BACKEND_HOST" --port "$BACKEND_PORT" &
BACKEND_PID=$!

# Frontend
cd "$FRONTEND_DIR"

echo "Starting Frontend (static server) on http://localhost:${FRONTEND_PORT} ..."
python3 -m http.server "$FRONTEND_PORT" --bind "$FRONTEND_HOST" &
FRONTEND_PID=$!

echo "Servers are running:"
echo "- Backend:  http://localhost:${BACKEND_PORT}"
echo "- Frontend: http://localhost:${FRONTEND_PORT}"

wait "$BACKEND_PID" "$FRONTEND_PID"
