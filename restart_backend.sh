#!/bin/bash
echo "Killing existing uvicorn processes..."
pkill -f "uvicorn main:app"
sleep 2

echo "Starting Backend (FastAPI) on http://localhost:8000 ..."
cd ./backend
source .venv/bin/activate
nohup uvicorn app.main:app --reload --host 0.0.0.0 --port 8000 &
echo "Backend restarted!"
