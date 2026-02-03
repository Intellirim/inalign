#!/bin/bash
set -e

echo "=== AgentShield Backend Entrypoint ==="

# Step 1: Initialize database (create tables + seed admin user)
echo "[1/2] Initializing database..."
python -m scripts.init_db

# Step 2: Start the API server
echo "[2/2] Starting uvicorn..."
exec uvicorn app.main:app --host "${API_HOST:-0.0.0.0}" --port "${API_PORT:-8000}" --workers 4
