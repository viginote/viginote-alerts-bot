#!/bin/bash
# Only copy clients.json if /data/clients.json does NOT already exist
# This preserves clients added via the hub Client Manager across deploys
if [ ! -f /data/clients.json ]; then
  echo "No clients.json on disk — seeding from repo..."
  cp clients.json /data/clients.json
  echo "clients.json seeded OK"
else
  echo "clients.json already exists on disk — preserving existing clients"
fi

# Install any missing packages (safety net)
pip install aiohttp==3.9.5 --quiet --break-system-packages 2>/dev/null || true

# Start API server in background
uvicorn api:app --host 0.0.0.0 --port ${PORT:-8000} &
UVICORN_PID=$!

# Start bot in background — if it crashes, API stays up
python main.py &
BOT_PID=$!

echo "API PID: $UVICORN_PID | Bot PID: $BOT_PID"

# Keep script alive — exit only if uvicorn dies
wait $UVICORN_PID
