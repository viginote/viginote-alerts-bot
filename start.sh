#!/bin/bash
# Always sync clients.json to /data on deploy
echo "Syncing clients.json to /data..."
cp clients.json /data/clients.json
echo "clients.json synced OK"

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
