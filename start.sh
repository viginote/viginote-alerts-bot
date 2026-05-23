#!/bin/bash
# Always sync clients.json to /data on deploy
echo "Syncing clients.json to /data..."
cp clients.json /data/clients.json
echo "clients.json synced OK"

# Start both services
uvicorn api:app --host 0.0.0.0 --port ${PORT:-8000} &
python main.py
