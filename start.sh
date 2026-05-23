#!/bin/bash
# Bootstrap clients.json to /data if not already there
if [ ! -f /data/clients.json ]; then
  echo "Bootstrapping clients.json to /data..."
  cp clients.json /data/clients.json
fi
# Start both services
uvicorn api:app --host 0.0.0.0 --port ${PORT:-8000} &
python main.py
