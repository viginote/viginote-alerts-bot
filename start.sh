#!/bin/bash
uvicorn api:app --host 0.0.0.0 --port ${PORT:-8000} &
python main.py
